package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/authsession"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"go.uber.org/zap"
)

// Engine orchestrates AI agent runs: context gathering, prompt rendering,
// agent execution, output parsing, and result ingestion. Dispatch happens
// through the in-process olium engine; no subprocess pools are involved.
type Engine struct {
	settings *config.Settings
	repo     *database.Repository

	// Caches for context gathering (populated lazily, thread-safe)
	dirTreeCacheMu   sync.RWMutex
	dirTreeCache     map[string]string // sourcePath → tree listing
	skipGuidanceOnce sync.Once
	skipGuidanceText string

	// contextCache caches DB enrichment results within a swarm run.
	// Set via SetContextCache before swarm execution; nil for non-swarm modes.
	contextCache *agentprompt.ContextCache

	// tokenUsage accumulates per-call token usage across every Run / sub-run
	// invocation on this Engine. SwarmRunner reads it at finalize time to
	// populate SwarmResult.TokenUsage for cost / telemetry.
	tokenUsageMu sync.Mutex
	tokenUsage   agenttypes.TokenUsage

	// budget is the run-wide cap installed by SetRunBudget (swarm's
	// --max-commands / --token-budget / --max-cost-usd); see budget.go.
	budget budgetState

	// runtime is the AI-dispatch seam. It defaults to the olium-backed runtime;
	// tests may inject a fake. All AI calls go through it so the engine depends
	// on the AgentRuntime interface, not the concrete olium engine.
	runtime AgentRuntime
}

// NewEngine creates a new agent engine backed by the in-process olium runtime.
func NewEngine(settings *config.Settings, repo *database.Repository) *Engine {
	return &Engine{
		settings: settings,
		repo:     repo,
		runtime:  oliumRuntime{},
	}
}

// rt returns the configured runtime, defaulting to the olium-backed runtime so
// an Engine built directly as &Engine{} (e.g. in tests) still dispatches.
func (e *Engine) rt() AgentRuntime {
	if e.runtime == nil {
		return oliumRuntime{}
	}
	return e.runtime
}

// Run executes a full agent pipeline: resolve prompt → render → execute → parse → ingest.
// Each call constructs a fresh in-process olium engine.
func (e *Engine) Run(ctx context.Context, opts Options) (*Result, error) {
	return e.runOnSession(ctx, opts, nil, nil)
}

// RunWithSkills is Run with a skill registry surfaced to the agent: the
// fresh-per-call engine gets an <available_skills> block and the load_skill
// tool for exactly the skills in reg. A nil/empty reg behaves like Run.
func (e *Engine) RunWithSkills(ctx context.Context, opts Options, reg *skill.Registry) (*Result, error) {
	return e.runOnSession(ctx, opts, nil, reg)
}

// RunWithExtraSkills merges extra template data (like RunWithExtra) and also
// surfaces the given skill registry to the agent. Used by the swarm plan phase
// to give the planner the full skill menu.
func (e *Engine) RunWithExtraSkills(ctx context.Context, opts Options, extra map[string]string, reg *skill.Registry) (*Result, error) {
	if extra != nil {
		if opts.Extra == nil {
			opts.Extra = make(map[string]string)
		}
		for k, v := range extra {
			opts.Extra[k] = v
		}
	}
	return e.runOnSession(ctx, opts, nil, reg)
}

// RunOnOliumEngine is like Run but reuses an existing AgentSession so the
// caller's prior conversation history (system prompt, tool defs, earlier
// turns) remains in the provider request and can hit prompt caches. Use
// with AgentSession.Fork() for parallel sub-runs that share a prefix —
// e.g., the source-analysis explore phase forks to 3 format/extension
// goroutines that don't need to re-append the explore notes.
func (e *Engine) RunOnOliumEngine(ctx context.Context, opts Options, sess AgentSession) (*Result, error) {
	return e.runOnSession(ctx, opts, sess, nil)
}

// runOnSession is the unified Run implementation. sess=nil → fresh session
// per call (default); sess != nil → reuse the supplied session. skills, when
// non-nil and non-empty, is surfaced via a per-call session carrying the
// <available_skills> block + load_skill tool (only on the fresh path; the
// session-reuse path already baked in whatever skills its session was built
// with).
func (e *Engine) runOnSession(ctx context.Context, opts Options, sess AgentSession, skills *skill.Registry) (*Result, error) {
	// AgentName is informational now — all dispatch goes through olium. Retain
	// the field so log lines and Result.AgentName keep their old semantics.
	if opts.AgentName == "" {
		opts.AgentName = "olium"
	}

	// Build the prompt
	prompt, outputSchema, templateID, err := e.buildPrompt(ctx, opts)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("prompt built",
		zap.String("templateID", templateID),
		zap.String("outputSchema", outputSchema),
		zap.Int("promptLength", len(prompt)))

	// Dry run: just return the rendered prompt
	if opts.DryRun {
		return &Result{
			AgentName:    opts.AgentName,
			TemplateID:   templateID,
			RawOutput:    prompt,
			OutputSchema: outputSchema,
			DryRun:       true,
		}, nil
	}

	// Show rendered prompt on stderr when --show-prompt is active
	if opts.ShowPrompt {
		fmt.Fprintf(os.Stderr, "\n── rendered prompt (%s) ──\n\n%s\n\n── end prompt ──\n\n", templateID, prompt)
	}

	if zap.L().Core().Enabled(zap.DebugLevel) {
		fmt.Fprintf(os.Stderr, "\n── prompt sent to agent (%s) ──\n\n%s\n\n── end prompt ──\n\n", templateID, prompt)
	}

	// Execute the agent via olium with optional retry on transient failures.
	retryCfg := agenttypes.DefaultRetryConfig()
	if opts.Retry != nil {
		retryCfg = *opts.Retry
	}

	var oliumCfg *config.OliumConfig
	if e.settings != nil {
		oc := e.settings.Agent.Olium
		oliumCfg = &oc
	}

	// Open a thinking sink in the session dir when one is set so reasoning
	// content from o1 / Claude thinking / Codex high-effort runs survives
	// past the live stream. Append mode so retries / multi-call SA waves
	// share one file per template per run.
	thinkingSink := openThinkingSink(opts)
	defer thinkingSink.close()

	var callUsage agenttypes.TokenUsage
	var callTools int
	var recordingError string
	var lastAttemptOut oliumRunOutput
	runOut, err := retryAgentCall(ctx, retryCfg, func(ctx context.Context, attempt int) (oliumRunOutput, error) {
		if exhausted := e.BudgetExhausted(); exhausted != nil {
			return lastAttemptOut, exhausted
		}
		runPrompt := prompt
		if attempt > 0 {
			runPrompt = "Please provide your full response.\n\n" + prompt
		}

		var out oliumRunOutput
		var runErr error
		defer func() {
			// Failed attempts still consumed provider tokens and tool work.
			// Charge each attempt once, before any retry can refill the runway.
			lastAttemptOut = out
			callUsage.InputTokens += out.Usage.InputTokens
			callUsage.OutputTokens += out.Usage.OutputTokens
			callTools += out.ToolCalls
			if out.RecordingError != "" {
				recordingError = out.RecordingError
			}
			e.addTokenUsage(out.Usage)
			e.chargeRunBudget(out.Usage, out.ToolCalls)
		}()
		switch {
		case sess != nil && !opts.PlanningOnly && !opts.OfflineTools:
			// Session-reuse path: the recorder (if any) is attached to the
			// session's engine and flushed by the caller's sess.Close().
			out, runErr = e.rt().RunOnSession(ctx, oliumCfg, sess, runPrompt, opts.StreamWriter, thinkingSink.writer(), opts.Verbose)
		case opts.PlanningOnly:
			// Selecting skills is not permission to execute them. Planning uses
			// only its supplied snapshot, even with source/bridge/tool flags.
			planSess, sErr := e.rt().NewSessionWithSpec(oliumCfg, SessionSpec{
				PlanningOnly: true,
				Skills:       skills,
				Record:       RecordSpec{SessionDir: opts.SessionDir, Template: opts.PromptTemplate},
			})
			if sErr != nil {
				return oliumRunOutput{}, sErr
			}
			out, runErr = e.rt().RunOnSession(ctx, oliumCfg, planSess, runPrompt, opts.StreamWriter, thinkingSink.writer(), opts.Verbose)
			closeAgentSessionWithWarning(planSess, opts.StreamWriter)
		case !opts.OfflineTools && ((skills != nil && skills.Len() > 0) || opts.EnableBurpBridgeTools):
			// Fresh-per-call path with skills and/or the live Burp bridge: build a
			// per-call session carrying the requested tools, run on it, then
			// flush its transcript via Close (the recorder buffers the final
			// turn until close). A build failure surfaces as a retryable error.
			rec := RecordSpec{SessionDir: opts.SessionDir, Template: opts.PromptTemplate}
			// When a repo is wired, also give the skill-driven agent the
			// read+replay tool subset so its skills can actually confirm against
			// scan records (not just reason over prompt context).
			var vigTools *VigToolSpec
			if e.repo != nil && skills != nil && skills.Len() > 0 {
				vigTools = &VigToolSpec{Repo: e.repo, ProjectUUID: opts.ProjectUUID}
			}
			var burpBridgeTools *BurpBridgeToolSpec
			if opts.EnableBurpBridgeTools || (skills != nil && skills.Len() > 0) {
				burpBridgeTools = &BurpBridgeToolSpec{ProjectUUID: opts.ProjectUUID}
			}
			skillSess, sErr := e.rt().NewSessionWithSpec(oliumCfg, SessionSpec{
				SourcePath:      opts.SourcePath,
				IncludeTools:    true,
				Skills:          skills,
				VigTools:        vigTools,
				BurpBridgeTools: burpBridgeTools,
				Record:          rec,
			})
			if sErr != nil {
				return oliumRunOutput{}, sErr
			}
			out, runErr = e.rt().RunOnSession(ctx, oliumCfg, skillSess, runPrompt, opts.StreamWriter, thinkingSink.writer(), opts.Verbose)
			closeAgentSessionWithWarning(skillSess, opts.StreamWriter)
		case opts.OfflineTools:
			// Offline path: a per-call session whose only tools read local
			// files, so the agent cannot reach the target (no bash, no
			// web_fetch, no browser).
			rec := RecordSpec{SessionDir: opts.SessionDir, Template: opts.PromptTemplate}
			offSess, sErr := e.rt().NewSessionWithSpec(oliumCfg, SessionSpec{
				SourcePath:   opts.SourcePath,
				IncludeTools: true,
				OfflineTools: true,
				Record:       rec,
			})
			if sErr != nil {
				return oliumRunOutput{}, sErr
			}
			out, runErr = e.rt().RunOnSession(ctx, oliumCfg, offSess, runPrompt, opts.StreamWriter, thinkingSink.writer(), opts.Verbose)
			closeAgentSessionWithWarning(offSess, opts.StreamWriter)
		case opts.MaxTurns > 0:
			// Fresh-per-call path with an explicit turn budget. RunPrompt builds
			// its session with the config's default cap (agent.max_turns, 32) and
			// never saw Options.MaxTurns, so a caller that documented-overrides it
			// — e.g. the browser auth phase, which must navigate and try several
			// login surfaces before it can capture a session — was silently
			// capped at 32 and failed with "exceeded max turns". Build the session
			// explicitly so the requested cap applies, mirroring the offline path.
			rec := RecordSpec{SessionDir: opts.SessionDir, Template: opts.PromptTemplate}
			turnSess, sErr := e.rt().NewSessionWithSpec(oliumCfg, SessionSpec{
				SourcePath:   opts.SourcePath,
				IncludeTools: true,
				MaxTurns:     opts.MaxTurns,
				Record:       rec,
			})
			if sErr != nil {
				return oliumRunOutput{}, sErr
			}
			out, runErr = e.rt().RunOnSession(ctx, oliumCfg, turnSess, runPrompt, opts.StreamWriter, thinkingSink.writer(), opts.Verbose)
			closeAgentSessionWithWarning(turnSess, opts.StreamWriter)
		default:
			// Fresh-per-call path: record a per-phase transcript when a session
			// dir is wired, named by template so concurrent phases don't clash.
			rec := RecordSpec{SessionDir: opts.SessionDir, Template: opts.PromptTemplate}
			out, runErr = e.rt().RunPrompt(ctx, oliumCfg, runPrompt, opts.StreamWriter, thinkingSink.writer(), opts.SourcePath, opts.Verbose, rec)
		}
		if runErr != nil {
			return out, runErr
		}
		if strings.TrimSpace(out.Text) == "" {
			zap.L().Warn("agent returned empty output, treating as retryable",
				zap.String("agent", opts.AgentName))
			return out, errEmptyAgentOutput
		}
		return out, nil
	})

	stdout := runOut.Text
	// Keep the final deliverable/partial text separate from cumulative spend.
	runOut.Usage = callUsage
	runOut.ToolCalls = callTools

	// Ensure streamed output ends with a newline so subsequent console lines
	// (e.g. session dir, phase banners) don't start on the same line.
	if opts.StreamWriter != nil && stdout != "" && !strings.HasSuffix(stdout, "\n") {
		_, _ = io.WriteString(opts.StreamWriter, "\n")
	}

	if err != nil {
		return &Result{
			AgentName:      opts.AgentName,
			TemplateID:     templateID,
			RawOutput:      stdout,
			RenderedPrompt: prompt,
			TokenUsage:     runOut.Usage,
			RecordingError: recordingError,
		}, fmt.Errorf("agent execution failed: %w", err)
	}

	// Write output to file if requested
	if opts.OutputPath != "" {
		if writeErr := os.WriteFile(opts.OutputPath, []byte(stdout), 0644); writeErr != nil {
			zap.L().Warn("Failed to write agent output to file",
				zap.String("path", opts.OutputPath),
				zap.Error(writeErr))
		}
	}

	result := &Result{
		AgentName:      opts.AgentName,
		TemplateID:     templateID,
		RawOutput:      stdout,
		RenderedPrompt: prompt,
		OutputSchema:   outputSchema,
		TokenUsage:     runOut.Usage,
		RecordingError: recordingError,
	}

	// Parse and ingest results based on output schema
	switch outputSchema {
	case "findings":
		findings, parseErr := parsing.ParseFindings(stdout)
		if parseErr != nil {
			zap.L().Warn("Failed to parse agent findings", zap.Error(parseErr))
			result.ParseError = parseErr.Error()
			return result, nil
		}
		result.Findings = findings
		if e.repo != nil {
			saved, skipped, ingestErr := e.ingestFindings(ctx, findings, opts)
			if ingestErr != nil {
				zap.L().Warn("Failed to ingest some findings", zap.Error(ingestErr))
			}
			result.SavedCount = saved
			result.SkippedCount = skipped
		}

	case "http_records":
		records, parseErr := parsing.ParseHTTPRecords(stdout)
		if parseErr != nil {
			zap.L().Warn("Failed to parse agent HTTP records", zap.Error(parseErr))
			result.ParseError = parseErr.Error()
			return result, nil
		}
		result.HTTPRecords = records
		if e.repo != nil {
			count, ingestErr := e.ingestHTTPRecords(ctx, records, opts)
			if ingestErr != nil {
				zap.L().Warn("Failed to ingest some HTTP records", zap.Error(ingestErr))
			}
			result.SavedCount = count
		}

	case "source_analysis":
		// Parsing and ingestion are handled by the pipeline runner (runSourceAnalysis)
		// to avoid double-ingestion. Engine only stores raw output for the caller.

	case "swarm_plan":
		// Parsing and ingestion are handled by the swarm runner (runMasterAgent)
		// to avoid double-ingestion. Engine only stores raw output for the caller.

	case "recon_deliverable":
		// Parsed by autopilot pipeline runner.

	case "vuln_queue":
		// Parsed by autopilot pipeline runner.

	case "exploitation_evidence":
		// Parsed by autopilot pipeline runner.

	case agenttypes.TriageConfirmOutputSchema:
		// Parsed by the agent triage CLI subcommand; engine just carries raw output.
	}

	return result, nil
}

// closeAgentSessionWithWarning keeps transcript finalization failure nonfatal
// without losing its signal in the run's stream. Do not return it as a provider
// failure: retrying successful tool work to repair recording can repeat effects.
// Close errors may contain private data; only fixed metadata reaches the stream.
func closeAgentSessionWithWarning(sess AgentSession, writer io.Writer) {
	if err := sess.Close(); err != nil {
		_ = WriteRuntimeProgress(writer, "agent", "recording", "Evidence degraded: transcript finalization failed; transcript may be incomplete")
	}
}

// RunWithExtra executes an agent run with additional extra template data injected.
// This is used by swarm mode to pass request context and vuln type to the template.
func (e *Engine) RunWithExtra(ctx context.Context, opts Options, extra map[string]string) (*Result, error) {
	if extra != nil {
		if opts.Extra == nil {
			opts.Extra = make(map[string]string)
		}
		for k, v := range extra {
			opts.Extra[k] = v
		}
	}
	return e.Run(ctx, opts)
}

// postProcessSourceAnalysisWithMerged handles DB ingestion and reprobing for a
// pre-parsed, pre-merged SourceAnalysisResult. It skips parsing and LLM repair
// since the caller already parsed each sub-agent's
// output individually.
func (e *Engine) postProcessSourceAnalysisWithMerged(ctx context.Context, cfg SourceAnalysisConfig,
	merged *SourceAnalysisResult, combinedRaw string, combinedPrompt string) (*SourceAnalysisResult, string, string, error) {

	if merged == nil {
		merged = &SourceAnalysisResult{}
	}

	// Fetch authentication_hostnames for the target hostname and replace hardcoded auth headers.
	var sessionHeaders map[string]string
	hostname := hostnameFromURL(cfg.TargetURL)
	if e.repo != nil && len(merged.HTTPRecords) > 0 && hostname != "" {
		dbRows, dbErr := e.repo.GetAuthenticationHostnamesByHostname(ctx, cfg.ProjectUUID, hostname)
		if dbErr == nil && len(dbRows) > 0 {
			sessionHeaders = authsession.AuthHeadersFromAuthenticationHostnames(dbRows)
			if len(sessionHeaders) > 0 {
				merged.HTTPRecords = authsession.ReplaceAuthHeadersInRecords(merged.HTTPRecords, sessionHeaders)
			}
		}
	}

	// Ingest discovered HTTP records into the database
	if e.repo != nil && len(merged.HTTPRecords) > 0 {
		ingestOpts := Options{
			Source:      "source-analysis",
			ProjectUUID: cfg.ProjectUUID,
			ScanUUID:    cfg.ScanUUID,
		}
		count, ingestErr := e.ingestHTTPRecords(ctx, merged.HTTPRecords, ingestOpts)
		if ingestErr != nil {
			zap.L().Warn("Failed to ingest source-analysis HTTP records", zap.Error(ingestErr))
		} else {
			printPhaseLine("source-analysis", fmt.Sprintf("ingested HTTP records  count=%d", count))
		}
	}

	// Adopt complete versions even on partial failure. The agent's route/body
	// description remains input lineage, never the request half of a new response.
	var reprobeErr error
	if e.repo != nil && hostname != "" {
		versions, captures, probeErr := reprobeObservedRecordVersions(ctx, e.repo, cfg.ProjectUUID, hostname, sessionHeaders, "source-analysis")
		adoptErr := adoptAgentRecordVersions(ctx, e.repo, cfg.ProjectUUID, merged.HTTPRecords, versions, captures)
		reprobeErr = errors.Join(probeErr, adoptErr)
		if reprobeErr != nil {
			zap.L().Warn("Source-analysis reprobe incomplete", zap.Error(reprobeErr))
		}
	}

	return merged, combinedRaw, combinedPrompt, reprobeErr
}

// reprobeObservedRecordVersions retains the live receipt alongside saved UUIDs.
// Database row hydration restores bytes but cannot recover capture provenance;
// never manufacture a captured receipt from those historical bytes.
func reprobeObservedRecordVersions(ctx context.Context, repo *database.Repository, projectUUID, hostname string, authHeaders map[string]string, source string) (map[string]string, map[string]*httpmsg.HttpRequestResponse, error) {
	// Prompt/session hostnames include the port; traffic rows store the service
	// hostname and port separately. Normalize only this traffic lookup boundary.
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}
	hostname = strings.Trim(hostname, "[]")
	captures := make(map[string]*httpmsg.HttpRequestResponse)
	var mu sync.Mutex
	versions, err := authsession.ReprobeUnprobedRecords(ctx, repo, projectUUID, hostname, authHeaders, source,
		func(oldUUID, _ string, observed *httpmsg.HttpRequestResponse) {
			mu.Lock()
			captures[oldUUID] = observed
			mu.Unlock()
		})
	return versions, captures, err
}

// loadObservedRecordVersion hydrates both halves together. A failed read, foreign
// project, or compacted/incomplete row must not cause UUID-only adoption. When a
// live capture is supplied, it must match the saved bytes and destination; its
// receipt is preserved rather than being lost during database reconstruction.
func loadObservedRecordVersion(ctx context.Context, repo *database.Repository, projectUUID, versionUUID string, captured ...*httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	record, err := repo.GetRecordByUUID(ctx, versionUUID)
	if err != nil {
		return nil, err
	}
	if projectUUID == "" {
		projectUUID = database.DefaultProjectUUID
	}
	if record.ProjectUUID != projectUUID {
		return nil, fmt.Errorf("record version %s belongs to another project", versionUUID)
	}
	if !record.HasResponse || record.BodyCompaction != nil || len(record.RawRequest) == 0 || len(record.RawResponse) == 0 ||
		record.RequestHash != fmt.Sprintf("%x", sha256.Sum256(record.RawRequest)) ||
		record.ResponseHash != fmt.Sprintf("%x", sha256.Sum256(record.RawResponse)) {
		return nil, fmt.Errorf("record version %s has no complete stored exchange", versionUUID)
	}
	if len(captured) > 0 {
		observed := captured[0]
		if observed == nil || observed.Request() == nil || !observed.HasResponse() {
			return nil, fmt.Errorf("record version %s has no complete live capture", versionUUID)
		}
		x := observed.Evidence()
		if x == nil || x.Provenance != evidence.ProvenanceCaptured || x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete || x.Validate() != nil {
			return nil, fmt.Errorf("record version %s has no complete live capture", versionUUID)
		}
		if !bytes.Equal(record.RawRequest, x.Request) || !bytes.Equal(record.RawResponse, x.Response) ||
			!bytes.Equal(observed.Request().Raw(), x.Request) || !bytes.Equal(observed.Response().Raw(), x.Response) {
			return nil, fmt.Errorf("record version %s does not match the live captured exchange", versionUUID)
		}
		restored, err := httpmsg.FromEvidenceExchange(x)
		if err != nil {
			return nil, fmt.Errorf("record version %s has an invalid live capture: %w", versionUUID, err)
		}
		service, expected := observed.Service(), restored.Service()
		if service == nil || service.Host() != expected.Host() || service.Port() != expected.Port() || service.Protocol() != expected.Protocol() ||
			record.Hostname != expected.Host() || record.Port != expected.Port() || record.Scheme != expected.Protocol() {
			return nil, fmt.Errorf("record version %s does not match the live captured destination", versionUUID)
		}
		return observed.Clone(), nil
	}
	// A historical raw-pair reload is not a recovered capture receipt. Keep its
	// provenance absent/unknown rather than certifying it from storage hashes.
	return database.RecordToHttpRequestResponse(record)
}

func adoptAgentRecordVersions(ctx context.Context, repo *database.Repository, projectUUID string, records []AgentHTTPRecord, versions map[string]string, captures ...map[string]*httpmsg.HttpRequestResponse) error {
	var failures []error
	for i := range records {
		versionUUID, ok := versions[records[i].RecordUUID]
		if !ok {
			continue
		}
		var captured []*httpmsg.HttpRequestResponse
		if len(captures) > 0 {
			captured = append(captured, captures[0][records[i].RecordUUID])
		}
		observed, err := loadObservedRecordVersion(ctx, repo, projectUUID, versionUUID, captured...)
		if err != nil {
			failures = append(failures, fmt.Errorf("adopt %s: %w", records[i].RecordUUID, err))
			continue
		}
		records[i].ObservedExchange = observed
		records[i].RecordUUID = versionUUID
	}
	return errors.Join(failures...)
}

// RunSourceAnalysisParallel executes consolidated source analysis in 4 LLM calls
// across 2 waves:
//
//	Wave 1 (single call):
//	  Call 1: swarm-source-explore   (reads source → notes on routes + auth + sinks)
//	Wave 2 (parallel, consumes Wave 1 output):
//	  Call 2a: swarm-source-format-routes     (route notes → JSONL http_records)
//	  Call 2b: swarm-source-format-session    (auth notes → session_config JSON)
//	  Call 3:  swarm-source-extensions         (combined notes → JS scanner extensions)
//
// The single explore call reads the codebase once and produces two labeled sections
// (routes + auth/session) that are split for the format calls. When SDK pool is
// available, format-routes reuses the explore session (multi-turn) for full context.
func (e *Engine) RunSourceAnalysisParallel(ctx context.Context, cfg SourceAnalysisConfig) (saResult *SourceAnalysisResult, rawOutput string, renderedPrompt string, err error) {
	if cfg.SourcePath == "" {
		return nil, "", "", nil
	}

	exploreTemplate := "swarm-source-explore"
	formatRoutesTemplate := "swarm-source-format-routes"
	formatSessionTemplate := "swarm-source-format-session"
	extensionsTemplate := "swarm-source-extensions"

	merged := &SourceAnalysisResult{}
	var allRawOutputs []string
	var allPrompts []string
	var errs []error

	// Build one shared olium engine for the entire SA wave. The explore
	// call runs on this engine, then the 3 format/extension calls Fork()
	// it so the explore notes live in provider history (cached, not
	// re-sent in 48KB+ user-message Appends).
	var oliumCfg *config.OliumConfig
	if e.settings != nil {
		oc := e.settings.Agent.Olium
		oliumCfg = &oc
	}
	// Build the shared session with a transcript recorder when a session dir is
	// wired, so the explore wave's turns (the only ones that run on the parent
	// — the format/extension forks carry no recorder by design) persist for
	// debugging. Closed at the end of source analysis via defer below.
	sharedSession, sharedErr := e.rt().NewSessionWithSpec(oliumCfg, SessionSpec{
		SourcePath:   cfg.SourcePath,
		IncludeTools: true,
		Record:       RecordSpec{SessionDir: cfg.SessionDir, Template: "source-analysis"},
	})
	if sharedErr != nil {
		// Falls back to the per-call build path below — sub-calls use Run()
		// instead of RunOnOliumEngine() and re-append context as before.
		zap.L().Warn("source-analysis: failed to build shared engine, falling back to per-call engines", zap.Error(sharedErr))
		sharedSession = nil
	}
	defer func() {
		if sharedSession != nil {
			_ = sharedSession.Close()
		}
	}()

	// --- Wave 1: Explore (reads source code once, produces notes for routes + auth) ---
	var exploreOutput string
	var sections sourceExploreSections

	{
		printPhaseLine("source-analysis", "running source exploration (routes + auth)")
		printPhasePromptLine("source-analysis", exploreTemplate, ResolveTemplatePath(exploreTemplate, e.settings.Agent.TemplatesDir))

		opts := Options{
			AgentName: cfg.AgentName,

			PromptTemplate: exploreTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			Files:          cfg.Files,
			Instruction:    cfg.Instruction,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         exploreTemplate,
			SessionDir:     cfg.SessionDir,
			StreamWriter:   cfg.StreamWriter,
		}
		var result *Result
		var exploreErr error
		if sharedSession != nil {
			result, exploreErr = e.RunOnOliumEngine(ctx, opts, sharedSession)
		} else {
			result, exploreErr = e.Run(ctx, opts)
		}
		if cfg.SessionDir != "" && result != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-explore-prompt.md", result.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-explore-output.md", result.RawOutput)
		}
		if exploreErr != nil {
			var explorePrompt string
			if result != nil {
				explorePrompt = result.RenderedPrompt
			}
			return nil, "", explorePrompt, fmt.Errorf("source exploration failed: %w", exploreErr)
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- explore ---\n%s", result.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- explore ---\n%s", result.RenderedPrompt))

		exploreOutput = result.RawOutput

		// Split the unified output into a structured intermediate representation
		// so downstream phases don't manipulate raw marker-delimited text directly.
		sections = extractSourceExploreSections(exploreOutput)
		writeSourceExploreSections(cfg.SessionDir, sections)
	}

	if cfg.DryRun {
		_, _ = fmt.Fprint(os.Stdout, exploreOutput)
		combinedPrompt := strings.Join(allPrompts, "\n\n")
		return nil, exploreOutput, combinedPrompt, nil
	}

	printPhaseLine("source-analysis", "exploration complete, running format + extensions in parallel")

	// Prepare explore output for appending to downstream calls.
	// Truncate to 64KB to avoid context overflow.
	exploreContext := exploreOutput
	const maxExploreBytes = 64 * 1024
	if len(exploreContext) > maxExploreBytes {
		exploreContext = exploreContext[:maxExploreBytes] + "\n\n... (truncated)"
	}

	// --- Wave 2: Format + Extensions in parallel (up to 3 goroutines, capped
	// by cfg.MaxConcurrency) ---
	// streamGroup gives each parallel sub-agent a tagged, line-buffered
	// writer. Without this, three providers streaming tokens at once
	// produce unreadable per-character interleave on the user's terminal.
	streams := newStreamGroup(cfg.StreamWriter)
	formatRoutesStream := streams.writer("format-routes")
	formatSessionStream := streams.writer("format-session")
	extensionsStream := streams.writer("extensions")

	// Prepare per-topic explore contexts for format calls (truncated to 48KB each).
	const maxSplitExploreBytes = 48 * 1024
	routesExploreContext := sections.Routes
	if len(routesExploreContext) > maxSplitExploreBytes {
		routesExploreContext = routesExploreContext[:maxSplitExploreBytes] + "\n\n... (truncated)"
	}
	sessionExploreContext := sections.Session
	if len(sessionExploreContext) > maxSplitExploreBytes {
		sessionExploreContext = sessionExploreContext[:maxSplitExploreBytes] + "\n\n... (truncated)"
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Bound the format/extension sub-agents to the configured concurrency
	// (cfg.MaxConcurrency, from --swarm-subagent-concurrency / SAMaxConcurrency).
	// 0 or an out-of-range value keeps the historical behavior of running all
	// three at once. This is a per-wave cap, stricter than and independent of
	// the process-wide provider semaphore.
	saConcurrency := cfg.MaxConcurrency
	if saConcurrency <= 0 || saConcurrency > 3 {
		saConcurrency = 3
	}
	saSem := make(chan struct{}, saConcurrency)

	printPhasePromptLine("source-analysis", formatRoutesTemplate, ResolveTemplatePath(formatRoutesTemplate, e.settings.Agent.TemplatesDir))
	printPhasePromptLine("source-analysis", formatSessionTemplate, ResolveTemplatePath(formatSessionTemplate, e.settings.Agent.TemplatesDir))
	printPhasePromptLine("source-analysis", extensionsTemplate, ResolveTemplatePath(extensionsTemplate, e.settings.Agent.TemplatesDir))

	wg.Add(3)

	// Call 2a: Format routes (route notes → JSONL http_records)
	go func() {
		defer wg.Done()
		saSem <- struct{}{}
		defer func() { <-saSem }()

		opts := Options{
			AgentName: cfg.AgentName,

			PromptTemplate: formatRoutesTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         formatRoutesTemplate,
			SessionDir:     cfg.SessionDir,
			StreamWriter:   formatRoutesStream,
		}
		// Fork the shared engine so explore notes live in provider history
		// (cached, no resend). Fall back to per-call engine + Append when
		// no shared engine is available (e.g., provider build failed above).
		var formatResult *Result
		var formatErr error
		if sharedSession != nil {
			formatResult, formatErr = e.RunOnOliumEngine(ctx, opts, sharedSession.Fork())
		} else {
			opts.Append = "## Route Analysis Notes\n\n" + routesExploreContext
			formatResult, formatErr = e.Run(ctx, opts)
		}
		formatRoutesStream.Flush()

		if cfg.SessionDir != "" && formatResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-routes-prompt.md", formatResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-routes-output.md", formatResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if formatErr != nil {
			zap.L().Warn("Route format phase failed", zap.Error(formatErr))
			errs = append(errs, fmt.Errorf("format-routes: %w", formatErr))
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- format-routes ---\n%s", formatResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- format-routes ---\n%s", formatResult.RenderedPrompt))

		result, parseErr := parsing.ParseSourceAnalysisResult(formatResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse format-routes output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("format-routes parse: %w", parseErr))
			return
		}
		if result != nil {
			merged.HTTPRecords = append(merged.HTTPRecords, result.HTTPRecords...)
		}
	}()

	// Call 2b: Format session (auth notes → session_config JSON)
	go func() {
		defer wg.Done()
		saSem <- struct{}{}
		defer func() { <-saSem }()

		opts := Options{
			AgentName: cfg.AgentName,

			PromptTemplate: formatSessionTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         formatSessionTemplate,
			SessionDir:     cfg.SessionDir,
			StreamWriter:   formatSessionStream,
		}
		var formatResult *Result
		var formatErr error
		if sharedSession != nil {
			formatResult, formatErr = e.RunOnOliumEngine(ctx, opts, sharedSession.Fork())
		} else {
			opts.Append = "## Authentication & Session Analysis Notes\n\n" + sessionExploreContext
			formatResult, formatErr = e.Run(ctx, opts)
		}
		formatSessionStream.Flush()

		if cfg.SessionDir != "" && formatResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-session-prompt.md", formatResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-session-output.md", formatResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if formatErr != nil {
			zap.L().Warn("Session format phase failed", zap.Error(formatErr))
			errs = append(errs, fmt.Errorf("format-session: %w", formatErr))
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- format-session ---\n%s", formatResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- format-session ---\n%s", formatResult.RenderedPrompt))

		result, parseErr := parsing.ParseSourceAnalysisResult(formatResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse format-session output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("format-session parse: %w", parseErr))
			return
		}
		if result != nil {
			if result.SessionConfig != nil && len(result.SessionConfig.Sessions) > 0 {
				merged.SessionConfig = result.SessionConfig
			}
		}
	}()

	// Call 3: Extensions (notes → JS scanner extensions, single call)
	go func() {
		defer wg.Done()
		saSem <- struct{}{}
		defer func() { <-saSem }()

		extOpts := Options{
			AgentName: cfg.AgentName,

			PromptTemplate: extensionsTemplate,
			TargetURL:      cfg.TargetURL,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         extensionsTemplate,
			SessionDir:     cfg.SessionDir,
			StreamWriter:   extensionsStream,
		}
		var extResult *Result
		var extErr error
		if sharedSession != nil {
			extResult, extErr = e.RunOnOliumEngine(ctx, extOpts, sharedSession.Fork())
		} else {
			// Fall back: extensions agent doesn't read source code, so always
			// append explore notes when no shared engine is available.
			extOpts.Append = "## Source Code Analysis Notes\n\n" + exploreContext
			extResult, extErr = e.Run(ctx, extOpts)
		}
		extensionsStream.Flush()

		if cfg.SessionDir != "" && extResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-extensions-prompt.md", extResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-extensions-output.md", extResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if extErr != nil {
			errs = append(errs, fmt.Errorf("extensions: %w", extErr))
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- extensions ---\n%s", extResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- extensions ---\n%s", extResult.RenderedPrompt))

		result, parseErr := parsing.ParseSourceAnalysisResult(extResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse extensions output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("extensions parse: %w", parseErr))
			return
		}
		if result != nil {
			merged.Extensions = append(merged.Extensions, result.Extensions...)
		}
	}()

	wg.Wait()

	combinedRaw := strings.Join(allRawOutputs, "\n\n")
	combinedPrompt := strings.Join(allPrompts, "\n\n")

	// All 3 calls failed — return error with explore output for diagnostics.
	if len(errs) >= 3 {
		zap.L().Warn("All format + extensions calls failed")
		return nil, combinedRaw, combinedPrompt, fmt.Errorf("source analysis format and extensions all failed: %v", errs)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			zap.L().Warn("Source analysis sub-agent failed (partial results available)", zap.Error(e))
		}
	}

	// Post-process merged results: session header replacement, DB ingestion, reprobing.
	// Build a synthetic raw output that postProcessSourceAnalysis can parse if needed.
	// Since we already parsed format output above, pass the merged result directly
	// by injecting it into the post-processing flow.
	merged.SessionExploreNotes = sessionExploreNotesOrFallback(sessionExploreContext, exploreContext)
	return e.postProcessSourceAnalysisWithMerged(ctx, cfg, merged, combinedRaw, combinedPrompt)
}

type sourceExploreSections struct {
	Routes  string `json:"routes"`
	Session string `json:"session"`
	Raw     string `json:"raw"`
}

func extractSourceExploreSections(output string) sourceExploreSections {
	routes, session := splitExploreSections(output)
	return sourceExploreSections{
		Routes:  routes,
		Session: session,
		Raw:     output,
	}
}

func writeSourceExploreSections(sessionDir string, sections sourceExploreSections) {
	if sessionDir == "" {
		return
	}
	data, err := json.MarshalIndent(sections, "", "  ")
	if err != nil {
		zap.L().Warn("Failed to marshal source explore sections", zap.Error(err))
		return
	}
	path := filepath.Join(sessionDir, "swarm-source-explore-sections.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		zap.L().Warn("Failed to write source explore sections", zap.Error(err))
	}
}

// sessionExploreNotesOrFallback returns the session explore context if available,
// otherwise falls back to the combined explore context.
// splitExploreSections splits unified explore output into route and session sections.
// It looks for "## SECTION 1: Application Routes" and "## SECTION 2: Authentication & Session Management"
// headings. If headings are not found, both sections receive the full output as fallback
// (and a warning is logged so the duplicated context cost is visible — see docs on
// the explore template format).
func splitExploreSections(output string) (routes, session string) {
	const routesMarker = "## SECTION 1: Application Routes"
	const sessionMarker = "## SECTION 2: Authentication & Session Management"

	routesIdx := strings.Index(output, routesMarker)
	sessionIdx := strings.Index(output, sessionMarker)

	switch {
	case routesIdx >= 0 && sessionIdx > routesIdx:
		routes = strings.TrimSpace(output[routesIdx+len(routesMarker) : sessionIdx])
		session = strings.TrimSpace(output[sessionIdx+len(sessionMarker):])
	case routesIdx >= 0:
		routes = strings.TrimSpace(output[routesIdx+len(routesMarker):])
		session = output // fallback
		zap.L().Warn("explore output missing SECTION 2 marker — sending full output to format-session, duplicating context",
			zap.Int("output_bytes", len(output)),
			zap.String("missing_marker", sessionMarker))
		printPhaseLine("source-analysis", fmt.Sprintf("⚠ explore output missing %q — format-session falls back to full output (~%d bytes duplicated)", sessionMarker, len(output)))
	case sessionIdx >= 0:
		routes = output // fallback
		session = strings.TrimSpace(output[sessionIdx+len(sessionMarker):])
		zap.L().Warn("explore output missing SECTION 1 marker — sending full output to format-routes, duplicating context",
			zap.Int("output_bytes", len(output)),
			zap.String("missing_marker", routesMarker))
		printPhaseLine("source-analysis", fmt.Sprintf("⚠ explore output missing %q — format-routes falls back to full output (~%d bytes duplicated)", routesMarker, len(output)))
	default:
		// No section markers found — give full output to both formatters.
		// This is the worst case: the same context gets sent 3x (routes + session + extensions),
		// so make the cost visible.
		routes = output
		session = output
		zap.L().Warn("explore output missing both SECTION markers — full output sent to all 3 sub-agents, tripling context cost",
			zap.Int("output_bytes", len(output)))
		printPhaseLine("source-analysis", fmt.Sprintf("⚠ explore output missing both SECTION markers — full output sent to all 3 sub-agents (~%d bytes × 3)", len(output)))
	}
	return
}

func sessionExploreNotesOrFallback(sessionContext, combinedContext string) string {
	if sessionContext != "" {
		return sessionContext
	}
	return combinedContext
}

// enrichContext populates context fields in the template data from database
// and module registry. Only fields declared in the template's variables list are queried.
func (e *Engine) enrichContext(ctx context.Context, data *TemplateData, templateVars []string) {
	var limits config.ContextLimits
	if e.settings != nil {
		limits = e.settings.Agent.ContextLimits
	}
	enrichContextFromDB(ctx, data, e.repo, data.Hostname, templateVars, limits, e.contextCache)
	enrichContextModules(data, templateVars)
	enrichContextCommands(data, templateVars)
}

// SetContextCache sets a context cache for DB enrichment results.
// Used by swarm runs to avoid redundant queries across phases.
func (e *Engine) SetContextCache(cache *agentprompt.ContextCache) {
	e.contextCache = cache
}

// addTokenUsage merges per-call usage into the engine-wide accumulator.
// Safe to call from concurrent Engine.Run / RunSourceAnalysisParallel paths.
func (e *Engine) addTokenUsage(u agenttypes.TokenUsage) {
	if u.InputTokens == 0 && u.OutputTokens == 0 {
		return
	}
	e.tokenUsageMu.Lock()
	e.tokenUsage.InputTokens += u.InputTokens
	e.tokenUsage.OutputTokens += u.OutputTokens
	e.tokenUsageMu.Unlock()
}

// TokenUsage returns the cumulative token usage of every Engine.Run call
// made on this Engine instance. SwarmRunner reads this at finalize time.
func (e *Engine) TokenUsage() agenttypes.TokenUsage {
	e.tokenUsageMu.Lock()
	defer e.tokenUsageMu.Unlock()
	return e.tokenUsage
}

// ResetTokenUsage zeroes the accumulator. Useful for tests; production
// callers get a fresh accumulator from NewEngine.
func (e *Engine) ResetTokenUsage() {
	e.tokenUsageMu.Lock()
	e.tokenUsage = agenttypes.TokenUsage{}
	e.tokenUsageMu.Unlock()
}

// InvalidateContextCache clears the context cache. Call after phases
// that modify scan data (native scan, rescan).
func (e *Engine) InvalidateContextCache() {
	if e.contextCache != nil {
		e.contextCache.Invalidate()
	}
}

// buildPrompt resolves the prompt source and renders it.
// Returns the rendered prompt, output schema, template ID, and any error.
func (e *Engine) buildPrompt(ctx context.Context, opts Options) (prompt string, outputSchema string, templateID string, err error) {
	// Priority: stdin > inline > file > template
	if opts.Stdin {
		data, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return "", "", "", fmt.Errorf("failed to read prompt from stdin: %w", readErr)
		}
		prompt = string(data)
		return prompt, "", "", nil
	}

	if opts.PromptInline != "" {
		return opts.PromptInline, "", "", nil
	}

	if opts.PromptFile != "" {
		tmpl, loadErr := agentprompt.LoadTemplateFromFile(opts.PromptFile)
		if loadErr != nil {
			return "", "", "", fmt.Errorf("failed to load prompt file: %w", loadErr)
		}
		templateData, gatherErr := e.gatherContext(ctx, opts, tmpl.Variables)
		if gatherErr != nil {
			return "", "", "", gatherErr
		}
		e.enrichContext(ctx, &templateData, tmpl.Variables)
		rendered, renderErr := agentprompt.RenderTemplate(tmpl, templateData)
		if renderErr != nil {
			return "", "", "", renderErr
		}
		rendered = appendPromptSuffix(rendered, opts)
		return rendered, tmpl.OutputSchema, tmpl.ID, nil
	}

	if opts.PromptTemplate != "" {
		// A directly constructed engine may omit optional settings (as the
		// inline/file paths already allow). Use the loader's default search
		// paths rather than panicking before runtime dispatch.
		templatesDir := ""
		if e.settings != nil {
			templatesDir = e.settings.Agent.TemplatesDir
		}
		tmpl, loadErr := agentprompt.LoadTemplate(opts.PromptTemplate, templatesDir)
		if loadErr != nil {
			return "", "", "", loadErr
		}
		templateData, gatherErr := e.gatherContext(ctx, opts, tmpl.Variables)
		if gatherErr != nil {
			return "", "", "", gatherErr
		}
		e.enrichContext(ctx, &templateData, tmpl.Variables)
		rendered, renderErr := agentprompt.RenderTemplate(tmpl, templateData)
		if renderErr != nil {
			return "", "", "", renderErr
		}
		rendered = appendPromptSuffix(rendered, opts)
		return rendered, tmpl.OutputSchema, tmpl.ID, nil
	}

	return "", "", "", fmt.Errorf("no prompt source specified (use --prompt-template, --prompt-file, --prompt, or --stdin)")
}

// appendPromptSuffix appends optional Append text and custom instructions to a rendered prompt.
func appendPromptSuffix(rendered string, opts Options) string {
	if opts.Append != "" {
		rendered += "\n\n" + opts.Append
	}
	if opts.Instruction != "" {
		rendered += "\n\n## Custom Instructions\n\n" + opts.Instruction
	}
	return rendered
}

// gatherContext reads source files and prepares template data.
// templateVars controls what gets populated: if "SourceCode" is declared,
// source files are read into the prompt; if only "SourcePath"/"DirectoryTree"
// are declared, just a directory listing is generated (letting the agent
// explore the codebase itself via tool use).
func (e *Engine) gatherContext(ctx context.Context, opts Options, templateVars []string) (TemplateData, error) {
	data := TemplateData{
		SourcePath: opts.SourcePath,
		Extra:      make(map[string]string),
	}

	// Set target context from options (always, regardless of SourcePath)
	if opts.TargetURL != "" {
		data.TargetURL = opts.TargetURL
	}
	if opts.Hostname != "" {
		data.Hostname = opts.Hostname
	} else if opts.TargetURL != "" {
		data.Hostname = hostnameFromURL(opts.TargetURL)
	}

	// Inject extra template data from options
	if opts.Extra != nil {
		for k, v := range opts.Extra {
			data.Extra[k] = v
		}
	}

	if opts.SourcePath == "" {
		return data, nil
	}

	// Check if the template wants embedded source code or just the path
	wantsSourceCode := hasVar(templateVars, "SourceCode")
	wantsDirectoryTree := hasVar(templateVars, "DirectoryTree")

	// Collect file list for language detection and (optionally) source code
	files := opts.Files
	if len(files) == 0 {
		collected, err := collectSourceFiles(ctx, opts.SourcePath)
		if err != nil {
			zap.L().Warn("Failed to collect source files", zap.Error(err))
		}
		files = collected
	}

	data.Language = detectLanguage(files)

	// Generate skip guidance if requested (tells the agent what to avoid, no tree dump).
	// Cached since it returns a static string.
	if hasVar(templateVars, "SkipGuidance") {
		e.skipGuidanceOnce.Do(func() {
			e.skipGuidanceText = generateSkipGuidance()
		})
		data.SkipGuidance = e.skipGuidanceText
	}

	// Generate directory tree listing if requested and SkipGuidance is not used
	// (SkipGuidance replaces the tree — the agent explores on its own).
	// Cached per sourcePath since the tree doesn't change within a run.
	if wantsDirectoryTree && !hasVar(templateVars, "SkipGuidance") {
		tree := e.cachedDirectoryTree(opts.SourcePath)
		if tree != "" {
			data.DirectoryTree = tree
		}
	}

	// Build a source hint summarizing the pre-filtered codebase
	if hasVar(templateVars, "SourceHint") && (data.DirectoryTree != "" || data.SkipGuidance != "" || len(files) > 0) {
		lang := data.Language
		if lang == "" {
			lang = "unknown"
		}
		data.SourceHint = fmt.Sprintf(
			"This directory tree has been pre-filtered to remove build artifacts, "+
				"dependencies, media assets, generated code, and lock files. "+
				"%d source files detected (%s). "+
				"Focus on route definitions, request handlers, authentication logic, "+
				"and input validation code.",
			len(files), lang)
	}

	// Only embed full source code if the template declares SourceCode variable
	if wantsSourceCode {
		data.SourceCode = e.collectSourceCode(opts.SourcePath, files)
	}

	return data, nil
}

// hasVar checks whether a variable name exists in the template variables list.
func hasVar(vars []string, name string) bool {
	for _, v := range vars {
		if v == name {
			return true
		}
	}
	return false
}

// collectSourceCode reads source files and returns concatenated content with file headers.
func (e *Engine) collectSourceCode(sourcePath string, files []string) string {
	var sourceCode strings.Builder

	const maxSourceBytes = 128 * 1024 // 128KB limit for source code context

	var skipped int
	for _, f := range files {
		path := f
		if !filepath.IsAbs(f) {
			path = filepath.Join(sourcePath, f)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			zap.L().Debug("Skipping unreadable file", zap.String("path", path), zap.Error(err))
			continue
		}
		if sourceCode.Len()+len(content) > maxSourceBytes {
			skipped++
			continue
		}
		rel, _ := filepath.Rel(sourcePath, path)
		if rel == "" {
			rel = f
		}
		fmt.Fprintf(&sourceCode, "// --- %s ---\n", rel)
		sourceCode.Write(content)
		sourceCode.WriteString("\n\n")
	}
	if skipped > 0 {
		zap.L().Warn("Source context truncated due to size limit",
			zap.Int("files_included", len(files)-skipped),
			zap.Int("files_skipped", skipped),
			zap.Int("max_bytes", maxSourceBytes))
		fmt.Fprintf(&sourceCode, "\n// --- %d additional files skipped (context limit: %dKB) ---\n", skipped, maxSourceBytes/1024)
	}

	return sourceCode.String()
}

// cachedDirectoryTree returns the directory tree for the given source path,
// caching the result so repeated calls with the same path avoid filesystem walks.
func (e *Engine) cachedDirectoryTree(sourcePath string) string {
	if sourcePath == "" {
		return ""
	}

	e.dirTreeCacheMu.RLock()
	if cached, ok := e.dirTreeCache[sourcePath]; ok {
		e.dirTreeCacheMu.RUnlock()
		return cached
	}
	e.dirTreeCacheMu.RUnlock()

	tree, err := generateDirectoryTree(sourcePath)
	if err != nil {
		zap.L().Warn("Failed to generate directory tree", zap.Error(err))
		return ""
	}

	e.dirTreeCacheMu.Lock()
	if e.dirTreeCache == nil {
		e.dirTreeCache = make(map[string]string)
	}
	e.dirTreeCache[sourcePath] = tree
	e.dirTreeCacheMu.Unlock()
	return tree
}

// generateDirectoryTree produces a compact tree listing of a source directory,
// showing the structure up to 3 levels deep with file counts for deeper directories.
func generateDirectoryTree(root string) (string, error) {
	const maxDepth = 4
	const maxEntries = 500

	var sb strings.Builder
	entries := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entries >= maxEntries {
			return filepath.SkipAll
		}
		// Skip symlinks to avoid cycles
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}

		depth := strings.Count(rel, string(filepath.Separator))

		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			if depth >= maxDepth {
				return filepath.SkipDir
			}
			indent := strings.Repeat("  ", depth)
			fmt.Fprintf(&sb, "%s%s/\n", indent, d.Name())
			entries++
			return nil
		}

		// Skip non-source files (media, binaries, lock files, minified bundles)
		if shouldSkipFile(d.Name()) {
			return nil
		}

		if depth < maxDepth {
			indent := strings.Repeat("  ", depth)
			fmt.Fprintf(&sb, "%s%s\n", indent, d.Name())
			entries++
		}
		return nil
	})

	if entries >= maxEntries {
		sb.WriteString("... (truncated)\n")
	}

	return sb.String(), err
}

// generateSkipGuidance returns a concise list of file/directory categories
// that the agent should avoid when exploring source code. Instead of dumping
// the full directory tree into the prompt, we let the agent explore on its own
// and just tell it what to skip.
func generateSkipGuidance() string {
	return `Do NOT spend time reading or exploring these categories of files and directories:

1. **Third-party libraries & dependencies** — node_modules/, vendor/, bower_components/, Pods/, .cargo/, .gradle/, .mvn/, .bundle/, .dart_tool/, .pub-cache/, site-packages/
2. **Compiled & generated files** — dist/, build/, out/, .next/, .nuxt/, target/, *.min.js, *.min.css, *.pb.go, *_generated.*, *.d.ts, *.pyc, *.class, *.o, *.so, *.dll
3. **Static media assets** — images (*.png, *.jpg, *.gif, *.svg, *.ico, *.webp), fonts (*.woff, *.woff2, *.ttf, *.eot), audio/video (*.mp4, *.mp3, *.wav)
4. **Database migrations** — migrations/, db/migrate/, alembic/, flyway/, sql/migrations/, schema/
5. **Lock & checksum files** — package-lock.json, yarn.lock, bun.lock, Gemfile.lock, poetry.lock, go.sum, *.lock, *.sum
6. **VCS, IDE & CI/CD config** — .git/, .svn/, .idea/, .vscode/, .github/, .gitlab/, .circleci/, .terraform/
7. **Test fixtures & snapshots** — __snapshots__/, fixtures/ (but DO read test source files — they often contain credentials and auth patterns)`
}
