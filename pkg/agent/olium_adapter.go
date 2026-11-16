package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/olium"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
	"github.com/vigolium/vigolium/pkg/olium/vigtool"
	"go.uber.org/zap"
)

// oliumRunOutput is the structured return of runOliumPrompt — text plus the
// per-call token usage summed across all turns of the multi-turn loop.
type oliumRunOutput struct {
	Text  string
	Usage agenttypes.TokenUsage
	// ToolCalls counts the tools the engine dispatched during the call, for
	// the run-wide --max-commands budget (RunBudget).
	ToolCalls int
	// RecordingError is a non-fatal, sanitized operator log degradation. It
	// must not cause tool re-execution or alter the parsed assistant answer.
	RecordingError string
}

// oliumProviderSem caps the number of in-flight olium provider calls
// across the entire process. Sized lazily on first acquire from
// cfg.EffectiveMaxConcurrent(); subsequent config changes are ignored to
// keep semantics simple (the swarm/autopilot session uses one config).
//
// Without this cap, source-analysis (3 parallel) + plan batches (3 parallel)
// + triage + repair calls can pile up and trigger 429s on tier-1 API plans.
var (
	oliumProviderSemOnce sync.Once
	oliumProviderSem     chan struct{}
)

// acquireProviderSlot blocks until a provider slot is available or ctx is
// cancelled. Returns a release func; safe to defer immediately after acquire.
func acquireProviderSlot(ctx context.Context, cfg *config.OliumConfig) (release func(), err error) {
	max := 4
	if cfg != nil {
		max = cfg.EffectiveMaxConcurrent()
	}
	if max <= 0 {
		// Unbounded — no semaphore.
		return func() {}, nil
	}
	oliumProviderSemOnce.Do(func() {
		oliumProviderSem = make(chan struct{}, max)
	})
	select {
	case oliumProviderSem <- struct{}{}:
		return func() { <-oliumProviderSem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// runOliumPromptWithThinking is the single dispatch path for all Engine.Run
// callers (query, swarm phases, source analysis) after the subprocess-backend
// removal. Streaming: if streamWriter is non-nil, text deltas are mirrored
// there in real time. It also forwards the model's thinking deltas
// (reasoning content from o1 / Claude thinking) to thinkingWriter — pass nil
// to discard. sourcePath, when set, is appended to the system prompt so the
// agent knows it has filesystem access to local source code.
func runOliumPromptWithThinking(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool, rec RecordSpec) (oliumRunOutput, error) {
	eng, err := buildOliumEngineWithSpec(cfg, SessionSpec{SourcePath: sourcePath, IncludeTools: true, Record: rec}, streamWriter)
	if err != nil {
		return oliumRunOutput{}, err
	}
	// Fresh-per-call path: this engine isn't reused, so flush + close its
	// transcript recorder here (no-op when rec.SessionDir was empty). The
	// recorder buffers the final assistant turn until close, so without this
	// the last turn never lands in the transcript.
	defer func() { _ = eng.CloseRecorder() }()
	return runOliumOnEngineWithThinking(ctx, cfg, eng, prompt, streamWriter, thinkingWriter, verbose)
}

// sessionMaxTurns gives specialized sessions priority over the ordinary phase
// budget. Non-positive values keep the bounded engine default; they never mean
// unlimited execution. Autopilot constructs its engine separately.
func sessionMaxTurns(cfg *config.OliumConfig, spec SessionSpec) int {
	if spec.MaxTurns > 0 {
		return spec.MaxTurns
	}
	if cfg != nil && cfg.MaxTurns > 0 {
		return cfg.MaxTurns
	}
	return 0
}

// buildOliumEngineWithSpec is the general engine constructor behind the
// AgentRuntime seam. It resolves the provider from olium config, then applies
// the SessionSpec (system prompt, source-path suffix, turn cap, tool set,
// prompt cache). Concrete olium engine/provider/tool types are confined to this
// file so the rest of pkg/agent depends only on the AgentRuntime interface.
func buildOliumEngineWithSpec(cfg *config.OliumConfig, spec SessionSpec, recordingSink ...io.Writer) (*oengine.Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("olium config is nil")
	}
	effectiveExtraBody, err := cfg.CustomProvider.EffectiveExtraBody()
	if err != nil {
		return nil, fmt.Errorf("olium custom_provider: %w", err)
	}
	prov, _, model, err := olium.ResolveProvider(olium.Options{
		Provider:            cfg.Provider,
		OAuthCredPath:       cfg.OAuthCredPath,
		OAuthToken:          cfg.OAuthToken,
		LLMAPIKey:           cfg.LLMAPIKey,
		GoogleCloudProject:  cfg.GoogleCloudProject,
		GoogleCloudLocation: cfg.GoogleCloudLocation,
		Model:               cfg.Model,
		ReasoningEffort:     cfg.ReasoningEffort,
		CustomBaseURL:       cfg.CustomProvider.BaseURL,
		CustomModelID:       cfg.CustomProvider.ModelID,
		CustomAPIKey:        firstNonEmpty(cfg.CustomProvider.APIKey, cfg.LLMAPIKey),
		CustomExtraHeaders:  cfg.CustomProvider.ExtraHeadersMap(),
		CustomExtraBody:     effectiveExtraBody,
	})
	if err != nil {
		return nil, fmt.Errorf("olium provider: %w", err)
	}

	if spec.PlanningOnly {
		// These providers execute their own hidden tool loops, outside olium's
		// dispatch boundary. Do not claim a no-probe guarantee they cannot honor.
		if err := planningProviderPolicy(prov); err != nil {
			return nil, err
		}
	}

	system := spec.System
	if system == "" {
		system = cfg.SystemPrompt
		if system == "" {
			system = olium.DefaultSystemPrompt
		}
	}
	if spec.SourcePath != "" {
		system += "\n\nApplication source code is available at: " + spec.SourcePath
	}
	if spec.PlanningOnly {
		system = planningSystemPrompt(spec.Skills)
	}

	ecfg := oengine.Config{
		Provider:          prov,
		Model:             model,
		System:            system,
		MaxTurns:          sessionMaxTurns(cfg, spec),
		EnablePromptCache: spec.EnablePromptCache,
		SpillDir:          spec.Record.SessionDir, // private, project-scoped full tool archive
		// Skills, when set, are rendered into the system prompt as an
		// <available_skills> block by engine.New. The load_skill tool that
		// serves their bodies is registered below (requires IncludeTools).
		Skills: spec.Skills,
	}
	if spec.PlanningOnly {
		ecfg.Skills = nil // selection metadata above, never load/follow guidance
		ecfg.DisableTools = true
		ecfg.RequireFinalAnswer = true
	}
	if !spec.PlanningOnly && spec.IncludeTools && spec.OfflineTools {
		ecfg.Skills = nil // this registry has no load_skill tool
		reg := tool.NewRegistry()
		tool.RegisterOfflineBuiltins(reg)
		ecfg.Tools = reg
	} else if !spec.PlanningOnly && spec.IncludeTools {
		reg := tool.NewRegistry()
		tool.RegisterBuiltins(reg, nil)
		if spec.Skills != nil && spec.Skills.Len() > 0 {
			reg.Register(skill.NewLoadTool(spec.Skills, reg))
		}
		// Read+replay subset: lets a skill-driven agent confirm/escalate against
		// prior scan records (explore → inspect → craft → replay). Stateless
		// tools only — no oast_mint (it owns an interactsh Service needing
		// Shutdown the per-call engine can't run).
		if spec.VigTools != nil && spec.VigTools.Repo != nil {
			sessCtx := &vigtool.SessionsContext{
				Repo:        spec.VigTools.Repo,
				ProjectUUID: spec.VigTools.ProjectUUID,
			}
			reg.Register(vigtool.NewQueryRecordsTool(sessCtx))
			reg.Register(vigtool.NewInspectRecordTool(sessCtx))
			reg.Register(vigtool.NewReplayRequestTool(sessCtx))
			reg.Register(vigtool.NewAttackKitTool())
		}
		if spec.BurpBridgeTools != nil {
			sessCtx := &vigtool.SessionsContext{ProjectUUID: spec.BurpBridgeTools.ProjectUUID}
			reg.Register(vigtool.NewSearchBurpItemsTool(sessCtx))
			reg.Register(vigtool.NewInspectBurpItemTool(sessCtx))
		}
		ecfg.Tools = reg
	}

	// Attach a Pi-style JSONL transcript recorder when a session dir is wired.
	// Mirrors autopilot's transcript so swarm/query phases also persist their
	// turns — including model reasoning — for post-hoc debugging. A recorder
	// construction failure is non-fatal: the run proceeds without a transcript.
	if spec.Record.SessionDir != "" {
		name := uniqueTranscriptName(spec.Record.SessionDir, spec.Record.Template)
		sessID := spec.Record.SessionID
		if sessID == "" {
			sessID = filepath.Base(spec.Record.SessionDir)
		}
		cwd, _ := os.Getwd()
		rec, rerr := sessionlog.New(filepath.Join(spec.Record.SessionDir, name), sessionlog.Meta{
			SessionID: sessID,
			Provider:  prov.Name(),
			Model:     model,
			Cwd:       cwd,
		})
		var sink io.Writer
		if len(recordingSink) > 0 {
			sink = recordingSink[0]
		}
		ec := &adapterRecorder{rec: rec, err: rerr, sink: sink}
		ec.warnIfDegraded()
		ecfg.Recorder = ec
	}

	return oengine.New(ecfg), nil
}

// adapterRecorder keeps evidence failure non-fatal but observable. The safe
// metadata warning never includes prompts, arguments, HTTP bodies, or results.
// Fresh calls also mirror it to their runtime sink; session callers still get
// the sticky error from Close and the configured logger warning.
type adapterRecorder struct {
	mu     sync.Mutex
	rec    *sessionlog.Recorder
	err    error
	sink   io.Writer
	warned bool
}

func (r *adapterRecorder) warnIfDegraded() {
	err := r.err
	if err == nil && r.rec != nil {
		err = r.rec.Err()
	}
	if err != nil && !r.warned {
		r.warned = true
		zap.L().Warn("Agent transcript recording degraded; evidence may be incomplete", zap.Error(err))
		_ = WriteRuntimeProgress(r.sink, "agent", "recording", "Evidence degraded: transcript recording failed; transcript may be incomplete")
	}
}

func (r *adapterRecorder) UserPrompt(prompt string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rec != nil {
		r.rec.UserPrompt(prompt)
	}
	r.warnIfDegraded()
}

func (r *adapterRecorder) Record(ev oengine.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rec != nil {
		r.rec.Record(ev)
	}
	r.warnIfDegraded()
}

func (r *adapterRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rec != nil {
		r.err = r.rec.Close()
	}
	r.warnIfDegraded()
	return r.err
}

// classifyOliumEventError restores context sentinels lost at the engine's
// string-only event boundary. A per-call deadline remains retryable while a
// cancelled/expired parent is still rejected by isRetryableAgentError.
func classifyOliumEventError(ctx context.Context, msg string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, context.DeadlineExceeded.Error()) {
		return fmt.Errorf("%s: %w", msg, context.DeadlineExceeded)
	}
	if strings.Contains(lower, context.Canceled.Error()) {
		return fmt.Errorf("%s: %w", msg, context.Canceled)
	}
	return classifyOliumError(msg)
}

// transcriptSeqCacheSize bounds the (sessionDir, template) → counter LRU. The
// counter only needs to disambiguate concurrent same-template calls within a
// single run (a swarm plan batch), which all happen close together, so a few
// thousand recent entries is ample. A flat map here was an unbounded leak: each
// run has a unique sessionDir, so its keys accumulated for the whole process
// lifetime even after the session dir was cleaned off disk.
const transcriptSeqCacheSize = 4096

// transcriptSeq tracks how many recorders have been opened per
// (sessionDir, template) within this process, so concurrent same-template
// calls (swarm plan batches run up to BatchConcurrency goroutines deep) get
// distinct files instead of interleaving large tool-result lines into one.
var (
	transcriptSeqMu sync.Mutex
	transcriptSeq   *lru.Cache[string, int]
)

// uniqueTranscriptName returns the per-phase transcript basename for a session
// dir + template. The first use of a (dir, template) pair in this process gets
// the clean name (transcript-<template>.jsonl); the 2nd, 3rd, … get
// transcript-<template>-2.jsonl etc. Keying on dir keeps separate runs (each
// its own session dir) clean — only true collisions within one run are
// suffixed. An empty template falls back to "inline", matching the thinking
// sink's naming.
func uniqueTranscriptName(sessionDir, template string) string {
	safe := sanitizeTemplateSegment(template)
	key := sessionDir + "\x00" + safe
	transcriptSeqMu.Lock()
	if transcriptSeq == nil {
		// lru.New only errors on size <= 0; the constant is positive.
		transcriptSeq, _ = lru.New[string, int](transcriptSeqCacheSize)
	}
	n, _ := transcriptSeq.Get(key)
	transcriptSeq.Add(key, n+1)
	transcriptSeqMu.Unlock()
	if n == 0 {
		return "transcript-" + safe + ".jsonl"
	}
	return fmt.Sprintf("transcript-%s-%d.jsonl", safe, n+1)
}

// runOliumOnEngineWithThinking is the full-fidelity version that also
// forwards thinking deltas (reasoning content) to a separate sink. Lets
// session-dir loggers preserve the model's reasoning artifact for later
// debugging without polluting the user-visible text stream.
func runOliumOnEngineWithThinking(ctx context.Context, cfg *config.OliumConfig, eng *oengine.Engine, prompt string, streamWriter, thinkingWriter io.Writer, verbose bool) (oliumRunOutput, error) {
	release, err := acquireProviderSlot(ctx, cfg)
	if err != nil {
		return oliumRunOutput{}, err
	}
	defer release()

	// Bound the per-call duration so a hung provider stream can't pin the
	// whole phase. context.DeadlineExceeded is already a retryable
	// sentinel — retryAgentCall will back off and retry.
	if cfg != nil {
		if to := cfg.EffectiveCallTimeout(); to > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, to)
			defer cancel()
		}
	}

	var captured, currentTurn strings.Builder
	var terminalErr error
	var usage agenttypes.TokenUsage
	toolCalls := 0
	archiveWarned := false
	// Surface full tool arguments/results for recorded operator streams;
	// unrecorded runs keep concise tool cards. Per-turn usage is *not* echoed here — swarm
	// drives many short phases and a [turn done ...] line per phase is too
	// noisy. Adapter still tallies usage from the same event below. The
	// reasoning lane is pinned to stderr (not streamWriter, which is stdout
	// for swarm/query) so piped stdout stays clean; it's gated on --verbose
	// inside the logger.
	tlog := toollog.NewWith(streamWriter, verbose).WithThinkingWriter(os.Stderr).WithFullOutput(eng.ToolArchiveDir())
	ch := eng.Run(ctx, prompt)
	for ev := range ch {
		if ev.Type == oengine.EventToolExecStart {
			toolCalls++
		}
		if ev.Type == oengine.EventToolExecEnd && !archiveWarned {
			if receipt, ok := ev.ToolDetails[tool.ArchiveDetailsKey].(map[string]any); ok {
				if complete, _ := receipt["complete"].(bool); !complete {
					archiveWarned = true
					zap.L().Warn("Agent tool archive degraded; full output retention is not guaranteed")
					_ = WriteRuntimeProgress(streamWriter, "agent", "recording", "Evidence degraded: tool archive incomplete; full output retention is not guaranteed")
				}
			}
		}
		if tlog.HandleTool(ev) {
			continue
		}
		if tlog.HandleThinking(ev) {
			// Also persist raw reasoning to the per-template thinking file
			// (transcript artifact) when one is wired; the logger only renders
			// the live, compacted stderr lane.
			if thinkingWriter != nil {
				_, _ = io.WriteString(thinkingWriter, ev.Delta)
			}
			continue
		}
		switch ev.Type {
		case oengine.EventTextDelta:
			// Flush buffered reasoning before this turn's assistant text so the
			// operator reads think → answer (a text-only phase never hits a
			// tool card to trigger the flush).
			tlog.FlushThinking()
			currentTurn.WriteString(ev.Delta)
			if streamWriter != nil {
				_, _ = io.WriteString(streamWriter, ev.Delta)
			}
		case oengine.EventStreamRetry:
			if ev.Usage != nil {
				usage.InputTokens += ev.Usage.Input
				usage.OutputTokens += ev.Usage.Output
			}
			// The recorder retains this abandoned attempt separately. Only the
			// current turn is discarded from parsed output; earlier completed
			// turns and their tool work must survive recovery.
			tlog.FlushThinking()
			currentTurn.Reset()
		case oengine.EventTurnDone:
			captured.WriteString(currentTurn.String())
			currentTurn.Reset()
			if ev.Usage != nil {
				usage.InputTokens += ev.Usage.Input
				usage.OutputTokens += ev.Usage.Output
			}
		case oengine.EventError:
			tlog.FlushThinking()
			if ev.Usage != nil {
				usage.InputTokens += ev.Usage.Input
				usage.OutputTokens += ev.Usage.Output
			}
			cause := classifyOliumEventError(ctx, ev.Err)
			if ev.BudgetExhausted && ctx.Err() == nil {
				kind := "turns"
				if strings.Contains(ev.Err, "max tool calls") {
					kind = "tool_calls"
				}
				cause = &RuntimeBudgetError{Kind: kind, Reason: ev.Err}
			}
			terminalErr = fmt.Errorf("olium: %w", cause)
		}
	}
	// Flush reasoning from a final turn that produced no assistant text and no
	// tool card (otherwise it'd be silently dropped at phase end).
	tlog.FlushThinking()
	// A terminal failure still returns the final attempt's partial output.
	captured.WriteString(currentTurn.String())
	var recordingError string
	if err := tlog.Err(); err != nil {
		recordingError = err.Error()
		tlog.ReportIncomplete()
	}
	return oliumRunOutput{Text: captured.String(), Usage: usage, ToolCalls: toolCalls, RecordingError: recordingError}, terminalErr
}

// WrapProviderWithSemaphore returns a provider.Provider that gates each
// Stream call through the shared oliumProviderSem. Use this around the
// resolved provider before passing it into long-running loops (autopilot)
// so their per-turn LLM calls participate in the same process-wide cap as
// the swarm/source-analysis paths — without this, autopilot bypasses the
// limiter and N concurrent sessions can flood the provider with 429s.
//
// The slot is held only for the duration of one Stream (one model turn),
// not the whole run, so a multi-hour autopilot doesn't pin a slot.
func WrapProviderWithSemaphore(cfg *config.OliumConfig, p provider.Provider) provider.Provider {
	if p == nil {
		return nil
	}
	return &semaphoreProvider{inner: p, cfg: cfg}
}

type semaphoreProvider struct {
	inner provider.Provider
	cfg   *config.OliumConfig
}

func (s *semaphoreProvider) Name() string { return s.inner.Name() }

// CloseIdleConnections forwards to the wrapped provider when it implements
// provider.ConnectionResetter so the engine's retry path can drain idle
// conns through the wrapper without unwrapping first.
func (s *semaphoreProvider) CloseIdleConnections() {
	if r, ok := s.inner.(provider.ConnectionResetter); ok {
		r.CloseIdleConnections()
	}
}

func (s *semaphoreProvider) Stream(ctx context.Context, req provider.Request) (<-chan stream.Event, error) {
	release, err := acquireProviderSlot(ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	innerCh, err := s.inner.Stream(ctx, req)
	if err != nil {
		release()
		return nil, err
	}
	// Re-emit events on a forwarded channel and release the slot only
	// after the inner stream drains. The engine drains the channel in
	// streamOnce, so cancelling ctx propagates to the inner provider and
	// the close arrives promptly.
	out := make(chan stream.Event, cap(innerCh))
	go func() {
		defer release()
		defer close(out)
		for ev := range innerCh {
			out <- ev
		}
	}()
	return out, nil
}
