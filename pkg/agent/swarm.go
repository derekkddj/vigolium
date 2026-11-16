package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/pkg/audit/claudecost"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/skill"

	"go.uber.org/zap"
)

// SwarmConfig configures an agent swarm run.
type SwarmConfig struct {
	// Inputs: raw input strings (URL, curl, raw HTTP, Burp XML, or record UUID)
	Inputs    []string  // raw input strings
	InputType InputType // explicit type (auto-detected if empty)

	// Source analysis
	SourcePath  string                  // path to application source code (triggers source analysis phase)
	Files       []string                // specific files to include (relative to SourcePath)
	DiffContext *agenttypes.DiffContext // non-nil when --diff or --last-commits was provided

	// Custom instruction
	Instruction string // user-provided custom instruction appended to agent prompts

	// ForceExtensions forces the Phase-2 extension agent to run even when the
	// plan agent decides built-in modules are sufficient. Bound to --with-extensions
	// on the CLI. Has no effect when DryRun is true (DryRun still skips Phase 2).
	ForceExtensions bool

	// Skill selection (planner-driven loading overrides)
	SkillNames    []string // --skill: force-include these skills, bypassing planner judgement
	SkillTags     []string // --skill-tag: force-include every skill carrying one of these tags
	NoSkillFilter bool     // --no-skill-filter: load the full skill set, ignore planner selection

	// Scanning parameters
	VulnType         string   // optional: focus on specific vulnerability type
	Focus            string   // optional: broad strategic hint (e.g. "API injection", "auth bypass")
	ModuleNames      []string // optional: explicit module IDs to use
	OnlyPhase        string   // isolate a single phase (empty = all phases)
	SkipPhases       []string // skip specific phases (empty = skip none)
	MaxIterations    int      // max triage-rescan loops (default 3)
	BatchConcurrency int      // max parallel master agent batches (0 = default 3)
	MaxMasterRetries int      // max master agent retries on parse failure (0 = default 3)
	SAMaxConcurrency int      // max parallel source analysis sub-agents (0 = default 3)

	// Agent
	AgentName          string
	DryRun             bool
	ShowPrompt         bool   // print rendered prompts to stderr before executing
	SourceAnalysisOnly bool   // run only source analysis phase and exit
	CodeAudit          bool   // enable AI security code audit phase (--code-audit)
	Browser            bool   // enable agent-browser integration (always on for swarm; no --browser flag)
	Auth               bool   // run browser-based auth phase before discovery (--browser-auth)
	Credentials        string // optional credentials for the browser auth phase (extracted from the prompt)
	CredentialSets     []agenttypes.IntentCredentialSet
	AuthRequired       bool
	RequiresBrowser    bool
	BrowserStartURL    string
	FocusRoutes        []string

	// Context truncation
	MaxResponseBodyBytes int // max response body size in context; 0 = default 4096
	MaxPlanRecords       int // max records sent to plan agent; 0 = no cap (ship the full surface)

	// Tuning: batching, probing, retries
	MasterBatchSize  int           // max records per master agent batch; 0 = default 5
	ProbeConcurrency int           // max parallel probe requests; 0 = default 10
	ProbeTimeout     time.Duration // per-request probe timeout; 0 = default 10s
	MaxProbeBodySize int           // max response body bytes during probing; 0 = default 2MB

	// ReconExtraHeaders, when set, is injected onto every recon probe
	// (and into the prompt-context's TechStack rendering). Populated by
	// the CLI from --cookie / --header / --auth-config so that recon
	// fingerprints authenticated pages instead of the public landing.
	ReconExtraHeaders map[string]string

	// Project/scan

	ProjectUUID string
	ScanUUID    string

	// Session directory base path for agent artifacts
	SessionsDir string

	// SessionDir is the pre-created session directory for this run.
	// When set, the swarm runner uses it directly instead of creating one.
	SessionDir string

	// AgenticScanUUID overrides the auto-generated agent run UUID.
	// When set (e.g. by CLI), the swarm runner uses this UUID for the DB record,
	// ensuring it matches the pre-created session directory name.
	AgenticScanUUID string

	// ResumeDir is the session directory of a previous run to resume from.
	// When set, the swarm runner loads the checkpoint and skips completed phases.
	ResumeDir string

	// Streaming: raw AI output and best-effort runtime metadata for this session.
	// Run synchronizes writes but never closes the caller-owned writer.
	StreamWriter     io.Writer
	Verbose          bool // when true, agent calls render a per-tool result preview alongside the standard one-liner
	ProgressCallback func(ProgressEvent)

	// ScanFunc runs the scan with the given module filters and extensions.
	ScanFunc ScanFunc

	// DiscoverFunc runs native discovery+spidering before master agent planning.
	// When set, the swarm runner executes discovery and feeds discovered records
	// into the master agent alongside the original inputs.
	DiscoverFunc func(ctx context.Context) error

	// SourceAnalysisCallback is called after source analysis completes to allow
	// the caller to process session config (e.g., convert to auth-config.yaml)
	// and extensions before the scan phase.
	SourceAnalysisCallback func(result *SourceAnalysisResult) error

	// BrowserAuthCallback is fired after the browser-based auth phase writes
	// an auth-config.yaml to the session dir. The CLI uses this to thread
	// the captured session into the discovery + scan funcs so the native
	// spider (and downstream scan) crawl post-login surface. Empty path =
	// auth phase ran but produced no config; the caller may treat that as
	// a soft failure.
	BrowserAuthCallback func(authConfigPath string) error

	// PhaseCallback is called when a swarm phase starts.
	PhaseCallback func(phase string)

	// Audit is the background-audit cfg slot — backed by either audit or
	// piolium per AuditHarness. Requires SourcePath to be non-empty. Field
	// name is legacy; the runtime is harness-agnostic.
	// Run budgets (--max-commands / --token-budget / --max-cost-usd): caps on
	// the cumulative tool calls, input+output tokens and estimated USD cost
	// across every agent call of the run (Engine.SetRunBudget). Zero = no cap.
	// Hitting one stops the run with SwarmResult.BudgetStop set and the
	// agentic_scans row at "budget_exhausted".
	MaxCommands int
	TokenBudget int64
	MaxCostUSD  float64

	// SkipPreflight skips the provider ping before the first phase
	// (--no-preflight). The ping's deadline is agent.olium.preflight_timeout.
	SkipPreflight bool

	Audit *config.AuditAgentConfig

	// AuditHarness selects which harness backs the Audit cfg. Zero-valued
	// defaults to audit for backward compat.
	AuditHarness HarnessSpec
}

// Prompt template constants for the agent swarm mode.
const (
	SwarmPromptPlan       = "agent-swarm-plan"
	SwarmPromptExtensions = "agent-swarm-extensions"
	SwarmPromptCodeAudit  = "swarm-code-audit"
	SwarmPromptTriage     = "agent-swarm-triage"
	SwarmPromptAuth       = "agent-swarm-auth"
)

// SwarmRunner orchestrates AI-guided targeted vulnerability scanning.
type SwarmRunner struct {
	engine *Engine
	repo   *database.Repository

	// skills is the full skill registry loaded once at the start of Run
	// (~/.vigolium/skills + project scopes + embedded). The plan phase sees
	// the full menu; the triage phase gets a planner-filtered subset. nil when
	// loading failed — phases then run without skills.
	skills *skill.Registry

	// extensionCache memoises successful runExtensionAgent results within
	// a process lifetime, keyed by a hash of (target + focus areas +
	// module tags). Keeps repeat planner runs on the same target — e.g.
	// rescan loops, batched fan-out, or two `vigolium agent swarm` calls
	// against the same site in one shell session — from re-invoking the
	// extension LLM round when the plan inputs haven't materially changed.
	extensionCache sync.Map // map[string]extensionCacheEntry
}

// extensionCacheEntry is a stored result from a successful extension-agent
// call. RawOutput is preserved so the merged plan's transcript stays
// faithful even on cache hits.
type extensionCacheEntry struct {
	Plan      *SwarmPlan
	RawOutput string
}

type swarmRecordStats struct {
	Initial   int
	Source    int
	Discovery int
}

// NewSwarmRunner creates a swarm runner.
func NewSwarmRunner(engine *Engine, repo *database.Repository) *SwarmRunner {
	return &SwarmRunner{
		engine: engine,
		repo:   repo,
	}
}

// selectTriageSkills computes the planner-filtered skill registry handed to
// the triage agent: the plan's recommended_skills unioned with the always-on
// set and any operator override (--skill / --skill-tag), or the full set under
// --no-skill-filter. Returns nil when no skills are loaded. Emits a one-line
// summary of the selection to stderr so the operator sees what triage will use.
func (s *SwarmRunner) selectTriageSkills(cfg SwarmConfig, result *SwarmResult) *skill.Registry {
	if s.skills == nil || s.skills.Len() == 0 {
		return nil
	}
	var picks []string
	if result != nil && result.SwarmPlan != nil {
		picks = result.SwarmPlan.RecommendedSkills
	}
	var alwaysOn []string
	if s.engine != nil && s.engine.settings != nil {
		alwaysOn = s.engine.settings.Agent.Olium.EffectiveAlwaysOnSkills()
	}
	sel, warnings := s.skills.Select(skill.SelectOptions{
		Picks:         picks,
		AlwaysOn:      alwaysOn,
		Forced:        cfg.SkillNames,
		ForcedTags:    cfg.SkillTags,
		DisableFilter: cfg.NoSkillFilter,
	})
	for _, w := range warnings {
		zap.L().Warn(w)
	}
	if len(warnings) > 0 {
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", SwarmPhaseTriage, fmt.Sprintf(
			"warning: skill selection warnings recorded: count=%d; see run details", len(warnings)))
	}
	if sel == nil || sel.Len() == 0 {
		return sel
	}
	fmt.Fprintf(os.Stderr, "[swarm] triage loading %d of %d skill(s): %s\n",
		sel.Len(), s.skills.Len(), strings.Join(sel.Names(), ", "))
	return sel
}

// persistPhase updates the agent run's current phase in the database.
func (s *SwarmRunner) persistPhase(ctx context.Context, agenticScan *database.AgenticScan) {
	if s.repo != nil {
		if err := s.repo.UpdateAgenticScan(ctx, agenticScan); err != nil {
			zap.L().Debug("Failed to persist phase update", zap.Error(err))
		}
	}
}

// probeConfig returns a ProbeConfig from the swarm's tuning parameters.
func (cfg *SwarmConfig) probeConfig() ProbeConfig {
	return ProbeConfig{
		Concurrency: cfg.ProbeConcurrency,
		Timeout:     cfg.ProbeTimeout,
		MaxBodySize: cfg.MaxProbeBodySize,
	}
}

// initializeSwarmRun is the swarm-local get-or-create/seed path. Unlike the
// generic partial updater, it validates stored identity before any pipeline
// writes. A transaction also covers creation collisions and native ownership,
// so a failed guard cannot leave a new parent or partially seed an existing one.
func (s *SwarmRunner) initializeSwarmRun(ctx context.Context, cfg *SwarmConfig, run *database.AgenticScan) error {
	if cfg.ProjectUUID == "" {
		cfg.ProjectUUID = database.DefaultProjectUUID
	}
	cfg.ProjectUUID = strings.Clone(cfg.ProjectUUID)
	cfg.ScanUUID = strings.Clone(cfg.ScanUUID)
	cfg.AgenticScanUUID = strings.Clone(cfg.AgenticScanUUID)
	run.UUID = strings.Clone(run.UUID)
	run.ProjectUUID = cfg.ProjectUUID
	cfg.AgenticScanUUID = run.UUID
	if s.repo == nil {
		if cfg.ScanUUID == "" {
			cfg.ScanUUID = uuid.NewString()
		}
		run.ScanUUID = cfg.ScanUUID
		return nil
	}
	return s.repo.DB().RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Match CreateAgenticScan's get-or-create contract, but keep subsequent
		// validation and seeding in the same transaction (including conflicts).
		if _, err := tx.NewInsert().Model(run).On("CONFLICT (uuid) DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("create agent run: %w", err)
		}
		existing := &database.AgenticScan{}
		q := tx.NewSelect().Model(existing).Where("uuid = ?", run.UUID)
		if s.repo.DB().Driver() == "postgres" {
			q = q.For("UPDATE")
		}
		if err := q.Scan(ctx); err != nil {
			return fmt.Errorf("read agent run: %w", err)
		}
		if existing.ProjectUUID != cfg.ProjectUUID {
			return fmt.Errorf("%w: swarm agent run belongs to another project", database.ErrScanProjectMismatch)
		}
		if existing.Mode != "swarm" {
			return fmt.Errorf("agent run UUID already belongs to another mode")
		}
		if existing.ScanUUID != "" {
			if cfg.ScanUUID != "" && cfg.ScanUUID != existing.ScanUUID {
				return fmt.Errorf("agent run UUID already references another native scan")
			}
			cfg.ScanUUID = existing.ScanUUID
		}
		if cfg.ScanUUID == "" {
			cfg.ScanUUID = uuid.NewString()
		}
		run.ScanUUID = cfg.ScanUUID

		child := &database.Scan{}
		childQuery := tx.NewSelect().Model(child).Column("uuid", "project_uuid", "agentic_scan_uuid").Where("uuid = ?", cfg.ScanUUID)
		if s.repo.DB().Driver() == "postgres" {
			childQuery = childQuery.For("UPDATE")
		}
		if err := childQuery.Scan(ctx); err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("read native scan: %w", err)
			}
		} else {
			if child.ProjectUUID != cfg.ProjectUUID {
				return fmt.Errorf("%w: swarm native scan belongs to another project", database.ErrScanProjectMismatch)
			}
			if child.AgenticScanUUID != "" && child.AgenticScanUUID != run.UUID {
				return fmt.Errorf("native scan UUID already belongs to another agent run")
			}
			// Claim only an unowned (or already matching) child. Later native
			// callbacks must never run against somebody else's nonempty parent.
			res, err := tx.NewUpdate().Model((*database.Scan)(nil)).Set("agentic_scan_uuid = ?", run.UUID).
				Where("uuid = ?", cfg.ScanUUID).Where("project_uuid = ?", cfg.ProjectUUID).
				Where("(agentic_scan_uuid IS NULL OR agentic_scan_uuid = '' OR agentic_scan_uuid = ?)", run.UUID).Exec(ctx)
			if err != nil {
				return fmt.Errorf("claim native scan: %w", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				return fmt.Errorf("native scan ownership changed during initialization")
			}
		}
		// Keep pre-created caller metadata, including a nested run's parent.
		// Carry immutable identity into subsequent phase/finalization writes.
		run.ParentAgenticScanUUID = existing.ParentAgenticScanUUID
		if !existing.StartedAt.IsZero() {
			run.StartedAt = existing.StartedAt
		}
		res, err := tx.NewUpdate().Model(run).OmitZero().
			ExcludeColumn("id", "uuid", "project_uuid", "parent_run_uuid", "created_at").
			Where("uuid = ?", run.UUID).Where("project_uuid = ?", cfg.ProjectUUID).
			Where("(scan_uuid IS NULL OR scan_uuid = '' OR scan_uuid = ?)", cfg.ScanUUID).Exec(ctx)
		if err != nil {
			return fmt.Errorf("seed agent run: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("agent run identity changed during initialization")
		}
		return nil
	})
}

// Run executes the full agent swarm pipeline.
func (s *SwarmRunner) Run(ctx context.Context, cfg SwarmConfig) (*SwarmResult, error) {
	start := time.Now()
	// Snapshot caller-owned identities before any run state or phase callback
	// retains them. Initialization repeats this at its own direct-call boundary.
	cfg.ProjectUUID = strings.Clone(cfg.ProjectUUID)
	cfg.ScanUUID = strings.Clone(cfg.ScanUUID)
	cfg.AgenticScanUUID = strings.Clone(cfg.AgenticScanUUID)
	cfg.StreamWriter = NewSynchronizedWriter(cfg.StreamWriter)

	// Set up context cache for DB enrichment across phases. ttl=0 means
	// entries live for the full run; we explicitly InvalidateContextCache
	// after phases that mutate findings/records (native scan, rescan), which
	// is the only real staleness window. A short TTL would just guarantee
	// misses on a multi-minute swarm.
	if s.engine != nil {
		s.engine.SetContextCache(agentprompt.NewContextCache(0))
	}

	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 3
	}
	// Resolve tuning defaults
	if cfg.MasterBatchSize <= 0 {
		cfg.MasterBatchSize = 5
	}
	// Resolve agent name to default if empty — ensures the DB record has the effective name
	if cfg.AgentName == "" && s.engine != nil && s.engine.settings != nil {
		cfg.AgentName = s.engine.settings.Agent.DefaultAgent
	}

	// Load the skill registry once for the whole run. The plan phase sees the
	// full menu and selects a subset (plan.recommended_skills); the triage
	// phase loads the planner-selected subset plus the always-on set. includeUser
	// surfaces ~/.vigolium/skills/. Loading is best-effort — a failure just runs
	// the phases without skills.
	s.skills, _ = olium.LoadSkillsFor(true)
	if s.skills != nil && s.skills.Len() > 0 {
		fmt.Fprintf(os.Stderr, "[swarm] %d skills available (planner selects a subset for triage)\n", s.skills.Len())
	}
	var protocol, model string
	if s.engine != nil && s.engine.settings != nil {
		protocol, model = s.engine.settings.Agent.BackendMeta()
	}
	// Create agent run record — use pre-assigned UUID if provided (e.g. from CLI session dir)
	agenticScanUUID := cfg.AgenticScanUUID
	if agenticScanUUID == "" {
		agenticScanUUID = uuid.New().String()
	}
	// Initialization resolves the native UUID from the stored run on resume,
	// or generates a fresh one, before any native/agent callbacks can write.
	agenticScan := &database.AgenticScan{
		UUID:        agenticScanUUID,
		ProjectUUID: cfg.ProjectUUID,
		ScanUUID:    cfg.ScanUUID,
		Mode:        "swarm",
		AgentName:   cfg.AgentName,
		Protocol:    protocol,
		Model:       model,
		VulnType:    cfg.VulnType,
		ModuleNames: cfg.ModuleNames,
		SourcePath:  cfg.SourcePath,
		SourceType:  database.InferSourceType(cfg.SourcePath),
		SessionDir:  cfg.SessionDir,
		Status:      "running",
		StartedAt:   start,
	}
	if len(cfg.Inputs) > 0 {
		agenticScan.InputRaw = cfg.Inputs[0]
	}

	result := &SwarmResult{AgenticScanUUID: agenticScanUUID}
	if err := s.initializeSwarmRun(ctx, &cfg, agenticScan); err != nil {
		// Do not finalize an unvalidated UUID: even terminal persistence or
		// attribution would be a write against a run we do not own.
		return result, fmt.Errorf("swarm initialization failed: %w", err)
	}

	_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", "run", "run started: "+agenticScanUUID)

	// Run budget: the engine charges every agent call; the first cap crossed
	// cancels the run with a *BudgetExhaustedError cause.
	budget := RunBudget{MaxCommands: cfg.MaxCommands, TokenBudget: cfg.TokenBudget, MaxCostUSD: cfg.MaxCostUSD, Model: model}
	if s.engine != nil && budget.Active() {
		var cancelBudget context.CancelCauseFunc
		ctx, cancelBudget = context.WithCancelCause(ctx)
		defer cancelBudget(nil)
		s.engine.SetRunBudget(budget, func(b *BudgetExhaustedError) {
			fmt.Fprintf(os.Stderr, "[swarm] %s — stopping\n", b.Reason)
			cancelBudget(b)
		})
	}

	// Fail fast on a broken olium provider so callers don't pay for
	// normalize + discovery before the very first LLM call dies on a
	// missing credential. Mirrors autopilot's RunAutonomous preflight.
	var err error
	if s.engine != nil && !cfg.SkipPreflight {
		if perr := s.engine.Preflight(ctx); perr != nil {
			err = fmt.Errorf("swarm preflight failed: %w", perr)
		}
	}

	// Execute phases (skipped on preflight failure)
	if err == nil {
		err = s.runSwarmPipeline(ctx, cfg, agenticScan, result)
	}

	return s.finishRun(ctx, cfg, agenticScan, result, start, err)
}

func (s *SwarmRunner) finishRun(ctx context.Context, cfg SwarmConfig, agenticScan *database.AgenticScan, result *SwarmResult, start time.Time, err error) (*SwarmResult, error) {
	// Finalization must survive the run's cancellation/deadline. Logging below
	// only observes the context; it never changes err or the existing status rules.
	// This is the common exit path, including discovery/planner failures and
	// cancellations that bypass finalizeSwarmStep. Preserve the original error
	// and status while reconciling whatever findings were actually persisted.
	if s.repo != nil || (agenticScan.UUID != "" && (cfg.ScanFunc != nil || cfg.DiscoverFunc != nil)) {
		ps := &swarmPipelineState{runner: s, cfg: cfg, agenticScan: agenticScan, result: result}
		ps.attributeRunFindings(ctx)
		result.TotalFindings, result.SeverityCounts = ps.runFindingCounts(ctx)
	}
	// Reconciliation has its own bounded detached calls. Give terminal status
	// persistence a fresh budget so a slow attribution/count cannot starve it.
	finalizeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	result.Duration = time.Since(start)
	now := time.Now()
	agenticScan.CompletedAt = now
	agenticScan.DurationMs = result.Duration.Milliseconds()
	agenticScan.FindingCount = result.TotalFindings

	// Pull cumulative token usage from the engine accumulator. Every
	// Engine.Run call during the pipeline (plan, source-analysis sub-agents,
	// triage, code-audit, repair) contributes here.
	if s.engine != nil {
		result.TokenUsage = s.engine.TokenUsage()
	}
	usage := claudecost.Usage{
		InputTokens:  int64(result.TokenUsage.InputTokens),
		OutputTokens: int64(result.TokenUsage.OutputTokens),
	}
	agenticScan.TotalInputTokens = usage.InputTokens
	agenticScan.TotalOutputTokens = usage.OutputTokens
	agenticScan.EstimatedCostUSD = usage.Price(agenticScan.Model)
	// Mirror the totals into the JSONB column so the existing per-phase
	// renderer in `vigolium agent session` surfaces them. Real per-phase
	// breakdown would require snapshotting the engine accumulator before
	// and after each pipeline phase — out of scope here; one rollup entry
	// is enough to keep operators from seeing an empty Token Usage block.
	if usage.InputTokens > 0 || usage.OutputTokens > 0 {
		agenticScan.TokenUsage = map[string]interface{}{
			"swarm": map[string]interface{}{
				"input_tokens":  usage.InputTokens,
				"output_tokens": usage.OutputTokens,
			},
		}
	}

	var budgetErr *BudgetExhaustedError
	if s.engine != nil {
		budgetErr = s.engine.BudgetExhausted()
	}
	if budgetErr != nil {
		result.BudgetStop = budgetErr.Stop
	}
	end := database.AgenticRunEnd{
		Err:             err,
		TimedOut:        err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded),
		BudgetExhausted: budgetErr != nil,
		Cancelled:       err != nil && budgetErr == nil && errors.Is(ctx.Err(), context.Canceled),
		Degraded:        result.Degraded,
	}
	result.TimedOut = end.TimedOut
	agenticScan.Status = database.AgenticRunStatus(end)
	switch {
	case budgetErr != nil:
		agenticScan.ErrorMessage = budgetErr.Reason
	case err != nil:
		agenticScan.ErrorMessage = err.Error()
	case result.Degraded:
		agenticScan.ErrorMessage = strings.Join(result.Warnings, "\n")
	}

	if s.repo != nil {
		projectUUID := agenticScan.ProjectUUID
		if projectUUID == "" {
			projectUUID = database.DefaultProjectUUID
		}
		// Finalization must not reassign a stored run from another project.
		updateResult, updateErr := s.repo.DB().NewUpdate().Model(agenticScan).OmitZero().
			Where("uuid = ?", agenticScan.UUID).Where("project_uuid = ?", projectUUID).Exec(finalizeCtx)
		if updateErr != nil {
			zap.L().Warn("Failed to update agent run record", zap.Error(updateErr))
		} else if n, _ := updateResult.RowsAffected(); n != 1 {
			zap.L().Warn("Agent run finalization refused: missing row or different project", zap.String("agentic_scan_uuid", agenticScan.UUID))
		} else if result.TotalFindings == 0 {
			// UpdateAgenticScan omits zero fields. Explicitly persist a known zero
			// rather than retaining a previous count from a resumed run.
			if _, updateErr := s.repo.DB().NewUpdate().Model((*database.AgenticScan)(nil)).
				Set("finding_count = 0").Where("uuid = ?", agenticScan.UUID).
				Where("project_uuid = ?", projectUUID).Exec(finalizeCtx); updateErr != nil {
				zap.L().Warn("Failed to persist empty agent finding count", zap.Error(updateErr))
			}
		}
	}

	// Free-form warnings/errors can contain credentials or complete target URLs.
	// Keep originals in result/DB, but log only safe categories and counts here.
	if result.TotalFindings < 0 {
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", "run", "warning: persisted finding count unavailable; findings=-1 means unknown")
	}
	if len(result.Warnings) > 0 {
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", "run", fmt.Sprintf(
			"warning: warnings recorded: count=%d; see run details", len(result.Warnings)))
	}
	phase := agenticScan.CurrentPhase
	if phase == "" {
		phase = "run" // preflight failure or cancellation before the first phase
	}
	if budgetErr != nil {
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", phase, "error: budget exhausted; see run details")
	} else if err != nil {
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", phase, "error: error recorded; see run details")
	}
	// Observe cancellation even if a non-fatal callback swallowed it, without
	// changing the returned error, persisted status or which phases execute.
	switch ctx.Err() {
	case context.Canceled:
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", "run", "context cancellation observed at run finish")
	case context.DeadlineExceeded:
		_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", "run", "context deadline observed at run finish")
	}
	_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", "run", fmt.Sprintf(
		"run finished: status=%s duration=%s records=%d findings=%d confirmed=%d false_positives=%d iterations=%d warnings=%d",
		agenticScan.Status, result.Duration.Round(time.Millisecond), result.TotalRecords, result.TotalFindings,
		result.Confirmed, result.FalsePositives, result.Iterations, len(result.Warnings)))
	if err != nil {
		return result, err
	}
	return result, nil
}

func (s *SwarmRunner) emitPhase(cfg SwarmConfig, phase string) {
	_ = WriteRuntimeProgress(cfg.StreamWriter, "swarm", phase, "phase started: "+phase)
	s.emitPhaseConsole(cfg, phase)
}

// emitPhaseConsole preserves the CLI callback/console behavior when a phase
// already logged its start before preparing work (e.g. extension validation).
func (s *SwarmRunner) emitPhaseConsole(cfg SwarmConfig, phase string) {
	if cfg.PhaseCallback != nil {
		cfg.PhaseCallback(phase)
	}
	printPhaseLine(phase, fmt.Sprintf("phase started: %s", phase))
}

func (s *SwarmRunner) addWarning(result *SwarmResult, format string, args ...interface{}) {
	if result == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	result.Degraded = true
	result.Warnings = append(result.Warnings, msg)
}

func (s *SwarmRunner) currentMaxFindingID(ctx context.Context, projectUUID string) int64 {
	if s.repo == nil || projectUUID == "" {
		return 0
	}
	var maxID int64
	if err := s.repo.DB().NewSelect().
		Model((*database.Finding)(nil)).
		ColumnExpr("COALESCE(MAX(id), 0)").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &maxID); err != nil {
		zap.L().Debug("Failed to query max finding id", zap.Error(err))
		return 0
	}
	return maxID
}

func (s *SwarmRunner) writeSwarmCheckpoint(sessionDir string, projectUUID string, completedPhases []string, targetURL string, recordCount int, plan *SwarmPlan, extensionDir string, triageRound int, extensionRenames map[string]string, result *SwarmResult, stats swarmRecordStats) error {
	cp := &SwarmCheckpoint{
		CompletedPhases:  append([]string(nil), completedPhases...),
		TargetURL:        targetURL,
		RecordCount:      recordCount,
		Plan:             plan,
		ExtensionDir:     extensionDir,
		Timestamp:        time.Now(),
		TriageRound:      triageRound,
		ExtensionRenames: extensionRenames,
		InitialRecords:   stats.Initial,
		SourceRecords:    stats.Source,
		DiscoveryRecords: stats.Discovery,
	}
	if result != nil {
		cp.LastFindingID = s.currentMaxFindingID(context.Background(), projectUUID)
		cp.Warnings = append(cp.Warnings, result.Warnings...)
	}
	return writeCheckpoint(sessionDir, cp)
}

// phaseCompleted returns true if the given phase is in the checkpoint's completed list.
// It normalizes legacy phase names for backward compatibility with old checkpoints.
func phaseCompleted(cp *SwarmCheckpoint, phase string) bool {
	if cp == nil {
		return false
	}
	normalized := NormalizeSwarmPhase(phase)
	for _, p := range cp.CompletedPhases {
		if NormalizeSwarmPhase(p) == normalized {
			return true
		}
	}
	return false
}
