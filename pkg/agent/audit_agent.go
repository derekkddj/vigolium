package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/audit"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/audit/stream"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/picost"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
	"github.com/vigolium/vigolium/pkg/procutil"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// cancelGracePeriod is how long Cancel waits for SIGTERM before escalating to SIGKILL.
const cancelGracePeriod = 10 * time.Second

// PlatformPi is the Pi runtime platform — runs piolium via `pi --mode json`.
const PlatformPi = "pi"

// PlatformAuditBin identifies the embedded vigolium-audit binary as the
// audit runner. vigolium-audit dispatches to claude or codex internally; the
// per-run agent comes from AuditAgentConfig.AuditDriverInvocation.
const PlatformAuditBin = "audit"

// DefaultAuditHarness returns the canonical audit harness spec used by
// `vigolium agent audit` and the autopilot/swarm background audit. The zero
// value of AuditAgentConfig.Harness is treated as this for backward compat.
func DefaultAuditHarness() HarnessSpec {
	return HarnessSpec{
		Name:            audit.HarnessName,
		SourceFolder:    "vigolium-results",
		SessionSubdir:   "vigolium-results",
		EnvPrefix:       "VIGOLIUM_AUDIT_",
		DBMode:          audit.HarnessName,
		DBAgentName:     "vigolium-audit",
		DBInputType:     audit.HarnessName,
		FindingIDPrefix: audit.HarnessName,
		FindingTag:      audit.HarnessName,
	}
}

// effectiveHarness returns the configured harness or the audit default.
func effectiveHarness(cfg AuditAgentConfig) HarnessSpec {
	if cfg.Harness.Name == "" {
		return DefaultAuditHarness()
	}
	return cfg.Harness
}

// harnessFindingSource projects the DB-tagging fields of a HarnessSpec onto
// the audit parser's FindingSource shape. Used wherever findings parsed
// from `<harness.SessionSubdir>/findings/` need to land in the database
// tagged with the right harness's mode/agent_name/tag set.
func harnessFindingSource(h HarnessSpec) audit.FindingSource {
	return audit.FindingSource{
		Mode:      h.DBMode,
		AgentName: h.DBAgentName,
		InputType: h.DBInputType,
		IDPrefix:  h.FindingIDPrefix,
		Tag:       h.FindingTag,
	}
}

// harness returns the resolved harness spec, populating the cache on first
// call. Used instead of effectiveHarness(r.cfg) so the resolution runs once
// per runner. Tolerates direct-literal AuditAgenticScanner construction
// (some tests skip NewAuditAgenticScanner).
func (r *AuditAgenticScanner) harness() HarnessSpec {
	if r.resolvedSpec.Name == "" {
		r.resolvedSpec = effectiveHarness(r.cfg)
	}
	return r.resolvedSpec
}

// auditProtocolForPlatform maps the platform onto the AgenticScan
// protocol vocabulary stored on the DB row.
func auditProtocolForPlatform(platform string) string {
	switch platform {
	case PlatformPi:
		return "pi-sdk"
	case PlatformAuditBin, "":
		return "audit-bin"
	default:
		return ""
	}
}

// ownerRepoRE matches a single owner/repo segment, e.g. "vigolium/vigolium-audit".
// Used by normalizeOwnerRepo to validate the candidate before returning it.
var ownerRepoRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// AuditAgenticScanner manages an vigolium-audit running as a background agent process.
// It launches the agent (Claude or Codex), periodically syncs audit-state.json
// and findings to the vigolium session dir, and imports findings into the database when complete.
type AuditAgenticScanner struct {
	cfg          AuditAgentConfig
	resolvedSpec HarnessSpec // cached harness spec; populated lazily by harness()
	repo         *database.Repository

	agenticScanUUID string // UUID of the child AgenticScan record tracking this audit

	mu             sync.Mutex
	cmd            *exec.Cmd
	done           chan struct{}
	err            error
	processErr     error
	evidenceErr    error
	terminalStatus string
	cancelled      bool
	startedAt      time.Time // wall time the agent subprocess was launched

	// syncMu serializes periodic writes with the final archive. Once finalizing
	// begins, no tick may overwrite the verified archive or regress DB status.
	syncMu        sync.Mutex
	syncFinalized bool
	archiveDir    string            // populated only after a complete, verified archive
	lastStateHash string            // advances only after successful disk and DB writes
	syncedFiles   map[string]string // filename → content hash, including same-size edits

	// Populated by importFindings after monitor() completes.
	findingStats FindingStats

	// Populated by finalizeAgenticScan from the harness's NDJSON output
	// (audit `result` event for audit, picost transcripts for piolium).
	// Zero-valued when the harness did not produce a usable summary.
	costSummary ScanCost

	// auditResult captures the final `result` event observed on the
	// audit NDJSON stream. Populated by the streaming goroutine in
	// Start() and read by computeCostSummary after monitor() drains the
	// pipe. Zero-valued for piolium runs.
	auditResult stream.Result

	// streamDone is closed by the streaming goroutine when it has
	// finished consuming the subprocess's stdout. monitor() waits on
	// this before computing cost / fallback output, so the captured
	// result is observable.
	streamDone chan struct{}

	// byokCleanup is set by Start() when a piolium codex BYOK run staged
	// auth.json into PI_CODING_AGENT_DIR. monitor() invokes it after the
	// subprocess exits to remove the staged file, restore the backup (if
	// any), and release the per-dir lock. Nil when no staging happened.
	byokCleanup func()
}

// FindingStats summarises the audit findings imported by a single audit run.
type FindingStats struct {
	Parsed     int            // total findings parsed from the session dir
	Saved      int            // findings successfully persisted to the database
	BySeverity map[string]int // count by normalized severity (critical/high/medium/low/info)

	// Reported is the count reported by the audit binary's own NDJSON
	// `result` event. It is only consulted when the on-disk findings tree
	// could not be parsed (Parsed == 0) and serves as a display-only
	// fallback so the CLI summary mirrors the streamer's `[result]` line
	// even when persistence didn't run. Severity keys are normalized to
	// lowercase to match BySeverity.
	Reported           int
	ReportedBySeverity map[string]int
}

// SeverityBreakdownString renders a colored "critical:N  high:N  ..." string in
// descending severity order. Buckets with zero count are skipped. Falls back to
// the audit-reported breakdown when the on-disk parse yielded nothing. Returns
// "" when no findings were counted at all.
func (s FindingStats) SeverityBreakdownString() string {
	src := s.BySeverity
	if len(src) == 0 || s.Parsed == 0 {
		if len(s.ReportedBySeverity) > 0 {
			src = s.ReportedBySeverity
		}
	}
	order := []struct {
		name  string
		color func(string) string
	}{
		{"critical", terminal.Red},
		{"high", terminal.Orange},
		{"medium", terminal.Yellow},
		{"low", terminal.Cyan},
		{"info", terminal.Gray},
	}
	var parts []string
	for _, b := range order {
		if n := src[b.name]; n > 0 {
			parts = append(parts, b.color(fmt.Sprintf("%s:%d", b.name, n)))
		}
	}
	return strings.Join(parts, "  ")
}

// NewAuditAgenticScanner creates a new runner for the background vigolium-audit.
//
// The AgenticScan DB row's UUID is derived as follows:
//
//   - Standalone audit (ParentAgenticScanUUID empty, SessionDir set): UUID is
//     filepath.Base(cfg.SessionDir). This gives the invariant that
//     `vigolium log <uuid>` and `vigolium log ls` resolve the session's
//     runtime.log via the conventional `{sessions_dir}/{uuid}/` path.
//   - Nested audit (ParentAgenticScanUUID set, e.g. spawned by autopilot/swarm):
//     a fresh UUID is generated. The parent already owns a row at
//     filepath.Base(SessionDir), so the child must differ to avoid a
//     primary-key collision on create. Resolution back to runtime.log
//     relies on the child row's persisted SessionDir column instead.
//   - No SessionDir: a fresh UUID is generated.
func NewAuditAgenticScanner(cfg AuditAgentConfig, repo *database.Repository) *AuditAgenticScanner {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 30 * time.Second
	}
	return &AuditAgenticScanner{
		cfg:             cfg,
		resolvedSpec:    effectiveHarness(cfg),
		repo:            repo,
		agenticScanUUID: deriveAuditScanUUID(cfg),
		done:            make(chan struct{}),
		syncedFiles:     make(map[string]string),
	}
}

// Start launches the audit harness (vigolium-audit binary or piolium via `pi`)
// as a background process. The harness selection drives binary
// resolution, argv construction, and stream decoding.
//
// On any failure path AFTER BYOK staging has run (codex auth.json copy)
// but BEFORE cmd.Start() succeeds, the staged file must be cleaned up
// here — monitor() never runs in that case. Past that point, monitor's
// deferred cleanup owns the restore.
func (r *AuditAgenticScanner) Start(ctx context.Context) error {
	platform := r.cfg.Platform

	// startSucceeded gates whether the deferred BYOK cleanup ownership
	// transfers to monitor (true) or fires here (false). r.byokCleanup is
	// nil-checked inside the defer to keep the no-BYOK path cheap.
	startSucceeded := false
	defer func() {
		if !startSucceeded && r.byokCleanup != nil {
			r.byokCleanup()
			r.byokCleanup = nil
		}
	}()

	// Validate source path up front. The subprocess inherits cmd.Dir =
	// SourcePath; if the directory doesn't exist, the kernel's chdir fails and
	// Go reports `fork/exec <binary>: no such file or directory` — pointing at
	// the binary instead of the cwd. Fail here with a clear message instead.
	if r.cfg.SourcePath == "" {
		return fmt.Errorf("audit source path is empty")
	}
	if info, err := os.Stat(r.cfg.SourcePath); err != nil {
		return fmt.Errorf("audit source path %q is not accessible: %w", r.cfg.SourcePath, err)
	} else if !info.IsDir() {
		return fmt.Errorf("audit source path %q is not a directory", r.cfg.SourcePath)
	}

	harness := r.harness()
	isAudit := harness.Name == audit.HarnessName
	if isAudit {
		platform = PlatformAuditBin
	}

	// Audit always runs with --json so the streaming goroutine can
	// extract the result event for cost reporting; piolium opts in via
	// cfg.StreamDecoder + StreamWriter.
	streamJSON := isAudit || (r.cfg.Stream && r.cfg.StreamWriter != nil && r.cfg.StreamDecoder != nil)

	binary, args, stdinPrompt, err := buildAuditAgentCommand(platform, r.cfg, streamJSON)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = r.cfg.SourcePath
	procutil.SetupProcessGroup(cmd) // own process group so the whole harness tree can be torn down
	// harnessEnv carries the vigolium-injected vars (PIOLIUM_REPOSITORY,
	// PIOLIUM_GIT_AVAILABLE, PIOLIUM_SESSION_UUID, optional commit-scan
	// knobs, and the audit-equivalent under ARCHON_*). Captured rather
	// than appended inline so the debug line can render them.
	harnessEnv := auditEnvFor(harness.EnvPrefix, r.cfg.SourcePath, r.agenticScanUUID, r.cfg.CommitScanLimit, r.cfg.CommitScanSince)
	cmd.Env = append(os.Environ(), harnessEnv...)
	// pioliumExtraEnv is the piolium-only runtime injection
	// (PI_CODING_AGENT_DIR) — distinct from harnessEnv since it's
	// opt-in via $PIOLIUM_HOME / the /opt/piolium auto-probe and
	// reads as nil otherwise.
	var pioliumExtraEnv []string
	// pioliumAuthEnv is the BYOK env-var bundle (api-key / oauth-token)
	// derived from r.cfg.AuthOverride. Tracked separately from
	// pioliumExtraEnv so we can redact its values in logs without
	// stripping the harmless PI_CODING_AGENT_DIR line.
	var pioliumAuthEnv []string
	// "" when no $PIOLIUM_HOME and no /opt/piolium probe hit. Resolved
	// once here and reused for both BYOK staging (codex auth.json) and
	// the debug-line render below — AgentDir() probes the filesystem.
	pioliumAgentDir := piolium.AgentDir()
	if harness.Name == piolium.HarnessName {
		pioliumExtraEnv = piolium.RuntimeEnv()
		cmd.Env = append(cmd.Env, pioliumExtraEnv...)
		// Pre-create the per-scan pi-session subdir so pi doesn't have
		// to. Best-effort — if it fails, pi will surface a more
		// specific error than "no such directory".
		if r.cfg.SessionDir != "" {
			_ = os.MkdirAll(filepath.Join(r.cfg.SessionDir, "pi-session"), 0o755)
		}

		if err := r.applyPioliumBYOK(cmd, &pioliumAuthEnv, pioliumAgentDir); err != nil {
			return err
		}
	}

	// Build readable command line for console output. Piolium runtime
	// env vars are prepended in shell form so a debug reader can tell
	// whether $PIOLIUM_HOME-driven injection actually fired this run.
	var cmdLine strings.Builder
	for _, env := range pioliumExtraEnv {
		cmdLine.WriteString(env)
		cmdLine.WriteByte(' ')
	}
	cmdLine.WriteString(binary)
	for _, a := range args {
		cmdLine.WriteByte(' ')
		if strings.ContainsAny(a, " \t\n'\"\\") {
			cmdLine.WriteString("'" + strings.ReplaceAll(a, "'", "'\\''") + "'")
		} else {
			cmdLine.WriteString(a)
		}
	}
	// Combine harness vars (always present), piolium runtime vars (often
	// nil), and BYOK auth env (only set when an override fired) into one
	// slice so the operator sees the full set vigolium injected on top
	// of the inherited shell env. Secret values are redacted before logging
	// — the live cmd.Env still has the real values, this is log-only.
	injectedEnv := append([]string(nil), harnessEnv...)
	injectedEnv = append(injectedEnv, pioliumExtraEnv...)
	injectedEnv = append(injectedEnv, pioliumAuthEnv...)
	zap.L().Debug("starting background audit",
		zap.String("cmd", redactAuditDriverCmdLine(cmdLine.String())),
		zap.String("platform", platform),
		zap.String("harness", harness.Name),
		zap.String("mode", r.cfg.Mode),
		zap.String("source", r.cfg.SourcePath),
		zap.String("piolium_agent_dir", pioliumAgentDir),
		zap.Strings("injected_env", redactEnvSlice(injectedEnv)))
	if stdinPrompt != "" {
		cmd.Stdin = strings.NewReader(stdinPrompt)
	}

	var outputBuf syncBuffer
	var streamPipe io.ReadCloser
	var streamRawLog *os.File

	if streamJSON {
		// NDJSON harnesses (audit-bin always, piolium when its
		// StreamDecoder is wired in): decode via the per-harness
		// streamer, tee raw JSONL to the session dir, and still
		// capture into outputBuf for the fallback-output path in
		// monitor().
		pipe, pipeErr := cmd.StdoutPipe()
		if pipeErr != nil {
			return fmt.Errorf("stdout pipe: %w", pipeErr)
		}
		streamPipe = pipe

		if r.cfg.SessionDir != "" {
			rawPath := filepath.Join(r.cfg.SessionDir, "audit-stream.jsonl")
			_ = os.MkdirAll(filepath.Dir(rawPath), 0o755)
			if f, err := os.OpenFile(rawPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				streamRawLog = f
			} else {
				zap.L().Debug("Failed to open audit-stream.jsonl", zap.Error(err))
			}
		}
	} else if r.cfg.StreamWriter != nil {
		cmd.Stdout = io.MultiWriter(&outputBuf, r.cfg.StreamWriter)
	} else {
		cmd.Stdout = &outputBuf
	}
	// Tee stderr to StreamWriter too — non-Claude backends often surface
	// warnings/errors only on stderr, and we want them in runtime.log
	// for later replay.
	if r.cfg.StreamWriter != nil {
		cmd.Stderr = io.MultiWriter(&outputBuf, r.cfg.StreamWriter)
	} else {
		cmd.Stderr = &outputBuf
	}

	if err := cmd.Start(); err != nil {
		if streamRawLog != nil {
			_ = streamRawLog.Close()
		}
		return fmt.Errorf("failed to start audit (harness=%s binary=%s cwd=%s): %w", harness.Name, binary, cmd.Dir, err)
	}

	r.mu.Lock()
	r.cmd = cmd
	r.startedAt = time.Now()
	r.streamDone = make(chan struct{})
	r.mu.Unlock()

	if streamJSON {
		go func() {
			defer close(r.streamDone)
			defer func() {
				if streamRawLog != nil {
					_ = streamRawLog.Close()
				}
			}()
			// When streamRawLog is open, the on-disk audit-stream.jsonl
			// is the canonical replay artifact — don't also accumulate
			// the full NDJSON in outputBuf. The buffer's only consumer
			// is the early-exit fallback in monitor(), which fires when
			// no output reached either sink (collectFallbackOutput then
			// reconstructs from synced findings).
			var rawWriter io.Writer = &outputBuf
			if streamRawLog != nil {
				rawWriter = streamRawLog
			}
			renderTo := r.cfg.StreamWriter
			if renderTo == nil {
				renderTo = io.Discard
			}
			if isAudit {
				res, err := stream.Stream(streamPipe, renderTo, stream.Options{
					RawLog:       rawWriter,
					ShowThinking: r.cfg.ShowThinking,
				})
				if err != nil {
					zap.L().Debug("audit stream decoder exited with error", zap.Error(err))
				}
				r.mu.Lock()
				r.auditResult = res
				r.mu.Unlock()
				return
			}
			if r.cfg.StreamDecoder != nil {
				if err := r.cfg.StreamDecoder(streamPipe, renderTo, rawWriter); err != nil {
					zap.L().Debug("audit stream decoder exited with error", zap.Error(err))
				}
			}
		}()
	} else {
		// No streaming goroutine — close streamDone immediately so
		// monitor() doesn't block waiting for it.
		close(r.streamDone)
	}

	// Create child AgenticScan record
	r.createAgenticScan(ctx)

	go r.monitor(ctx, cmd, &outputBuf)
	go r.syncLoop(ctx)

	// Past this point monitor() owns the BYOK cleanup. Flip the gate so
	// the deferred-on-failure handler at the top of Start() doesn't fire.
	startSucceeded = true
	return nil
}

// newAuditAgenticScanRow builds the initial "running" AgenticScan row for
// an audit run. Shared by the single-subprocess scanner and the piolium
// chain scanner so the row shape stays in lockstep.
func newAuditAgenticScanRow(cfg AuditAgentConfig, harness HarnessSpec, scanUUID string, startedAt time.Time) *database.AgenticScan {
	return &database.AgenticScan{
		UUID:                  scanUUID,
		ProjectUUID:           cfg.ProjectUUID,
		ScanUUID:              cfg.ScanUUID,
		Mode:                  harness.DBMode,
		AgentName:             harness.DBAgentName,
		Protocol:              auditProtocolForPlatform(cfg.Platform),
		InputType:             harness.DBInputType,
		Status:                "running",
		CurrentPhase:          "initializing",
		SourcePath:            cfg.SourcePath,
		SessionDir:            cfg.SessionDir,
		ParentAgenticScanUUID: cfg.ParentAgenticScanUUID,
		StartedAt:             startedAt,
	}
}

// applyAuditTerminalStatus resolves an audit run's final Status from its
// process error and cancellation state. Shared by every audit finalizer
// so "completed / cancelled / failed" is decided in one place.
func applyAuditTerminalStatus(run *database.AgenticScan, runErr error, cancelled bool) {
	switch {
	case runErr == nil:
		run.Status = "completed"
	case cancelled:
		run.Status = "cancelled"
	default:
		run.Status = "failed"
		run.ErrorMessage = runErr.Error()
	}
}

func (r *AuditAgenticScanner) createAgenticScan(ctx context.Context) {
	if r.repo == nil || r.cfg.SuppressAgenticScanRow {
		return
	}
	run := newAuditAgenticScanRow(r.cfg, r.harness(), r.agenticScanUUID, time.Now())
	if err := r.repo.CreateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("Failed to create audit AgenticScan", zap.Error(err))
	}
}

func (r *AuditAgenticScanner) monitor(ctx context.Context, cmd *exec.Cmd, output *syncBuffer) {
	defer close(r.done)

	// BYOK cleanup (currently: piolium codex auth.json restore + lock
	// release). Runs as the very last thing in monitor so that a panic /
	// early-return in any later step still triggers it.
	if r.byokCleanup != nil {
		defer r.byokCleanup()
	}

	err := cmd.Wait()
	// Capture execution cancellation before detaching finalization. A clean exit
	// still wins if cancellation arrived after the process had already finished.
	executionCancelled := err != nil && ctx.Err() != nil

	// Drain the streaming goroutine (if any) before reading captured
	// state — auditResult and the raw outputBuf both depend on the
	// stdout pipe being fully consumed.
	r.mu.Lock()
	streamDone := r.streamDone
	r.mu.Unlock()
	if streamDone != nil {
		<-streamDone
	}

	r.mu.Lock()
	r.err = err
	r.processErr = err
	r.cancelled = r.cancelled || executionCancelled
	cancelled := r.cancelled
	r.mu.Unlock()

	harnessName := r.harness().Name
	if err != nil {
		if cancelled {
			zap.L().Info("Audit cancelled", zap.String("harness", harnessName))
		} else {
			zap.L().Warn("Audit process exited with error",
				zap.String("harness", harnessName),
				zap.Error(err))
		}
	} else {
		zap.L().Info("Audit completed successfully", zap.String("harness", harnessName))
	}

	// Finalize on a detached, bounded context. On cancellation the execution ctx
	// is already done, which would fail the finding import and the terminal status
	// update — dropping findings and leaving the run stuck at "running" exactly
	// when it was cancelled. WithoutCancel keeps values but not the cancellation,
	// so finalization is attempted independently (the "cancelled" vs "failed"
	// distinction is preserved via r.cancelled in finalizeAgenticScan).
	finalizeCtx, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancelFinalize()

	// Only a complete, verified archive permits source removal. Failed archive
	// (including absent SessionDir) imports the authoritative source, not a
	// possibly partial incremental copy, and leaves that source intact.
	evidenceErr := r.archiveAndImport(finalizeCtx)
	harness := r.harness()
	if evidenceErr != nil {
		zap.L().Warn("Audit evidence finalization incomplete", zap.Error(evidenceErr))
		r.mu.Lock()
		r.err = errors.Join(err, evidenceErr)
		r.mu.Unlock()
	}

	// Save raw output
	if r.cfg.SessionDir != "" {
		outputPath := filepath.Join(r.cfg.SessionDir, harness.Name+"-audit-output.md")
		rawOutput := output.Bytes()

		// If stdout buffer is empty (process killed before --print flushed),
		// fall back to guarded reads from the verified archive/source authority.
		if len(rawOutput) == 0 {
			var fallbackErr error
			rawOutput, fallbackErr = r.collectFallbackOutputContext(finalizeCtx)
			evidenceErr = errors.Join(evidenceErr, fallbackErr)
		}

		if len(rawOutput) > 0 {
			if writeErr := writeAuditArtifact(outputPath, rawOutput); writeErr != nil {
				zap.L().Warn("Failed to save audit output", zap.Error(writeErr))
				evidenceErr = errors.Join(evidenceErr, writeErr)
				r.mu.Lock()
				r.err = errors.Join(err, evidenceErr)
				r.mu.Unlock()
			}
		}
	}

	// The archive budget may be exhausted. Do not reuse it for the terminal DB
	// write: cancellation or slow evidence work must not strand a running row.
	r.computeCostSummary()
	terminalErr := r.persistAuditTerminalStatus(ctx, err, evidenceErr)
	evidenceErr = errors.Join(evidenceErr, terminalErr)
	run := &database.AgenticScan{}
	applyAuditTerminalStatus(run, err, cancelled)
	if err == nil && evidenceErr != nil {
		run.Status = database.CompletedAgenticScanStatus(true)
	}
	r.mu.Lock()
	r.evidenceErr = evidenceErr
	r.terminalStatus = run.Status
	r.err = errors.Join(err, evidenceErr)
	r.mu.Unlock()
}

// collectFallbackOutput reads key files from the verified archive or source
// fallback and concatenates them. Used when the process was killed before
// stdout was flushed (e.g. --print mode with early cancellation).
func (r *AuditAgenticScanner) collectFallbackOutput() []byte {
	ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
	defer cancel()
	data, _ := r.collectFallbackOutputContext(ctx)
	return data
}

func (r *AuditAgenticScanner) collectFallbackOutputContext(ctx context.Context) ([]byte, error) {
	auditDirLocal := r.evidenceDir()
	if auditDirLocal == "" {
		return nil, nil
	}

	// Top-level reports across lite/scan/deep modes. Includes the Phase 5A/5B/5C
	// matrices added in upstream commit 87b2281.
	candidates := []string{
		"lite-recon.md",
		"commit-recon-report.md",
		"knowledge-base-report.md",
		"enrichment-report.md",
		"spec-gap-report.md",
		"advisory-report.md",
		"authz-matrix.md",
		"cross-service-edges.md",
		"final-audit-report.md",
	}

	var parts [][]byte
	for _, name := range candidates {
		data, err := readAuditControl(ctx, auditDirLocal, name, maxAuditControlBytes)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			continue
		}
		header := fmt.Sprintf("# %s\n\n", strings.TrimSuffix(name, ".md"))
		parts = append(parts, []byte(header))
		parts = append(parts, data)
		parts = append(parts, []byte("\n\n---\n\n"))
	}

	// Enumerate confirmed findings (each in audit/findings/<ID>-<slug>/report.md).
	// findings-draft/ is wiped at the end of every successful run so we no longer
	// scan it; consolidated findings live under findings/ regardless of mode.
	root, rootErr := openAuditRoot(auditDirLocal)
	if rootErr != nil {
		return nil, rootErr
	}
	defer root.root.Close()
	entries, readErr := root.readDirContext(ctx, "findings")
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, readErr
	}
	if readErr == nil {
		var findingDirs []string
		for _, e := range entries {
			if e.IsDir() {
				findingDirs = append(findingDirs, e.Name())
			}
		}
		if len(findingDirs) > 0 {
			sort.Strings(findingDirs)
			var summary strings.Builder
			fmt.Fprintf(&summary, "# Findings\n\n%d findings produced:\n", len(findingDirs))
			for _, name := range findingDirs {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if int64(summary.Len()+len(name)+3) > maxAuditParseBytes {
					return nil, fmt.Errorf("audit fallback summary limit exceeded")
				}
				fmt.Fprintf(&summary, "- %s\n", name)
			}
			parts = append(parts, []byte(summary.String()))
		}
	}

	var buf []byte
	for _, p := range parts {
		if int64(len(buf)+len(p)) > maxAuditParseBytes {
			return nil, fmt.Errorf("audit fallback summary limit exceeded")
		}
		buf = append(buf, p...)
	}
	return buf, ctx.Err()
}

func (r *AuditAgenticScanner) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.done:
			return
		case <-ticker.C:
			r.syncStateOnce(ctx)
			r.syncFindingsIncrementalContext(ctx)
		}
	}
}

// syncStateOnce copies audit-state.json from source to session dir
// and updates the child AgenticScan with current phase info. Skips
// both the disk write and the DB update when the state hash is
// unchanged from the previous tick — long-running audits don't churn
// hundreds of KB of identical bytes through fsync once a minute.
func (r *AuditAgenticScanner) syncStateOnce(ctx context.Context) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if r.syncFinalized || r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}
	harness := r.harness()

	readCtx, cancel := context.WithTimeout(ctx, auditIOTimeout)
	defer cancel()
	data, err := readAuditControl(readCtx, filepath.Join(r.cfg.SourcePath, harness.SourceFolder), "audit-state.json", maxAuditControlBytes)
	if err != nil {
		return // file may not exist yet
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	if hash == r.lastStateHash {
		return
	}

	destDir := filepath.Join(r.cfg.SessionDir, harness.SessionSubdir)
	if err := ensureAuditDir(destDir); err != nil {
		zap.L().Warn("Failed to create audit state directory", zap.Error(err))
		return
	}
	dest := filepath.Join(destDir, "audit-state.json")
	if writeErr := writeAuditArtifact(dest, data); writeErr != nil {
		zap.L().Warn("Failed to sync audit state", zap.Error(writeErr))
		return
	}
	if err := r.updateAgenticScanProgress(readCtx, data); err != nil {
		zap.L().Warn("Failed to sync audit progress", zap.Error(err))
		return
	}
	r.lastStateHash = hash
}

// syncFindingsIncremental streams changed draft files to the session directory.
// Content fingerprints detect same-size edits and advance only after publication.
func (r *AuditAgenticScanner) syncFindingsIncremental() {
	r.syncFindingsIncrementalContext(context.Background())
}

func (r *AuditAgenticScanner) syncFindingsIncrementalContext(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, auditIOTimeout)
	defer cancel()
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if r.syncFinalized || r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return
	}
	harness := r.harness()
	srcDir := filepath.Join(r.cfg.SourcePath, harness.SourceFolder, "findings-draft")
	root, err := openAuditRoot(srcDir)
	if err != nil {
		return
	}
	defer root.root.Close()
	entries, err := root.readDirContext(ctx, ".")
	if err != nil {
		return
	}
	destDir := filepath.Join(r.cfg.SessionDir, harness.SessionSubdir, "findings-draft")
	if err := ensureAuditDir(destDir); err != nil {
		zap.L().Warn("Failed to create draft findings directory", zap.Error(err))
		return
	}
	if r.syncedFiles == nil {
		r.syncedFiles = make(map[string]string)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		hash, err := auditHashInRoot(ctx, root, entry.Name())
		if err != nil {
			continue
		}
		if r.syncedFiles[entry.Name()] == hash {
			continue
		}
		copiedHash, err := copyAuditInRoot(ctx, root, entry.Name(), filepath.Join(destDir, entry.Name()), -1)
		if err != nil {
			zap.L().Warn("Failed to sync draft finding", zap.String("file", entry.Name()), zap.Error(err))
			continue
		}
		r.syncedFiles[entry.Name()] = copiedHash
	}
}

// syncFolderFull publishes only a complete, verified archive. Periodic sync is
// stopped before copying; a partial or stale session tree is never authoritative.
func (r *AuditAgenticScanner) syncFolderFull() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return r.syncFolderFullContext(ctx)
}

func (r *AuditAgenticScanner) syncFolderFullContext(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.syncFinalized = true
	r.archiveDir = ""
	if r.cfg.SessionDir == "" || r.cfg.SourcePath == "" {
		return fmt.Errorf("cannot archive audit evidence: source and session directories are required")
	}
	harness := r.harness()
	if !filepath.IsLocal(harness.SourceFolder) || !filepath.IsLocal(harness.SessionSubdir) {
		return fmt.Errorf("cannot archive audit evidence: harness paths must be local")
	}
	srcDir := filepath.Join(r.cfg.SourcePath, harness.SourceFolder)
	destDir := filepath.Join(r.cfg.SessionDir, harness.SessionSubdir)
	if err := ensureAuditDir(filepath.Dir(destDir)); err != nil {
		return err
	}
	resolvedSrc, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		return err
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(destDir))
	if err != nil {
		return err
	}
	if auditPathsOverlap(resolvedSrc, filepath.Join(resolvedParent, filepath.Base(destDir))) {
		return fmt.Errorf("cannot archive audit evidence: source and destination overlap")
	}
	before, err := auditFolderManifestContext(ctx, srcDir)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(destDir), ".audit-archive-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyDirContext(ctx, srcDir, stage); err != nil {
		return fmt.Errorf("copy audit archive: %w", err)
	}
	after, err := auditFolderManifestContext(ctx, srcDir)
	if err != nil {
		return err
	}
	copied, err := auditFolderManifestContext(ctx, stage)
	if err != nil {
		return err
	}
	if !equalAuditManifests(before, after) || !equalAuditManifests(after, copied) {
		return fmt.Errorf("audit archive verification failed: source changed or copy is incomplete")
	}
	if err := syncAuditDirsContext(ctx, stage); err != nil {
		return fmt.Errorf("sync audit archive directories: %w", err)
	}

	// Preserve the old incremental tree until the verified replacement is in
	// place. Rename failure restores it; no partial copy is published.
	if err := ctx.Err(); err != nil {
		return err
	}
	backup := stage + ".previous"
	if info, err := os.Lstat(destDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("audit archive destination is not a real directory")
		}
		if err := os.Rename(destDir, backup); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stage, destDir); err != nil {
		if _, statErr := os.Lstat(backup); statErr == nil {
			if restoreErr := os.Rename(backup, destDir); restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous archive at %s: %w", backup, restoreErr))
			}
		}
		return err
	}
	if err := syncAuditDir(filepath.Dir(destDir)); err != nil {
		return fmt.Errorf("sync published audit archive: %w", err)
	}
	r.archiveDir = destDir
	if err := os.RemoveAll(backup); err != nil {
		zap.L().Warn("Verified archive published but old incremental copy remains", zap.String("path", backup), zap.Error(err))
	}
	return nil
}

// archiveAndImport is called only after the harness process has exited. Failed
// copies explicitly fall back to source and never authorize source removal.
func (r *AuditAgenticScanner) archiveAndImport(ctx context.Context) error {
	archiveErr := r.syncFolderFullContext(ctx)
	if archiveErr != nil {
		zap.L().Warn("Audit archive failed; retaining source and importing source evidence",
			zap.String("source", r.cfg.SourcePath), zap.Error(archiveErr))
	}
	importErr := r.importFindingsFrom(ctx, r.evidenceDir())
	if archiveErr != nil || importErr != nil || r.cfg.KeepSourceOutputDir {
		return errors.Join(archiveErr, importErr)
	}
	srcDir := filepath.Join(r.cfg.SourcePath, r.harness().SourceFolder)
	// Recheck immediately before cleanup, including descendant content, so a
	// changed/resumed source is retained. This is not a cross-process lease.
	source, err := auditFolderManifestContext(ctx, srcDir)
	if err != nil {
		return err
	}
	archived, err := auditFolderManifestContext(ctx, r.evidenceDir())
	if err != nil {
		return err
	}
	if !equalAuditManifests(source, archived) {
		return fmt.Errorf("source evidence changed after archiving; retaining %s", srcDir)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.RemoveAll(srcDir); err != nil {
		return fmt.Errorf("remove verified audit source: %w", err)
	}
	zap.L().Info("Cleaned up verified harness output dir from source", zap.String("path", srcDir))
	return nil
}

func (r *AuditAgenticScanner) evidenceDir() string {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if r.archiveDir != "" {
		return r.archiveDir
	}
	if r.cfg.SourcePath != "" {
		return filepath.Join(r.cfg.SourcePath, r.harness().SourceFolder)
	}
	// Standalone imports of an already-existing archive have no source path.
	if r.cfg.SessionDir != "" {
		return filepath.Join(r.cfg.SessionDir, r.harness().SessionSubdir)
	}
	return ""
}

// importFindings parses the harness output from session dir and imports findings.
// Populates r.findingStats so the CLI summary can report what was persisted.
func (r *AuditAgenticScanner) importFindings(ctx context.Context) {
	_ = r.importFindingsFrom(ctx, r.evidenceDir())
}

func (r *AuditAgenticScanner) importFindingsFrom(ctx context.Context, auditDirLocal string) error {
	harness := r.harness()
	if auditDirLocal == "" {
		return fmt.Errorf("cannot import audit findings: no evidence directory")
	}
	result, err := parseAuditEvidence(ctx, auditDirLocal)
	if err != nil {
		// ParseFolder returns a nil error for a missing/empty dir, so a non-nil
		// error means the audit output is corrupt and every finding is being
		// dropped — warn loudly with the path rather than swallowing it at Debug.
		zap.L().Warn("Failed to parse harness output for import (findings dropped)",
			zap.String("dir", auditDirLocal),
			zap.Error(err))
		return err
	}

	auditID := ""
	if len(result.State.Audits) > 0 {
		auditID = result.State.Audits[0].AuditID
	}

	findings := audit.BuildFindingsWithSource(result.RawFindings, auditID, r.agenticScanUUID, r.cfg.ProjectUUID, result.RepoName, harnessFindingSource(harness))

	stats := FindingStats{
		Parsed:     len(findings),
		BySeverity: make(map[string]int, len(findings)),
	}
	for _, f := range findings {
		stats.BySeverity[f.Severity]++
	}

	// Persist when a repository is available — otherwise we still want Parsed
	// and BySeverity on the runner so the CLI summary can render counts.
	var persistenceErr error
	if r.repo != nil {
		for _, f := range findings {
			if err := ctx.Err(); err != nil {
				persistenceErr = errors.Join(persistenceErr, err)
				break
			}
			f.ScanUUID = r.cfg.ScanUUID
			if err := r.repo.SaveFindingDirect(ctx, f); err != nil {
				persistenceErr = errors.Join(persistenceErr, err)
				zap.L().Warn("Failed to persist audit finding; retaining source evidence", zap.String("module", f.ModuleID), zap.Error(err))
				continue
			}
			if f.ID > 0 {
				stats.Saved++
			}
		}
	}

	// Always capture what the audit binary itself reported on its NDJSON
	// stream. The CLI summary falls back to these counts when on-disk
	// parsing yielded nothing, so the operator sees the same totals the
	// streamer just printed in the `[result]` line.
	r.mu.Lock()
	res := r.auditResult
	r.mu.Unlock()
	if res.Findings.Total > 0 {
		stats.Reported = res.Findings.Total
		stats.ReportedBySeverity = make(map[string]int, len(res.Findings.BySeverity))
		for sev, n := range res.Findings.BySeverity {
			if n <= 0 {
				continue
			}
			stats.ReportedBySeverity[strings.ToLower(sev)] += n
		}
	}

	r.mu.Lock()
	r.findingStats = stats
	r.mu.Unlock()

	if stats.Parsed > 0 {
		zap.L().Info("Imported audit findings",
			zap.Int("parsed", stats.Parsed),
			zap.Int("saved", stats.Saved))
	}
	return persistenceErr
}

// FindingStats returns the summary of findings parsed and imported by this
// audit run. Only populated after monitor() has completed.
func (r *AuditAgenticScanner) FindingStats() FindingStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := r.findingStats
	if stats.BySeverity != nil {
		cp := make(map[string]int, len(stats.BySeverity))
		for k, v := range stats.BySeverity {
			cp[k] = v
		}
		stats.BySeverity = cp
	}
	if stats.ReportedBySeverity != nil {
		cp := make(map[string]int, len(stats.ReportedBySeverity))
		for k, v := range stats.ReportedBySeverity {
			cp[k] = v
		}
		stats.ReportedBySeverity = cp
	}
	return stats
}

func (r *AuditAgenticScanner) updateAgenticScanProgress(ctx context.Context, stateData []byte) error {
	if r.repo == nil || r.cfg.SuppressAgenticScanRow {
		return nil
	}

	var state audit.State
	if err := json.Unmarshal(stateData, &state); err != nil {
		return err
	}
	if len(state.Audits) == 0 {
		return nil
	}

	latest := state.Audits[len(state.Audits)-1]

	var phases []string
	currentPhase := ""
	for id, phase := range latest.Phases {
		if phase.Status == "complete" {
			phases = append(phases, id)
		}
		if phase.Status == "in_progress" {
			currentPhase = id
		}
	}

	run, err := r.repo.GetAgenticScan(ctx, r.agenticScanUUID)
	if err != nil {
		return err
	}

	run.PhasesRun = phases
	run.CurrentPhase = currentPhase
	if latest.Status != "" {
		if latest.Status == "complete" {
			run.Status = "completed"
		} else {
			run.Status = "running"
		}
	}

	return r.repo.UpdateAgenticScan(ctx, run)
}

func (r *AuditAgenticScanner) persistAuditTerminalStatus(executionCtx context.Context, processErr, evidenceErr error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(executionCtx), auditTerminalTimeout)
	defer cancel()
	return r.finalizeAgenticScan(ctx, processErr, evidenceErr)
}

func (r *AuditAgenticScanner) finalizeAgenticScan(ctx context.Context, processErr, evidenceErr error) error {
	if r.repo == nil || r.cfg.SuppressAgenticScanRow {
		return nil
	}

	run, err := r.repo.GetAgenticScan(ctx, r.agenticScanUUID)
	if err != nil {
		return fmt.Errorf("read audit terminal catalog: %w", err)
	}

	var stateErr error
	if evidenceDir := r.evidenceDir(); evidenceDir != "" {
		data, err := readAuditControl(ctx, evidenceDir, "audit-state.json", maxAuditControlBytes)
		if err == nil {
			run.ResultJSON = string(data)
		} else if !os.IsNotExist(err) {
			stateErr = err
		}
	}
	evidenceErr = errors.Join(evidenceErr, stateErr)

	run.CompletedAt = time.Now()
	run.DurationMs = run.CompletedAt.Sub(run.StartedAt).Milliseconds()

	// A clean process exit is "completed" even if Cancel() raced in after
	// the process already finished — processErr==nil takes precedence.
	r.mu.Lock()
	cancelled := r.cancelled
	r.mu.Unlock()
	applyAuditTerminalStatus(run, processErr, cancelled)
	if evidenceErr != nil {
		if processErr == nil {
			run.Status = database.CompletedAgenticScanStatus(true)
		}
		run.ErrorMessage = errors.Join(processErr, evidenceErr).Error()
	}

	applyScanCost(run, r.costSummary)

	if err := r.repo.UpdateAgenticScan(ctx, run); err != nil {
		zap.L().Warn("failed to persist finalized agentic scan", zap.String("run", run.UUID), zap.Error(err))
		return errors.Join(stateErr, fmt.Errorf("persist audit terminal catalog: %w", err))
	}
	return stateErr
}

// computeCostSummary derives a priced ScanCost for the run and stores
// it on the runner. Sources by harness:
//
//   - audit: the captured `result` event from auditstream (totalUsd
//     and totalTokens are emitted by the binary itself).
//   - piolium: per-session rollout under <source>/.piolium/.
func (r *AuditAgenticScanner) computeCostSummary() {
	harness := r.harness()

	var cost ScanCost
	switch harness.Name {
	case piolium.HarnessName:
		if r.cfg.SourcePath == "" {
			return
		}
		s, err := picost.BuildSummary(r.cfg.SourcePath, r.processStartedAt())
		if err != nil {
			zap.L().Debug("Failed to compute pi cost summary", zap.Error(err))
			return
		}
		cost = scanCostFromPi(s)
	default:
		// audit (and unset → audit by harness() default).
		r.mu.Lock()
		res := r.auditResult
		r.mu.Unlock()
		cost = scanCostFromAudit(res, r.cfg.AuditDriverInvocation.Agent)
	}

	if cost.IsZero() {
		return
	}
	r.mu.Lock()
	r.costSummary = cost
	r.mu.Unlock()
}

// ProcessStartedAt returns the wall time the audit subprocess was launched.
// Used to disambiguate codex rollouts (when multiple share a cwd) and to
// classify early-runtime failures for the audit fallback path. Returns the
// zero time if Start has not been called.
func (r *AuditAgenticScanner) ProcessStartedAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startedAt
}

// processStartedAt is the internal alias kept for the few package-internal
// callers. New code should use ProcessStartedAt.
func (r *AuditAgenticScanner) processStartedAt() time.Time {
	return r.ProcessStartedAt()
}

// Harness returns the harness spec the runner was configured with. Lets
// callers label output and tag findings without re-reading config or
// hard-coding harness names like "piolium" / "audit".
func (r *AuditAgenticScanner) Harness() HarnessSpec {
	return r.cfg.Harness
}

// CostSummary returns the priced token summary for this audit run. The
// zero value is returned when the run is still active, used an
// unsupported backend, or the backend transcript could not be parsed.
func (r *AuditAgenticScanner) CostSummary() ScanCost {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Shallow copy is sufficient — ScanCost holds no slices the caller
	// could mutate, and the Blob map is never modified post-build.
	return r.costSummary
}

// Wait blocks until the audit finishes.
func (r *AuditAgenticScanner) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Done returns a channel that closes when the audit finishes.
func (r *AuditAgenticScanner) Done() <-chan struct{} {
	return r.done
}

// Cancel stops the audit process. Sends SIGTERM first, then SIGKILL after a grace period.
func (r *AuditAgenticScanner) Cancel() {
	r.mu.Lock()
	r.cancelled = true
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return
	}

	_ = procutil.SignalProcessGroup(cmd.Process.Pid, false) // SIGTERM the process group

	select {
	case <-r.done:
		return
	case <-time.After(cancelGracePeriod):
		_ = procutil.SignalProcessGroup(cmd.Process.Pid, true) // escalate to SIGKILL
	}
}

// Status returns a summary of the current audit state.
func (r *AuditAgenticScanner) Status() *AuditAgentStatus {
	state := r.readCurrentState()
	if state == nil || len(state.Audits) == 0 {
		return &AuditAgentStatus{Running: r.isRunning(), Phase: "initializing"}
	}

	latest := state.Audits[len(state.Audits)-1]
	completedPhases := 0
	totalPhases := len(latest.Phases)
	currentPhase := ""

	for id, phase := range latest.Phases {
		if phase.Status == "complete" {
			completedPhases++
		}
		if phase.Status == "in_progress" {
			currentPhase = id
		}
	}

	return &AuditAgentStatus{
		Running:         r.isRunning(),
		Status:          latest.Status,
		Mode:            JoinModes(r.cfg.EffectiveModes()),
		Phase:           currentPhase,
		CompletedPhases: completedPhases,
		TotalPhases:     totalPhases,
	}
}

func (r *AuditAgenticScanner) isRunning() bool {
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (r *AuditAgenticScanner) readCurrentState() *audit.State {
	// Try the source dir first (authoritative while the audit is running),
	// then fall back to the synced copy in the session dir. The fallback
	// matters after monitor() removes the source-side output dir on cleanup:
	// by the time Status() is called from the CLI summary, only the session
	// copy remains.
	harness := r.harness()
	candidates := []string{
		filepath.Join(r.cfg.SourcePath, harness.SourceFolder, "audit-state.json"),
	}
	if r.cfg.SessionDir != "" {
		candidates = append(candidates, filepath.Join(r.cfg.SessionDir, harness.SessionSubdir, "audit-state.json"))
	}

	for _, path := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
		data, err := readAuditControl(ctx, filepath.Dir(path), filepath.Base(path), maxAuditControlBytes)
		cancel()
		if err != nil {
			continue
		}
		var state audit.State
		if err := json.Unmarshal(data, &state); err != nil {
			continue
		}
		return &state
	}
	return nil
}

// --- Process management helpers ---

// syncBuffer is a thread-safe buffer for capturing process output.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(b.buf))
	copy(cp, b.buf)
	return cp
}

// copyDir streams regular files and rejects symlinks/special files instead of
// following them out of the evidence tree or silently producing a partial copy.
func copyDir(src, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
	defer cancel()
	return copyDirContext(ctx, src, dest)
}

func copyDirContext(ctx context.Context, src, dest string) error {
	return walkAuditTree(ctx, src, func(root *auditRootFS, name string, d fs.DirEntry) error {
		destPath := filepath.Join(dest, filepath.FromSlash(name))
		if d.IsDir() {
			return ensureAuditDir(destPath)
		}
		_, err := copyAuditInRoot(ctx, root, name, destPath, -1)
		return err
	})
}

// ensureAuditDir rejects symlink components. New evidence directories are
// private; existing shared parent directories keep their permissions.
func ensureAuditDir(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := ensureAuditDir(filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit evidence directory is not a real directory: %s", path)
	}
	if parent := filepath.Dir(path); parent != path {
		return ensureAuditDir(parent)
	}
	return nil
}

// publishAuditArtifact writes a private temporary file, fsyncs it, and renames
// it atomically. Errors leave the previous artifact and fingerprint untouched.
func publishAuditArtifact(dest string, write func(io.Writer) error) error {
	if err := ensureAuditDir(filepath.Dir(dest)); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(dest), ".audit-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	writeErr := write(file)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), dest)
}

func writeAuditArtifact(dest string, data []byte) error {
	return publishAuditArtifact(dest, func(out io.Writer) error {
		_, err := out.Write(data)
		return err
	})
}

func openAuditFile(filePath string) (*os.File, error) {
	root, err := openAuditRoot(filepath.Dir(filePath))
	if err != nil {
		return nil, err
	}
	defer root.root.Close()
	file, err := root.Open(filepath.Base(filePath))
	if err != nil {
		return nil, err
	}
	f := file.(*os.File)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("unsupported audit evidence file")
	}
	return f, nil
}

func auditFileHash(filePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
	defer cancel()
	root, err := openAuditRoot(filepath.Dir(filePath))
	if err != nil {
		return "", err
	}
	defer root.root.Close()
	return auditHashInRoot(ctx, root, filepath.Base(filePath))
}

func copyAuditFile(src, dest string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
	defer cancel()
	root, err := openAuditRoot(filepath.Dir(src))
	if err != nil {
		return "", err
	}
	defer root.root.Close()
	return copyAuditInRoot(ctx, root, filepath.Base(src), dest, -1)
}

// A manifest holds only paths and fingerprints, never whole evidence contents.
// Directory entries are included so missing/extra files or empty dirs are caught.
func auditFolderManifest(root string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
	defer cancel()
	return auditFolderManifestContext(ctx, root)
}

func auditFolderManifestContext(ctx context.Context, dir string) (map[string]string, error) {
	manifest := make(map[string]string)
	err := walkAuditTree(ctx, dir, func(root *auditRootFS, name string, d fs.DirEntry) error {
		if d.IsDir() {
			manifest[name] = "dir"
			return nil
		}
		hash, err := auditHashInRoot(ctx, root, name)
		if err != nil {
			return err
		}
		manifest[name] = hash
		return nil
	})
	return manifest, err
}

// Sync directory entries as well as file contents before source removal.
func syncAuditDirs(root string) error {
	ctx, cancel := context.WithTimeout(context.Background(), auditIOTimeout)
	defer cancel()
	return syncAuditDirsContext(ctx, root)
}

func syncAuditDirsContext(ctx context.Context, dir string) error {
	var dirs []string
	if err := walkAuditTree(ctx, dir, func(_ *auditRootFS, name string, d fs.DirEntry) error {
		if d.IsDir() {
			dirs = append(dirs, filepath.Join(dir, filepath.FromSlash(name)))
		}
		return nil
	}); err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := syncAuditDir(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func syncAuditDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func equalAuditManifests(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for path, hash := range a {
		if b[path] != hash {
			return false
		}
	}
	return true
}

func auditPathsOverlap(a, b string) bool {
	a, err := filepath.Abs(a)
	if err != nil {
		return true
	}
	b, err = filepath.Abs(b)
	if err != nil {
		return true
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	return a == b || strings.HasPrefix(a, b+string(os.PathSeparator)) || strings.HasPrefix(b, a+string(os.PathSeparator))
}

// --- Audit harness environment ---

// applyPioliumBYOK injects per-run BYOK creds into the pi subprocess: env
// vars for api-key / oauth-token paths, a staged <pi-agent-dir>/auth.json
// for codex cred files. No-op when the override is empty so non-BYOK runs
// pay no cost. authEnv is appended to (caller tracks it separately so
// secret values can be redacted in the debug line).
//
// Before staging, sweep any orphaned lock + backup left behind by a prior
// crashed run in the same agent dir so we don't error on a dead lock. The
// sweep is best-effort and never blocks the launch.
func (r *AuditAgenticScanner) applyPioliumBYOK(cmd *exec.Cmd, authEnv *[]string, pioliumAgentDir string) error {
	if r.cfg.AuthOverride.IsZero() {
		return nil
	}
	if envEntries := PiAuthEnv(r.cfg.AuthOverride); len(envEntries) > 0 {
		*authEnv = envEntries
		cmd.Env = append(cmd.Env, envEntries...)
	}
	if r.cfg.AuthOverride.OAuthCredFile == "" ||
		normalizedAgent(r.cfg.AuthOverride.Agent) != string(AuditDriverAgentCodex) {
		return nil
	}
	if pioliumAgentDir != "" {
		sweep := SweepStalePioliumAuth([]string{pioliumAgentDir})
		for _, s := range sweep.Swept {
			zap.L().Warn("piolium codex BYOK: restored stale backup from crashed run",
				zap.String("dir", s.Dir),
				zap.String("restored_from", s.BackupPath),
				zap.String("dead_run", s.Holder.Run),
				zap.Int("dead_pid", s.Holder.PID))
		}
		for _, o := range sweep.Orphaned {
			zap.L().Warn("piolium codex BYOK: orphaned backup left in place (manual restore required)",
				zap.String("path", o))
		}
	}
	cleanup, err := stagePioliumCodexCred(
		r.cfg.AuthOverride.OAuthCredFile,
		pioliumAgentDir,
		r.agenticScanUUID,
	)
	if err != nil {
		return fmt.Errorf("piolium codex BYOK: %w", err)
	}
	r.byokCleanup = cleanup
	return nil
}

// auditEnvFor produces the harness-specific env vars upstream CLIs normally
// export before launching the agent. Vigolium bypasses those wrappers and
// runs claude/codex/pi directly, so we replicate the exports here
// so the harness's agents see the repo identity, git availability, commit
// scan limits, and a stable session UUID.
//
// prefix is the harness env-var namespace (e.g. "ARCHON_", "PIOLIUM_").
func auditEnvFor(prefix, sourcePath, sessionUUID string, commitLimit int, commitSince string) []string {
	if prefix == "" {
		prefix = "ARCHON_"
	}
	repo := deriveRepositoryName(sourcePath)
	gitAvailable := "false"
	if isGitWorkTree(sourcePath) {
		gitAvailable = "true"
	}
	envs := []string{
		prefix + "REPOSITORY=" + repo,
		prefix + "GIT_AVAILABLE=" + gitAvailable,
		prefix + "SESSION_UUID=" + sessionUUID,
	}
	// Surface a hand-curated `<source>/vigolium-results/INFO.md` to the harness's
	// knowledge-base-builder, which treats it as authoritative project context
	// when ARCHON_INFO_AVAILABLE=true. Only emitted under the ARCHON_ prefix —
	// piolium has no equivalent today.
	if prefix == "ARCHON_" {
		envs = append(envs, prefix+"INFO_AVAILABLE="+infoFileAvailable(sourcePath))
	}
	if commitLimit > 0 {
		envs = append(envs, fmt.Sprintf("%sCOMMIT_SCAN_LIMIT=%d", prefix, commitLimit))
	}
	if commitSince != "" {
		envs = append(envs, prefix+"COMMIT_SCAN_SINCE="+commitSince)
	}
	return envs
}

// infoFileAvailable reports "true" when <target>/vigolium-results/INFO.md exists as a
// non-empty regular file. Mirrors the standalone vigolium-audit CLI's
// hasAuditDriverInfoFile helper so vigolium-launched runs see the same signal.
func infoFileAvailable(target string) string {
	if target == "" {
		return "false"
	}
	info, err := os.Stat(filepath.Join(target, "vigolium-results", "INFO.md"))
	if err != nil {
		return "false"
	}
	if info.IsDir() || info.Size() == 0 {
		return "false"
	}
	return "true"
}

// deriveRepositoryName resolves a repo identity for the audit target. Tries
// the git remote first (canonicalized to "owner/repo" when possible), then
// falls back to the directory basename. Mirrors the upstream behavior at a
// fraction of the surface area — manifest probing is omitted.
func deriveRepositoryName(target string) string {
	if name := repoNameFromGitRemote(target); name != "" {
		return name
	}
	return filepath.Base(target)
}

func repoNameFromGitRemote(target string) string {
	cmd := exec.Command("git", "-C", target, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return normalizeOwnerRepo(strings.TrimSpace(string(out)))
}

func isGitWorkTree(target string) bool {
	cmd := exec.Command("git", "-C", target, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// normalizeOwnerRepo canonicalizes a git URL or owner/repo string. Returns
// "" when the input doesn't contain a recognizable owner/repo segment.
func normalizeOwnerRepo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimSuffix(raw, "/")
	raw = strings.TrimSuffix(raw, ".git")
	// git@host:owner/repo or https://host/owner/repo
	if idx := strings.LastIndex(raw, ":"); idx >= 0 {
		if rest := strings.TrimLeft(raw[idx+1:], "/"); ownerRepoRE.MatchString(rest) {
			return rest
		}
	}
	if idx := strings.LastIndex(raw, "/"); idx > 0 {
		// Walk back one segment to capture owner/repo from a URL path.
		prev := strings.LastIndex(raw[:idx], "/")
		if prev >= 0 {
			rest := raw[prev+1:]
			if ownerRepoRE.MatchString(rest) {
				return rest
			}
		}
	}
	if ownerRepoRE.MatchString(raw) {
		return raw
	}
	return ""
}

// --- Platform command builders ---

// AgenticScanUUID returns the UUID of the AgenticScan row this runner owns.
// Useful for tests and callers that need to look up the row after Wait().
func (r *AuditAgenticScanner) AgenticScanUUID() string {
	return r.agenticScanUUID
}

// piPreArgs builds the pre-`--mode json -p` flag list passed to `pi`.
// Empty when neither PiProvider nor PiModel is set.
func piPreArgs(cfg AuditAgentConfig) []string {
	var out []string
	if cfg.PiProvider != "" {
		out = append(out, "--provider", cfg.PiProvider)
	}
	if cfg.PiModel != "" {
		out = append(out, "--model", cfg.PiModel)
	}
	return out
}

// buildAuditAgentCommand resolves the CLI binary and builds the argument list
// for launching vigolium-audit (claude/codex) or piolium (pi) on the
// given platform. When stream is true the command emits line-oriented JSON on
// stdout (Claude's stream-json or Pi's --mode json) so the caller can render
// a live activity feed via the appropriate decoder.
//
// sessionDir is vigolium's per-scan session root. On the pi platform it
// becomes `--session-dir <sessionDir>/pi-session` so pi's transcripts and
// state land alongside vigolium's audit-stream.jsonl and synced findings.
// This is independent of $PIOLIUM_SESSION_DIR (the standalone-piolium
// default): vigolium owns per-scan isolation; $PIOLIUM_HOME is only the
// piolium *agent config* root (set via PI_CODING_AGENT_DIR — see
// piolium.RuntimeEnv). Empty sessionDir omits the flag and lets pi pick
// its own location (used by tests and ad-hoc runs).
//
// cfg.AdditionalArgs are appended verbatim after the harness-specific args
// and are typically piolium's --plm-* passthrough flags. They are ignored
// for the audit harness.
//
// piPreArgs are inserted ahead of `--mode json -p` on the pi platform so
// pi sees them as its own flags (e.g. `--provider`, `--model`). Ignored
// for non-pi platforms.
func buildAuditAgentCommand(platform string, cfg AuditAgentConfig, stream bool) (binary string, args []string, stdinPrompt string, err error) {
	switch platform {
	case PlatformPi:
		binary, err = exec.LookPath("pi")
		if err != nil {
			return "", nil, "", fmt.Errorf("pi CLI not found in PATH: %w", err)
		}
		command := "/piolium-" + cfg.Mode
		args = append(args, piPreArgs(cfg)...)
		if cfg.SessionDir != "" {
			args = append(args, "--session-dir", filepath.Join(cfg.SessionDir, "pi-session"))
		}
		if stream {
			args = append(args, "--mode", "json", "-p", command)
		} else {
			args = append(args, "-p", command)
		}
		if len(cfg.AdditionalArgs) > 0 {
			args = append(args, cfg.AdditionalArgs...)
		}
		return binary, args, stdinPrompt, nil

	case PlatformAuditBin, "":
		binary, err = bin.Path()
		if err != nil {
			return "", nil, "", fmt.Errorf("locate embedded vigolium-audit binary: %w (run `make build-audit`)", err)
		}
		// vigolium-audit CLI: `audit run --target <abs> (--mode <mode> |
		// --modes a,b,c) --agent <claude|codex> [--api-key|--oauth-*]
		// [--json]`. vigolium handles git clone / archive extraction in Go
		// before launch, so --target is always a local absolute path.
		//
		// A multi-mode chain is handed to audit's native `--modes` so
		// audit owns the sequential execution, stop-on-non-complete, the
		// --from-audit auto-detect between modes, and the aggregate
		// --max-cost cap. A single mode keeps the original `--mode` form so
		// existing behavior (and audit's per-mode resume semantics) is
		// untouched.
		args = []string{
			"run",
			"--target", cfg.SourcePath,
		}
		if modes := cfg.EffectiveModes(); len(modes) > 1 {
			args = append(args, "--modes", JoinModes(modes))
		} else {
			args = append(args, "--mode", modes[0])
		}
		args = append(args, cfg.AuditDriverInvocation.Args()...)
		// Pass our AgenticScan UUID to audit so its auth-overrides path can
		// namespace backup files (.audit-backup-<uuid>) and the cred-dir
		// lock breadcrumb. Two concurrent BYOK audits would otherwise
		// collide on a fixed-name backup; the per-uuid suffix makes the
		// collision a hard error from the lock instead of a silent stomp.
		if cfg.ScanUUID != "" {
			args = append(args, "--run-uuid", cfg.ScanUUID)
		}
		if cfg.KeepRaw {
			args = append(args, "--keep-raw")
		}
		if stream {
			args = append(args, "--json")
		}
		return binary, args, stdinPrompt, nil

	default:
		return "", nil, "", fmt.Errorf("unsupported audit platform %q", platform)
	}
}

// --- Public API ---

// StartAuditAgent creates and starts a background audit run for the given
// harness (audit or piolium). Returns nil runner when the cfg is disabled
// or sourcePath is empty. When streamWriter is non-nil, audit output is
// streamed in real-time. Harness-specific bits (Platform=pi + StreamDecoder
// for piolium) are auto-installed when harness.Name == "piolium".
func StartAuditAgent(ctx context.Context, agentCfg config.AuditAgentConfig, harness HarnessSpec, sourcePath, sessionDir, projectUUID, scanUUID, parentAgenticScanUUID string, repo *database.Repository, streamWriter io.Writer) (*AuditAgenticScanner, error) {
	if !agentCfg.IsEnabled() || sourcePath == "" {
		return nil, nil
	}
	if harness.Name == "" {
		harness = DefaultAuditHarness()
	}

	cfg := AuditAgentConfig{
		Harness:               harness,
		Mode:                  agentCfg.EffectiveMode(),
		Platform:              PlatformAuditBin,
		SourcePath:            sourcePath,
		SessionDir:            sessionDir,
		ProjectUUID:           projectUUID,
		ScanUUID:              scanUUID,
		ParentAgenticScanUUID: parentAgenticScanUUID,
		SyncInterval:          time.Duration(agentCfg.EffectiveSyncInterval()) * time.Second,
		StreamWriter:          streamWriter,
		Stream:                streamWriter != nil,
	}

	if harness.Name == piolium.HarnessName {
		cfg.Platform = PlatformPi
		cfg.Stream = true
		cfg.StreamDecoder = func(in io.Reader, render io.Writer, raw io.Writer) error {
			return pistream.Stream(in, render, pistream.Options{RawLog: raw})
		}
	}

	runner := NewAuditAgenticScanner(cfg, repo)
	if err := runner.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start %s-audit: %w", harness.Name, err)
	}

	return runner, nil
}

// startAuditAgentBackground is a shared helper that starts an audit (audit
// or piolium) and returns the runner and a wait func. Logs startup
// success/failure via the provided logFn. Returns nil runner and nil wait
// when the audit is disabled or fails to start. Under the local source lease,
// any existing output requires recovery before reuse. The harness also drives
// platform/stream-decoder selection inside StartAuditAgent.
func startAuditAgentBackground(ctx context.Context, auditCfg *config.AuditAgentConfig, harness HarnessSpec, sourcePath, sessionDir, projectUUID, scanUUID, parentAgenticScanUUID string, repo *database.Repository, streamWriter io.Writer, logFn func(msg string)) (*AuditAgenticScanner, func(), error) {
	if auditCfg == nil || !auditCfg.IsEnabled() || sourcePath == "" {
		return nil, nil, nil
	}
	if harness.Name == "" {
		harness = DefaultAuditHarness()
	}

	// Serialize audits that share this source-tree output dir. The embedded audit
	// binary writes to a fixed `<source>/<SourceFolder>` path. The lease makes a
	// second same-source audit wait for the first to finish, then refuses reuse
	// if previous evidence remains. Released when the run's monitor exits.
	staleDir := filepath.Join(sourcePath, harness.SourceFolder)
	releaseLease, leaseErr := acquireAuditSourceLeaseContext(ctx, staleDir)
	if leaseErr != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		zap.L().Warn("Audit source output cannot be checked; recover before reusing source", zap.String("path", staleDir))
		if logFn != nil {
			logFn("audit source output cannot be checked; recovery path " + staleDir)
		}
		return nil, nil, errors.Join(ErrAuditSourceNeedsRecovery, leaseErr)
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(releaseLease) }
	leaseHeld := true
	defer func() {
		// If we return without a live runner, drop the lease here; otherwise it is
		// released asynchronously once the runner's monitor goroutine exits.
		if leaseHeld {
			release()
		}
	}()
	if err := checkAuditSourceReusable(staleDir); err != nil {
		zap.L().Warn("Audit source output retained; recover before reusing source", zap.String("path", staleDir))
		if logFn != nil {
			logFn("audit source output retained for recovery at " + staleDir)
		}
		return nil, nil, err
	}

	runner, err := StartAuditAgent(ctx, *auditCfg, harness, sourcePath, sessionDir, projectUUID, scanUUID, parentAgenticScanUUID, repo, streamWriter)
	if err != nil {
		zap.L().Warn("Failed to start background audit, continuing without it",
			zap.String("harness", harness.Name),
			zap.Error(err))
		if logFn != nil {
			logFn(fmt.Sprintf("%s-audit failed to start: %v", harness.Name, err))
		}
		return nil, nil, err
	}
	if runner == nil {
		return nil, nil, nil
	}

	if logFn != nil {
		logFn(fmt.Sprintf("started (%s mode)", auditCfg.EffectiveMode()))
	}

	// wait blocks until the runner's monitor goroutine has fully exited.
	// Callers use this to wait for a parallel audit to finish naturally —
	// do NOT call Cancel() here or a fast-finishing parent pipeline would
	// abort a still-running audit and mark it as "cancelled" in the DB.
	// When the parent ctx is cancelled (SIGINT/timeout), exec.CommandContext
	// already kills the subprocess and the monitor will complete on its own.
	// Hand the lease to the run: release it once the monitor goroutine exits,
	// regardless of whether the caller invokes wait(). This keeps the source-tree
	// output dir reserved for the whole run.
	leaseHeld = false
	go func() {
		<-runner.Done()
		release()
	}()

	wait := func() {
		if err := runner.Wait(); err != nil {
			// Keep the historical func() API; the caller can obtain the structured
			// outcome from runner after waiting, without reimporting an old tree.
			zap.L().Warn("Background audit finalization incomplete", zap.String("run", runner.agenticScanUUID))
			if logFn != nil {
				logFn("audit evidence degraded; inspect retained run evidence before source reuse")
			}
		}
	}
	return runner, wait, nil
}

// auditSourceLeases serializes audits that share a source-tree output directory
// (keyed by the absolute `<source>/<SourceFolder>` path). The embedded audit
// binary writes to a fixed path per source tree, so concurrent same-source runs
// must not overlap or they clobber each other's output.
var (
	auditSourceLeasesMu sync.Mutex
	auditSourceLeases   = map[string]chan struct{}{}
)

// acquireAuditSourceLease blocks until the lease for key is free, then returns a
// release func. Callers must call the returned func exactly once.
func acquireAuditSourceLease(key string) func() {
	release, _ := acquireAuditSourceLeaseContext(context.Background(), key)
	return release
}

func acquireAuditSourceLeaseContext(ctx context.Context, key string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(key)
	if err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	key = filepath.Join(parent, filepath.Base(abs))
	auditSourceLeasesMu.Lock()
	gate, ok := auditSourceLeases[key]
	if !ok {
		gate = make(chan struct{}, 1)
		auditSourceLeases[key] = gate
	}
	auditSourceLeasesMu.Unlock()
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return nil, err
		}
		return func() { <-gate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ResolveAuditAgentConfig determines whether vigolium-audit should run.
