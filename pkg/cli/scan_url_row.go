package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// directScanFinalizeBudget bounds the scan-row finalization write, the same
// budget the runner's finalizer uses.
const directScanFinalizeBudget = 30 * time.Second

// directScanSession owns what one scan-url / scan-request invocation on the
// direct path persists beyond its findings: the scan row(s) and the store
// handle.
//
// The direct path used to create no scan row at all and run with an empty scan
// UUID unless --scan-uuid was typed, so its findings carried no scan_uuid and
// `log`, `scan status` and `finding --scan-uuid` had nothing to look up. Every
// input now gets a UUID and, when a store is open, a row:
//
//   - unpinned: one row per input, each with its own freshly minted UUID,
//     completed as soon as that input finishes;
//   - pinned (--scan-uuid): ONE shared row for the whole invocation, its target
//     the joined input list, re-completed after every input with the verdict
//     over all inputs so far (so an interrupt between inputs still leaves an
//     accurate row).
//
// It also owns closing the store. The handle is process-cached, and closing it
// after the first input (as executeDirectScan used to) left every later input of
// a batch writing into a closed database.
type directScanSession struct {
	name    string // database.ScanNameScanURL | database.ScanNameScanRequest
	pinned  string
	targets []string
	modules string

	storeOpened bool

	// admission is the scope verdict over every input, computed before any
	// request went out; nil under --ignore-scope (and for an ad-hoc session),
	// which applies no scope. See admitDirectInputs.
	admission *directAdmission

	// reach folds reachability across inputs: the exit is 1 only when none
	// answered (see directReach). schemeSource is how scan-request settled its
	// request's scheme (the result's scheme_source); empty for scan-url.
	reach        directReach
	schemeSource string

	// doc is the invocation's scan document under -j (nil otherwise): every
	// input, on either path, is folded into it and it is written once.
	doc *scanDocBuilder

	// Shared-row state (pinned only): created once, and the raw inputs of the
	// verdict, folded across inputs so the verdict is recomputed over all of
	// them rather than merged from per-input verdicts.
	sharedCreated bool
	agg           directScanAggregate

	// Captured only after begin validates identity. Completion never adopts a
	// stored row's project (or another store) when this invocation lacks scope.
	scanScopes map[string]directScanScope

	// budget is the invocation's request budget (--max-requests,
	// --max-requests-per-host), shared by every input; nil when unset. Its
	// verdict is folded into each row (runner.ApplyRequestBudget).
	budget *egress.Budget

	// phaseReasons are partial reasons the direct path observed outside the
	// executor report, per scan UUID: oast_unavailable (interactsh did not
	// register, blind checks skipped) and scan_budget
	// (--scanning-max-duration ran out). Folded into the row by complete.
	phaseReasons map[string][]string
	// phaseNotes are caveat codes the direct path observed that do not make
	// the scan partial (PhaseOutcome.Notes), per scan UUID.
	phaseNotes map[string][]string

	// cfg is the invocation's settings, loaded once (see directSettings).
	cfg *directSettings

	// heartbeats keep each row's liveness fresh while its input runs, one per
	// scan UUID. Each ends itself once its row is finalized (StopWhenRowDone);
	// close stops any left. Without them a long scan-url row carried no
	// heartbeat and `scan wait` would call it abandoned after two minutes.
	heartbeats map[string]*runner.Heartbeat

	// finished lists the rows this session completed, in order, with the
	// store they live in and the run's own view of each, so close can fire
	// one scan webhook per row once its verdict is final (a pinned row is
	// re-completed after every input and fires once, with the last verdict).
	finished     []string
	finishedOut  map[string]webhook.Outcome
	finishedRepo *database.Repository
}

type directScanScope struct {
	db      *database.DB
	project string
}

// directSettings is the settings one scan-url / scan-request invocation on the
// direct path runs with: global → the resolved project's overlay, with
// --oast-url and --scope-origin applied as runner.ApplyScanSettingOverrides
// applies them for `vigolium scan`. Loaded once, on first use, and shared by
// scope admission, OAST, the browser-probe stealth default,
// allow_risky_payloads and the scan webhook.
type directSettings struct {
	loaded   bool
	settings *config.Settings
	err      error
}

func (d *directSettings) get() (*config.Settings, error) {
	if !d.loaded {
		d.loaded = true
		d.settings, d.err = loadProjectSettings(globalConfig)
		if d.err == nil {
			runner.ApplyScanSettingOverrides(d.settings, &types.Options{OastURL: scanOpts.OastURL, ScopeOriginMode: globalScopeOrigin})
		}
	}
	return d.settings, d.err
}

// loadSettings returns the session's settings (see directSettings). An error
// means an explicit --config or a project overlay could not be read.
func (s *directScanSession) loadSettings() (*config.Settings, error) {
	if s.cfg == nil {
		s.cfg = &directSettings{}
	}
	return s.cfg.get()
}

// directScanAggregate is the folded input of DirectScanCompletion across the
// inputs that share one pinned row.
type directScanAggregate struct {
	rep         core.ExecutionReport
	reached     bool
	interrupted bool
	err         error
	tally       database.TargetTally
}

func (a *directScanAggregate) add(rep core.ExecutionReport, reached, interrupted bool, err error, tally database.TargetTally) {
	a.rep.StoppedEarly = a.rep.StoppedEarly || rep.StoppedEarly
	a.rep.DrainStalled = a.rep.DrainStalled || rep.DrainStalled
	a.rep.WorkersAbandoned = a.rep.WorkersAbandoned || rep.WorkersAbandoned
	a.rep.DeferredFlushSkipped = a.rep.DeferredFlushSkipped || rep.DeferredFlushSkipped
	a.rep.Unacked += rep.Unacked
	a.rep.ScopeRejected += rep.ScopeRejected
	a.rep.Responded += rep.Responded
	a.rep.FindingStoreFailed += rep.FindingStoreFailed
	a.reached = a.reached || reached
	a.interrupted = a.interrupted || interrupted
	if a.err == nil {
		a.err = err
	}
	a.tally.Merge(tally)
}

// newDirectScanSession prepares the session for inputs. name is the scan-row
// name of the invoking command.
func newDirectScanSession(name string, inputs []scanInput) *directScanSession {
	targets := make([]string, 0, len(inputs))
	for _, in := range inputs {
		targets = append(targets, in.target)
	}
	modules := resolveModules()
	return &directScanSession{
		name:    name,
		pinned:  strings.TrimSpace(globalScanUUID),
		targets: targets,
		modules: strings.Join(modules, ","),
		budget:  directRequestBudget(),
	}
}

// notePhaseReason records a partial reason for scanUUID's row (see
// phaseReasons).
func (s *directScanSession) notePhaseReason(scanUUID, reason string) {
	if s.phaseReasons == nil {
		s.phaseReasons = map[string][]string{}
	}
	for _, r := range s.phaseReasons[scanUUID] {
		if r == reason {
			return
		}
	}
	s.phaseReasons[scanUUID] = append(s.phaseReasons[scanUUID], reason)
}

// notePhaseCaveat records a caveat code for scanUUID that does not reduce
// coverage (PhaseOutcome.Notes).
func (s *directScanSession) notePhaseCaveat(scanUUID, code string) {
	if s.phaseNotes == nil {
		s.phaseNotes = map[string][]string{}
	}
	if !slices.Contains(s.phaseNotes[scanUUID], code) {
		s.phaseNotes[scanUUID] = append(s.phaseNotes[scanUUID], code)
	}
}

// scanUUID returns the UUID the next input scans under: the pinned one, or a
// fresh one per input.
func (s *directScanSession) scanUUID() string {
	return pinnedOrNewUUID(s.pinned)
}

// noteStore records that an input opened the store, so close releases it.
func (s *directScanSession) noteStore() { s.storeOpened = true }

// close releases the store once every input is done. Safe to call when no
// input opened one.
func (s *directScanSession) close() {
	if s == nil {
		return
	}
	for _, h := range s.heartbeats {
		h.Stop(context.Background())
	}
	// Before the store closes: the payload is read from each row.
	s.fireWebhooks()
	if s.storeOpened {
		closeDatabaseOnExit()
	}
}

// noteFinished records that scanUUID's row was completed with out as the
// run's own view (used only if the row read back is not terminal).
func (s *directScanSession) noteFinished(repo *database.Repository, scanUUID string, out webhook.Outcome) {
	if repo == nil || scanUUID == "" {
		return
	}
	if s.finishedOut == nil {
		s.finishedOut = make(map[string]webhook.Outcome)
	}
	if _, seen := s.finishedOut[scanUUID]; !seen {
		s.finished = append(s.finished, scanUUID)
	}
	s.finishedOut[scanUUID] = out
	s.finishedRepo = repo
}

// fireWebhooks posts the configured scan webhook once per completed row. It
// runs from close, after every input finished, so a pinned row reports its
// final verdict and an interrupted batch still reports the rows it wrote. The
// project's config overlay applies, as it does on the runner path.
func (s *directScanSession) fireWebhooks() {
	if len(s.finished) == 0 {
		return
	}
	settings, err := s.loadSettings()
	if err != nil {
		settings = settingsOrDefaults()
	}
	for _, id := range s.finished {
		webhook.FireNativeScanOutcome(settings, s.finishedRepo, id, s.finishedOut[id])
	}
	s.finished = nil
}

// startHeartbeat starts scanUUID's liveness heartbeat once its row exists.
// The direct path counts no requests outside the executor, so the beat
// carries liveness and phase only and leaves total_requests alone.
func (s *directScanSession) startHeartbeat(repo *database.Repository, projectUUID, scanUUID string) {
	if repo == nil || scanUUID == "" || s.heartbeats[scanUUID] != nil {
		return
	}
	if s.heartbeats == nil {
		s.heartbeats = make(map[string]*runner.Heartbeat)
	}
	settings := settingsOrDefaults()
	s.heartbeats[scanUUID] = runner.StartHeartbeat(runner.HeartbeatConfig{
		Repo:            repo,
		ScanUUID:        scanUUID,
		SessionsDir:     settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
		ProjectUUID:     projectUUID,
		Phase:           string(runner.PhaseDynamicAssessment),
		PhasesPlanned:   []string{string(runner.PhaseDynamicAssessment)},
		StopWhenRowDone: true,
		OnStopRequest:   interruptSelfOnStopRequest,
	})
}

// validateBeforeSchemeProbe checks direct scan-request's store and pinned
// identity before its optional TCP/TLS probe. It creates no scan or log rows;
// begin validates again and captures ownership after the final URL is known.
func (s *directScanSession) validateBeforeSchemeProbe(ctx context.Context) error {
	repo, project, err := acquireDirectScanDB(getDB)
	if err != nil {
		return err
	}
	if repo == nil {
		if s.pinned != "" {
			return fmt.Errorf("pinned scan UUID requires a database to validate ownership")
		}
		return nil
	}
	s.noteStore()
	if s.pinned == "" {
		return nil
	}
	if project == "" {
		project = database.DefaultProjectUUID
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directScanFinalizeBudget)
	defer cancel()
	scan, err := repo.GetScanByUUID(readCtx, s.pinned)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // A new pinned scan will be created by begin.
	}
	if err != nil {
		return fmt.Errorf("validate pinned direct scan before scheme probe: %w", err)
	}
	if scan.ProjectUUID != project {
		return fmt.Errorf("%w: pinned direct scan belongs to another project", database.ErrScanProjectMismatch)
	}
	return nil
}

// begin creates the scan row an input reports into, after the store was
// acquired and before any request goes out (and before an interrupt is
// checked: an interrupted input still gets a row that says so). Once a store is
// selected, creation or identity failures are fatal before any target requests
// or evidence writes. Unpinned, explicitly memory-only inputs need no row.
func (s *directScanSession) begin(ctx context.Context, repo *database.Repository, projectUUID, scanUUID, target, method string, active, passive int) error {
	if repo == nil {
		if s.pinned != "" {
			return fmt.Errorf("pinned scan UUID requires a database to validate ownership")
		}
		return nil
	}
	// Detached and bounded, like the finalizer: a Ctrl-C landing between store
	// acquisition and here must not leave findings stamped with a UUID that
	// has no row.
	rowCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directScanFinalizeBudget)
	defer cancel()
	if projectUUID == "" {
		projectUUID = database.DefaultProjectUUID
	}
	if scope, ok := s.scanScopes[scanUUID]; ok && (scope.db != repo.DB() || scope.project != projectUUID) {
		return fmt.Errorf("direct scan store or project changed during invocation")
	}
	if s.pinned == "" || !s.sharedCreated {
		rowTarget := target
		if s.pinned != "" {
			rowTarget = strings.Join(s.targets, ", ")
		}
		row := database.NewSingleRequestScan(scanUUID, projectUUID, s.name, rowTarget, s.modules, "cli")
		row.Threads = globalConcurrency
		row.Tags = callerTags
		if err := repo.CreateScan(rowCtx, row); err != nil {
			zap.L().Warn("Failed to create scan record", zap.String("scan_uuid", scanUUID), zap.Error(err))
			if !globalSilent {
				fmt.Fprintf(os.Stderr, "%s scan record/log initialization skipped (%v): %s\n",
					terminal.WarnPrefix(), err, scanUUID)
			}
			return fmt.Errorf("initialize direct scan: %w", err)
		}
	}
	// CreateScan is get-or-create. Confirm the stored identity even when a
	// pinned batch already initialized its shared row, and fail closed on a
	// read error. ScanLogger trusts the explicit scope supplied by its caller;
	// it must receive the confirmed row's scope, never a guessed/default store.
	scan, err := repo.GetScanByUUID(rowCtx, scanUUID)
	if err != nil {
		return fmt.Errorf("validate direct scan identity: %w", err)
	}
	if scan.ProjectUUID != projectUUID {
		return fmt.Errorf("%w: direct scan belongs to another project", database.ErrScanProjectMismatch)
	}
	if s.scanScopes == nil {
		s.scanScopes = make(map[string]directScanScope)
	}
	s.scanScopes[scanUUID] = directScanScope{db: repo.DB(), project: projectUUID}
	if s.pinned != "" {
		s.sharedCreated = true
	}
	logger := database.NewScanLogger(repo, scanUUID, scan.ProjectUUID)
	defer logger.Close()
	s.startHeartbeat(repo, scan.ProjectUUID, scanUUID)
	logger.Info("scan", fmt.Sprintf("%s started: %s %s with %d active + %d passive modules", s.name, method, target, active, passive))
	return nil
}

// end completes the row for one finished input on a detached, bounded context:
// on an interrupt the invocation's context is already cancelled, and writing on
// it would leave the row "running" forever. Runs on every exit path that had a
// row, interrupted or not.
func (s *directScanSession) end(ctx context.Context, repo *database.Repository, scanUUID, target string, executor *core.Executor, interrupted bool, execErr error, findings int) error {
	if repo == nil && s.pinned != "" {
		return fmt.Errorf("pinned scan completion requires its validated database")
	}
	if repo == nil || executor == nil {
		return nil
	}
	rep := executor.Report()
	failures := executor.BaselineFailures()
	return s.complete(ctx, repo, scanUUID, target, rep, failures, interrupted, execErr, runner.DirectTargetTally(target, rep, failures), findings)
}

// rejectInput reports an input scope refused, without sending anything: the
// row is created and completed failed with stop_reason no_targets_in_scope, and
// the result names the target and the rule. The command's exit code is decided
// over all inputs (directAdmission.settle).
func (s *directScanSession) rejectInput(ctx context.Context, scanUUID, target, method string, v types.TargetVerdict) (*scanResult, error) {
	repo, projectUUID, err := acquireDirectScanDB(getDB)
	if err != nil {
		return nil, err
	}
	if repo != nil {
		s.noteStore()
	}
	if err := s.begin(ctx, repo, projectUUID, scanUUID, target, method, 0, 0); err != nil {
		return nil, err
	}
	tally := runner.AdmissionTally(types.TargetAdmission{Rejected: []types.TargetVerdict{v}})
	if err := s.complete(ctx, repo, scanUUID, target, core.ExecutionReport{}, nil, false, nil, tally, 0); err != nil {
		return nil, err
	}
	return &scanResult{
		Target:          target,
		Method:          method,
		ScanUUID:        scanUUID,
		Findings:        []*output.ResultEvent{},
		Persisted:       repo != nil,
		StopReason:      database.ReasonNoTargetsInScope,
		TargetsRejected: []types.TargetVerdict{v},
		projectUUID:     projectUUID,
		repo:            repo,
	}, nil
}

// complete finishes one input's row from the run's report and target tally.
func (s *directScanSession) complete(ctx context.Context, repo *database.Repository, scanUUID, target string, rep core.ExecutionReport, failures []core.BaselineFailure, interrupted bool, execErr error, tally database.TargetTally, findings int) error {
	if repo == nil {
		if s.pinned != "" || s.scanScopes[scanUUID].db != nil {
			return fmt.Errorf("direct scan completion requires its validated database")
		}
		return nil
	}
	// A missing capture means begin failed or was bypassed. Never recover by
	// adopting whichever project's row happens to have this UUID now.
	scope, ok := s.scanScopes[scanUUID]
	if !ok || scope.db != repo.DB() {
		return fmt.Errorf("direct scan completion lacks validated store/project scope")
	}
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directScanFinalizeBudget)
	defer cancel()
	scan, err := repo.GetScanByUUID(finalCtx, scanUUID)
	if err != nil {
		return fmt.Errorf("validate direct scan completion: %w", err)
	}
	if scan.ProjectUUID != scope.project {
		return fmt.Errorf("%w: direct scan completion belongs to another project", database.ErrScanProjectMismatch)
	}
	reached := rep.Responded > 0

	completion := runner.DirectScanCompletion(rep, reached, interrupted, execErr, tally)
	if s.pinned != "" {
		s.agg.add(rep, reached, interrupted, execErr, tally)
		completion = runner.DirectScanCompletion(s.agg.rep, s.agg.reached, s.agg.interrupted, s.agg.err, s.agg.tally)
		execErr = s.agg.err
	}
	completion = runner.ApplyRequestBudget(completion, s.budget)
	defer func() {
		if completion.Completeness == database.CompletenessPartial {
			notePartialCompletion(scanUUID, unionPhaseReasons(completion.Phases))
		}
	}()
	if reached || (s.pinned != "" && s.agg.reached) {
		for _, reason := range s.phaseReasons[scanUUID] {
			completion = runner.ApplyDirectPhaseReason(completion, reason)
		}
		for _, code := range s.phaseNotes[scanUUID] {
			completion = runner.ApplyDirectPhaseNote(completion, code)
		}
		if len(config.RateClamps()) > 0 {
			completion = runner.ApplyDirectPhaseNote(completion, database.LimitRateCeiling)
		}
	}

	errMsg := runner.DirectScanErrorMessage(execErr, completion)
	// The write itself is scoped too, closing the read/update race. Only a
	// successful completion is logged or queued for webhook emission.
	if err := repo.CompleteScanWithOutcomeForProject(finalCtx, scope.project, scanUUID, errMsg, completion); err != nil {
		return fmt.Errorf("complete direct scan: %w", err)
	}
	logger := database.NewScanLogger(repo, scanUUID, scope.project)
	defer logger.Close()
	for _, issue := range tally.Rejected {
		logger.Error(string(runner.PhasePreflight), fmt.Sprintf("target %s rejected by scope (%s); nothing sent", issue.Target, issue.Code))
	}
	if !reached && !interrupted && tally.Admitted > 0 {
		detail := "no HTTP answer"
		if len(failures) > 0 {
			detail = failures[0].Class + ": " + failures[0].Detail
		}
		logger.Error("preflight", fmt.Sprintf("target %s did not answer (%s)", target, detail))
	}
	if execErr != nil {
		logger.Error(string(runner.PhaseDynamicAssessment), execErr.Error())
	}

	var outErr error
	if errMsg != "" && completion.StopReason != database.ReasonCancelled {
		outErr = errors.New(errMsg)
	}
	s.noteFinished(repo, scanUUID, webhook.Outcome{Err: outErr, Interrupted: completion.StopReason == database.ReasonCancelled, Target: target})

	status := "completed"
	if errMsg != "" {
		status = "failed: " + errMsg
	}
	line := fmt.Sprintf("%s finished %s: %s, %d finding(s)", s.name, target, status, findings)
	if completion.Completeness == database.CompletenessPartial {
		line += ", partial (" + completion.StopReason + ")"
	}
	logger.Info("scan", line)
	return nil
}
