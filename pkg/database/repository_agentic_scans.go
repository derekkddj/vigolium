package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"
)

// CreateAgenticScan stores a new agent run record. When a row with run.UUID
// already exists, the call is a no-op as long as the existing project_uuid
// matches — this is the get-or-create path used for cross-node sync via
// --scan-uuid. Returns ErrScanProjectMismatch when the existing row belongs
// to a different project. On a same-project UUID collision, submitted metadata
// is ignored.
func (r *Repository) CreateAgenticScan(ctx context.Context, run *AgenticScan) error {
	run.ProjectUUID = defaultProjectUUID(run.ProjectUUID)
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewInsert().Model(run).On("CONFLICT (uuid) DO NOTHING").Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to insert agent run: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 && run.UUID != "" {
			existing := &AgenticScan{}
			query := tx.NewSelect().Model(existing).Column("project_uuid").Where("uuid = ?", run.UUID)
			if r.db.Driver() == driverPostgres {
				query = query.For("UPDATE")
			}
			if getErr := query.Scan(ctx); getErr == nil {
				existingProject := defaultProjectUUID(existing.ProjectUUID)
				if existingProject != run.ProjectUUID {
					return fmt.Errorf("%w: agentic scan %s belongs to project %s, not %s",
						ErrScanProjectMismatch, run.UUID, existingProject, run.ProjectUUID)
				}
				// The same UUID/project is an idempotent no-op; do not validate
				// stale parent metadata or attach any submitted fields.
				return nil
			} else if !errors.Is(getErr, sql.ErrNoRows) {
				return fmt.Errorf("failed to verify existing agent run: %w", getErr)
			}
		}
		if err := checkAgenticParentProject(ctx, tx, run.ProjectUUID, run.ParentAgenticScanUUID, r.db.Driver()); err != nil {
			return err
		}
		return nil
	})
}

// checkAgenticParentProject rejects a known parent run owned by another project.
// Missing parent IDs remain valid soft references for legacy and out-of-band data.
// Callers run this inside the write transaction so the checked owner remains
// stable through admission; PostgreSQL locks a resolved parent row until commit.
func checkAgenticParentProject(ctx context.Context, idb bun.IDB, project, parentUUID, driver string) error {
	if parentUUID == "" {
		return nil
	}
	query := idb.NewSelect().Model((*AgenticScan)(nil)).Column("project_uuid").Where("uuid = ?", parentUUID)
	if driver == driverPostgres {
		query = query.For("UPDATE")
	}
	var owner string
	if err := query.Scan(ctx, &owner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("check agentic parent project: %w", err)
	}
	owner = defaultProjectUUID(owner)
	project = defaultProjectUUID(project)
	if owner != project {
		return fmt.Errorf("%w: agentic parent %s belongs to project %s, not %s",
			ErrScanProjectMismatch, parentUUID, owner, project)
	}
	return nil
}

// AttributeScanToAgenticScan reconciles a native child on success or failure.
// Both rows must exist in the same project. Ownership cannot be reassigned;
// only missing finding parents are filled, preserving historical attribution.
// This does not reconstruct deduplicated occurrences: findings whose original
// scan_uuid belongs to an older run remain there until an occurrence model exists.
func (r *Repository) AttributeScanToAgenticScan(ctx context.Context, scanUUID, agenticScanUUID string) error {
	if scanUUID == "" || agenticScanUUID == "" {
		return nil
	}
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		parent := &AgenticScan{}
		parentQuery := tx.NewSelect().Model(parent).Column("uuid", "project_uuid").Where("uuid = ?", agenticScanUUID)
		if r.db.Driver() == "postgres" {
			parentQuery = parentQuery.For("UPDATE")
		}
		if err := parentQuery.Scan(ctx); err != nil {
			return fmt.Errorf("attribute parent scan: %w", err)
		}
		scan := &Scan{}
		scanQuery := tx.NewSelect().Model(scan).Column("uuid", "project_uuid", "agentic_scan_uuid").Where("uuid = ?", scanUUID)
		if r.db.Driver() == "postgres" {
			scanQuery = scanQuery.For("UPDATE")
		}
		if err := scanQuery.Scan(ctx); err != nil {
			return fmt.Errorf("attribute native scan: %w", err)
		}
		if scan.ProjectUUID != parent.ProjectUUID {
			return fmt.Errorf("%w: native scan %s and parent %s belong to different projects", ErrScanProjectMismatch, scanUUID, agenticScanUUID)
		}
		if scan.AgenticScanUUID != "" && scan.AgenticScanUUID != agenticScanUUID {
			return fmt.Errorf("native scan %s already belongs to another agent run", scanUUID)
		}
		// Refuse malformed cross-project children rather than partially stamping.
		foreign, err := tx.NewSelect().Model((*Finding)(nil)).Where("scan_uuid = ?", scanUUID).
			Where("project_uuid <> ?", scan.ProjectUUID).Exists(ctx)
		if err != nil {
			return fmt.Errorf("validate child findings: %w", err)
		}
		if foreign {
			return fmt.Errorf("%w: native scan has findings in another project", ErrScanProjectMismatch)
		}
		res, err := tx.NewUpdate().Model((*Scan)(nil)).
			Set("agentic_scan_uuid = ?", agenticScanUUID).
			Where("uuid = ?", scanUUID).Where("project_uuid = ?", parent.ProjectUUID).
			Where("(agentic_scan_uuid = '' OR agentic_scan_uuid IS NULL OR agentic_scan_uuid = ?)", agenticScanUUID).Exec(ctx)
		if err != nil {
			return fmt.Errorf("attribute native scan: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return fmt.Errorf("native scan ownership changed during attribution")
		}
		if _, err := tx.NewUpdate().Model((*Finding)(nil)).
			Set("agentic_scan_uuid = ?", agenticScanUUID).
			Where("scan_uuid = ?", scanUUID).Where("project_uuid = ?", parent.ProjectUUID).
			Where("(agentic_scan_uuid = '' OR agentic_scan_uuid IS NULL)").Exec(ctx); err != nil {
			return fmt.Errorf("attribute child findings: %w", err)
		}
		return nil
	})
}

// GetAgenticScan retrieves an agent run by UUID.
func (r *Repository) GetAgenticScan(ctx context.Context, uuid string) (*AgenticScan, error) {
	run := &AgenticScan{}
	err := r.db.NewSelect().Model(run).Where("uuid = ?", uuid).Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent run not found: %w", err)
	}
	return run, nil
}

// UpdateAgenticScan updates an agent run record by UUID. Uses OmitZero so
// callers (SwarmRunner.Run and the API enrichAgenticScanRecord helpers) can
// pass partial structs without zeroing fields they don't intend to touch.
// To explicitly clear a field, use a column-list update via NewUpdate().
func (r *Repository) UpdateAgenticScan(ctx context.Context, run *AgenticScan) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		existing := &AgenticScan{}
		query := tx.NewSelect().Model(existing).Column("project_uuid").Where("uuid = ?", run.UUID)
		if r.db.Driver() == driverPostgres {
			query = query.For("UPDATE")
		}
		if err := query.Scan(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to validate agent run update: %w", err)
		} else if err == nil {
			project := defaultProjectUUID(existing.ProjectUUID)
			if run.ProjectUUID != "" && defaultProjectUUID(run.ProjectUUID) != project {
				return fmt.Errorf("%w: agentic scan %s belongs to project %s, not %s",
					ErrScanProjectMismatch, run.UUID, project, defaultProjectUUID(run.ProjectUUID))
			}
			if run.ParentAgenticScanUUID != "" {
				if err := checkAgenticParentProject(ctx, tx, project, run.ParentAgenticScanUUID, r.db.Driver()); err != nil {
					return err
				}
			}
		}
		if _, err := tx.NewUpdate().Model(run).OmitZero().Where("uuid = ?", run.UUID).Exec(ctx); err != nil {
			return fmt.Errorf("failed to update agent run: %w", err)
		}
		return nil
	})
}

// agenticScanBlobColumns are the agentic_scans columns holding uncapped
// JSON/text blobs — a single autopilot run's result_json is routinely
// megabytes. A list of 100 runs otherwise transfers, allocates and
// deserializes all of them so the handler can throw them away building a DTO
// of counters and timestamps. Mirrors recordBodyColumns / findingBodyColumns.
//
// Stated as an exclusion rather than as the complementary include list on
// purpose: the model has 40-odd columns, so an include list has to be updated
// for every column added or that column silently reads back as its zero value
// in every list view, with no compile-time or test signal.
var agenticScanBlobColumns = []string{
	"input_raw", "prompt_sent", "agent_raw_output",
	"attack_plan", "triage_result", "result_json",
}

// ListAgenticScanSummaries is ListAgenticScans with agenticScanBlobColumns
// dropped — same rows, same order, same total. Use it for any view that
// renders a run rather than replaying it; the omitted fields come back empty,
// so a caller that serializes the *AgenticScan verbatim (the `--json` CLI
// paths) must keep using ListAgenticScans.
func (r *Repository) ListAgenticScanSummaries(ctx context.Context, projectUUID string, mode string, limit, offset int) ([]*AgenticScan, int64, error) {
	return r.listAgenticScans(ctx, projectUUID, mode, nil, nil, limit, offset, agenticScanBlobColumns)
}

// AgenticScanStatusByUUID returns just the status column for a run.
//
// It exists for the SSE log follower, which asks "is this run finished yet?"
// twice a second for as long as a client watches: doing that through
// GetAgenticScan reads the run's full row — blobs included — so N followers on
// a finished-but-still-watched autopilot run pull 2N megabyte-scale reads per
// second out of the database to learn one short string.
func (r *Repository) AgenticScanStatusByUUID(ctx context.Context, uuid string) (string, error) {
	var status string
	err := r.db.NewSelect().
		Model((*AgenticScan)(nil)).
		Column("status").
		Where("uuid = ?", uuid).
		Scan(ctx, &status)
	if err != nil {
		return "", fmt.Errorf("agent run not found: %w", err)
	}
	return status, nil
}

// UpdateAgenticScanStorageURL sets the storage_url field on an agentic scan record.
func (r *Repository) UpdateAgenticScanStorageURL(ctx context.Context, agenticScanUUID, storageURL string) error {
	_, err := r.db.NewUpdate().Model((*AgenticScan)(nil)).
		Set("storage_url = ?", storageURL).
		Where("uuid = ?", agenticScanUUID).
		Exec(ctx)
	return err
}

// ListAgenticScans returns paginated agent runs for a project, ordered by
// created_at DESC, with every column populated. Callers that only render the
// run should prefer ListAgenticScanSummaries.
func (r *Repository) ListAgenticScans(ctx context.Context, projectUUID string, mode string, limit, offset int) ([]*AgenticScan, int64, error) {
	return r.listAgenticScans(ctx, projectUUID, mode, nil, nil, limit, offset, nil)
}

// ListAgenticScansCreatedBetween is ListAgenticScans restricted to runs
// created within [from, to]; a nil bound is open.
func (r *Repository) ListAgenticScansCreatedBetween(ctx context.Context, projectUUID string, from, to *time.Time, limit int) ([]*AgenticScan, error) {
	runs, _, err := r.listAgenticScans(ctx, projectUUID, "", from, to, limit, 0, nil)
	return runs, err
}

// listAgenticScans backs the list variants. A nil exclude slice selects every
// column; otherwise the named ones are left out. A nil from/to bound on
// created_at is open.
func (r *Repository) listAgenticScans(ctx context.Context, projectUUID, mode string, from, to *time.Time, limit, offset int, exclude []string) ([]*AgenticScan, int64, error) {
	projectUUID = defaultProjectUUID(projectUUID)
	if limit <= 0 {
		limit = 50
	}

	filter := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.Where("project_uuid = ?", projectUUID).
			Where("(parent_run_uuid IS NULL OR parent_run_uuid = '')")
		if mode != "" {
			q = q.Where("mode = ?", mode)
		}
		if from != nil {
			q = q.Where("created_at >= ?", *from)
		}
		if to != nil {
			q = q.Where("created_at <= ?", *to)
		}
		return q
	}
	total, countErr := filter(r.db.NewSelect().Model((*AgenticScan)(nil))).Count(ctx)

	var runs []*AgenticScan
	q := filter(r.db.NewSelect().Model(&runs)).
		OrderExpr("created_at DESC").
		Limit(int64(limit)).
		Offset(int64(offset))
	if len(exclude) > 0 {
		q = q.ExcludeColumn(exclude...)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("failed to list agent runs: %w", err)
	}
	if countErr != nil {
		total = int64(len(runs))
	}
	return runs, total, nil
}

// GetChildAgenticScans returns agent runs whose ParentAgenticScanUUID matches the given UUID.
func (r *Repository) GetChildAgenticScans(ctx context.Context, parentUUID string) ([]*AgenticScan, error) {
	var runs []*AgenticScan
	err := r.db.NewSelect().Model(&runs).
		Where("parent_run_uuid = ?", parentUUID).
		OrderExpr("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get child agent runs: %w", err)
	}
	return runs, nil
}

// TerminalAgenticScanStatuses is the authoritative set of agentic_scans.status
// values meaning the run has finished, used by the SSE log follower and other
// status readers. Add new terminal statuses here, not at call sites. Terminal
// status alone is not permission to expire evidence: runs can be resumed and
// the catalog may still have retained artifacts and dependent records.
var TerminalAgenticScanStatuses = []string{
	"completed",
	"completed_with_errors",
	"completed_with_warnings",
	"failed",
	"cancelled",
	"timeout",
	"budget_exhausted",
	"error",
}

// IsTerminalAgenticScanStatus reports whether an agentic_scans.status value
// is one of TerminalAgenticScanStatuses.
func IsTerminalAgenticScanStatus(status string) bool {
	return slices.Contains(TerminalAgenticScanStatuses, status)
}

// CompletedAgenticScanStatuses are the terminal statuses of a run that ran to
// the end: cleanly, degraded, or with some drivers failed. Code that means
// "finished successfully" should match this set, not the literal "completed",
// or degraded runs silently drop out.
var CompletedAgenticScanStatuses = []string{
	"completed",
	"completed_with_warnings",
	"completed_with_errors",
}

// CompletedAgenticScanStatus is the status of a run that finished without an
// error. A degraded run (audit failed to start, discovery failed, the model
// never called a tool...) is "completed_with_warnings", so it can be told
// apart from a clean pass. Every writer - server handlers, the CLI finalizers,
// the swarm runner - goes through here so one outcome gets one status.
func CompletedAgenticScanStatus(degraded bool) string {
	if degraded {
		return "completed_with_warnings"
	}
	return "completed"
}

// Agentic-run statuses beyond the completed set. "timeout" and
// "budget_exhausted" are runs that ran but stopped at a limit (the CLI exits 5
// for them); "cancelled" is an interrupt; "failed" an error.
const (
	AgenticScanStatusTimeout         = "timeout"
	AgenticScanStatusBudgetExhausted = "budget_exhausted"
	AgenticScanStatusCancelled       = "cancelled"
	AgenticScanStatusFailed          = "failed"
)

// AgenticRunEnd describes how an agentic run ended, for AgenticRunStatus.
type AgenticRunEnd struct {
	// Err is the run's error, nil on a clean finish. A time or budget stop
	// still counts as that stop when Err is set: the loop often reports the
	// cancellation it caused as an error.
	Err error
	// TimedOut: the wall-clock budget (--max-duration) fired.
	TimedOut bool
	// BudgetExhausted: a command, token or cost budget fired.
	BudgetExhausted bool
	// Cancelled: an interrupt (Ctrl-C, SIGTERM) stopped the run.
	Cancelled bool
	// Degraded: the run finished but with warnings (see CompletedAgenticScanStatus).
	Degraded bool
	// FailedDrivers/TotalDrivers: a multi-driver run (audit), see
	// MultiDriverAgenticScanStatus. Zero TotalDrivers means single-driver.
	FailedDrivers, TotalDrivers int
}

// AgenticRunStatus is the agentic_scans.status for a finished run. It is the
// one place that decides it, for the CLI finalizers and the swarm runner alike,
// so a timed-out run is "timeout" whichever path wrote it (it used to be
// "failed" in the database while the JSON said "timed_out").
func AgenticRunStatus(e AgenticRunEnd) string {
	switch {
	case e.Cancelled:
		return AgenticScanStatusCancelled
	case e.TimedOut:
		return AgenticScanStatusTimeout
	case e.BudgetExhausted:
		return AgenticScanStatusBudgetExhausted
	case e.TotalDrivers > 0:
		if e.Err != nil && e.FailedDrivers == 0 {
			return AgenticScanStatusFailed
		}
		return MultiDriverAgenticScanStatus(e.FailedDrivers, e.TotalDrivers)
	case e.Err != nil:
		return AgenticScanStatusFailed
	}
	return CompletedAgenticScanStatus(e.Degraded)
}

// MultiDriverAgenticScanStatus is the parent status of a run made of several
// drivers: "failed" when every driver failed (nothing ran, so
// "completed_with_errors" overstated it), "completed_with_errors" when some
// did, "completed" otherwise.
func MultiDriverAgenticScanStatus(failed, total int) string {
	switch {
	case failed == 0:
		return "completed"
	case failed >= total:
		return "failed"
	default:
		return "completed_with_errors"
	}
}

// ErrUnsafeAgenticScanRetention means the legacy unscoped sweep would detach
// artifacts, findings, child runs, or durable sections from their catalog.
var ErrUnsafeAgenticScanRetention = errors.New("automatic agent catalog deletion is disabled: scoped artifact and dependency retention is required")

// DeleteOldAgenticScans fails closed without deleting catalog rows. Terminal
// status and age alone do not make a run safe to delete: it can be resumed and
// retained evidence and dependent rows still refer to its UUID. Keep this API
// compatible until an opt-in, scoped retention workflow can coordinate artifacts
// and transactionally handle database dependencies.
//
// Deprecated: use an explicitly scoped, dependency-aware retention workflow.
func (r *Repository) DeleteOldAgenticScans(ctx context.Context, olderThan time.Duration) (int, error) {
	return 0, ErrUnsafeAgenticScanRetention
}
