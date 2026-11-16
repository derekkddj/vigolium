package database

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// ScanHeartbeat is one liveness beat of a running scan, written onto its row.
type ScanHeartbeat struct {
	// ProjectUUID, when supplied, conditions the write on the captured owner.
	// Empty preserves the legacy unscoped repository method contract.
	ProjectUUID string
	At          time.Time
	// Phase is the phase running now; "" between phases (and on the final beat)
	// clears current_phase.
	Phase string
	// RequestsSent is the scan's requests so far, written to total_requests.
	// Nil leaves total_requests untouched, for a caller that does not count.
	RequestsSent *int64
	PID          int
	Host         string
}

// UpdateScanHeartbeat stamps a running scan's row with its latest beat: one
// small UPDATE, by uuid, touching only the liveness columns (and
// total_requests). updated_at is deliberately left alone — it is the row's
// edit time, and a heartbeat every few seconds would make it meaningless as
// one; heartbeat_at is the liveness column.
//
// Only a row still "running" is touched: a late beat must never re-stamp a
// finalized row. updated reports whether a row was written, which is how a
// heartbeat learns its scan was finalized by someone else. stop is the stop
// request pending on the row (nil when none), returned by the same statement.
func (r *Repository) UpdateScanHeartbeat(ctx context.Context, scanUUID string, hb ScanHeartbeat) (updated bool, stop *ScanStopRequest, err error) {
	q := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("heartbeat_at = ?", hb.At).
		Where("uuid = ?", scanUUID).
		Where("status = ?", "running")
	if hb.ProjectUUID != "" {
		q = q.Where("project_uuid = ?", hb.ProjectUUID)
	}
	if hb.Phase == "" {
		q = q.Set("current_phase = NULL")
	} else {
		q = q.Set("current_phase = ?", hb.Phase)
	}
	if hb.PID > 0 {
		q = q.Set("pid = ?", hb.PID)
	}
	if hb.Host != "" {
		q = q.Set("runner_host = ?", hb.Host)
	}
	if hb.RequestsSent != nil {
		q = q.Set("total_requests = ?", *hb.RequestsSent)
	}
	var rows []struct {
		At *time.Time `bun:"stop_requested_at"`
		By *string    `bun:"stop_requested_by"`
	}
	if err := q.Returning("stop_requested_at, stop_requested_by").Scan(ctx, &rows); err != nil {
		return false, nil, err
	}
	if len(rows) == 0 {
		return false, nil, nil
	}
	if at := rows[0].At; at != nil && !at.IsZero() {
		stop = &ScanStopRequest{At: *at}
		if rows[0].By != nil {
			stop.By = *rows[0].By
		}
	}
	return true, stop, nil
}

// LastScanLogTimes returns, per scan, the newest scan_logs.created_at — one
// GROUP BY over every listed scan, for liveness readers that list many scans at
// once. Scans with no log lines are absent from the map.
//
// projectUUIDs narrows the read to the projects the scans belong to, which is
// what lets the (project_uuid, scan_uuid) index serve it; pass none to read
// across projects (a stateless read of a standalone file).
func (r *Repository) LastScanLogTimes(ctx context.Context, projectUUIDs, scanUUIDs []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(scanUUIDs))
	if len(scanUUIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		ScanUUID string    `bun:"scan_uuid"`
		Last     time.Time `bun:"last_at"`
	}
	q := r.db.NewSelect().
		TableExpr("scan_logs").
		ColumnExpr("scan_uuid").
		ColumnExpr("MAX(created_at) AS last_at").
		Where("scan_uuid IN (?)", bun.List(scanUUIDs)).
		GroupExpr("scan_uuid")
	if len(projectUUIDs) > 0 {
		q = q.Where("project_uuid IN (?)", bun.List(projectUUIDs))
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !row.Last.IsZero() {
			out[row.ScanUUID] = row.Last
		}
	}
	return out, nil
}

// ListRunningScans returns every scan row whose stored status is still
// "running", newest first — the candidates a reaper checks for liveness. An
// empty projectUUID reads across projects (a stateless read of a standalone
// file), like ListScans.
func (r *Repository) ListRunningScans(ctx context.Context, projectUUID string) ([]*Scan, error) {
	var scans []*Scan
	q := r.db.NewSelect().
		Model(&scans).
		Where("status = ?", "running").
		OrderExpr("created_at DESC")
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if err := q.Scan(ctx); err != nil {
		return nil, err
	}
	return scans, nil
}

// ReapAbandonedScan finalizes a scan whose row still says "running" but whose
// process is gone (the caller's liveness verdict): status failed, completeness
// partial, stop_reason abandoned, and an error_message appending the last write
// to any existing diagnostics. lastWriteAt is the last observed write, NOT the
// exact time the process died. finished_at uses that observation when known,
// else now; phase_outcomes, counts, and stored evidence are left as they are.
//
// The caller must supply the database-loaded scan it checked for liveness. One
// atomic UPDATE checks its captured project, PID, host, start, heartbeat, and edit
// time as well as the running status: an advanced heartbeat, reassignment, restart,
// resume edit, or finalization makes this a no-op. The project is never defaulted
// or omitted.
// reaped reports whether this call wrote the row; this method does not infer
// abandonment from staleness or run automatically on startup.
func (r *Repository) ReapAbandonedScan(ctx context.Context, scan *Scan, lastWriteAt time.Time) (reaped bool, err error) {
	if scan == nil {
		return false, nil
	}
	finishedAt := lastWriteAt
	msg := "abandoned: the scan's process stopped without finalizing its row (no liveness signal ever written)"
	if finishedAt.IsZero() {
		finishedAt = time.Now()
	} else {
		msg = "abandoned: the scan's process stopped without finalizing its row (last write " + finishedAt.UTC().Format(time.RFC3339) + ")"
	}
	durationMs := int64(0)
	if !scan.StartedAt.IsZero() && finishedAt.After(scan.StartedAt) {
		durationMs = finishedAt.Sub(scan.StartedAt).Milliseconds()
	}
	q := r.db.NewUpdate().
		Model((*Scan)(nil)).
		Set("status = ?", "failed").
		// Append the CURRENT diagnostics inside the UPDATE, not scan.ErrorMessage:
		// an error written since the liveness read must not be lost.
		Set("error_message = CASE WHEN COALESCE(error_message, '') = '' THEN ? ELSE error_message || ? END", msg, "\n"+msg).
		Set("completeness = ?", CompletenessPartial).
		Set("stop_reason = ?", ReasonAbandoned).
		Set("finished_at = ?", finishedAt).
		Set("duration_ms = ?", durationMs).
		Set("current_phase = NULL").
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", scan.UUID).
		Where("project_uuid = ?", scan.ProjectUUID).
		Where("status = ?", "running").
		// These nullzero fields load SQL NULL as Go's zero value on legacy rows.
		Where("COALESCE(pid, 0) = ?", scan.PID).
		Where("COALESCE(runner_host, '') = ?", scan.RunnerHost)
	q = scanLivenessTimeEqual(q, r.db.Driver(), "started_at", scan.StartedAt)
	// Pause/resume edits updated_at even before a resumed runner sends a beat.
	q = scanLivenessTimeEqual(q, r.db.Driver(), "updated_at", scan.UpdatedAt)
	if scan.HeartbeatAt == nil {
		q = q.Where("heartbeat_at IS NULL")
	} else {
		q = scanLivenessTimeEqual(q, r.db.Driver(), "heartbeat_at", *scan.HeartbeatAt)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// scanLivenessTimeEqual compares database-loaded timestamps without dropping
// precision. column is a trusted internal identifier. PostgreSQL uses native
// timestamps with Bun's time binding; SQLite needs identical text for SQL's
// CURRENT_TIMESTAMP and Bun writes (UTC suffix and fractional trailing zeros).
// Do not use datetime/julianday: rounding could accept an advanced heartbeat.
func scanLivenessTimeEqual(q *bun.UpdateQuery, driver, column string, at time.Time) *bun.UpdateQuery {
	if driver != driverSQLite {
		return q.Where(column+" = ?", at.UTC())
	}
	utc := "replace(" + column + ", '+00:00', '')"
	exact := "(CASE WHEN instr(" + utc + ", '.') > 0 THEN rtrim(rtrim(" + utc + ", '0'), '.') ELSE " + utc + " END)"
	return q.Where(exact+" = ?", at.UTC().Format("2006-01-02 15:04:05.999999999"))
}
