package database

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// FindingWrite bundles the arguments needed to persist a single finding,
// allowing a batch of findings to be coalesced into one transaction.
// See Repository.SaveFindingsBatch.
type FindingWrite struct {
	Event           *output.ResultEvent
	HTTPRecordUUIDs []string
	ScanUUID        string
	ProjectUUID     string
}

// SaveFinding stores a vulnerability finding linked to HTTP records by UUIDs.
// Uses INSERT ON CONFLICT for atomic dedup when finding_hash is non-empty.
func (r *Repository) SaveFinding(ctx context.Context, event *output.ResultEvent, httpRecordUUIDs []string, scanUUID string, projectUUID string) error {
	_, err := r.SaveFindingInserted(ctx, event, httpRecordUUIDs, scanUUID, projectUUID)
	return err
}

// SaveFindingInserted is SaveFinding reporting whether a NEW finding row was
// written (false on a dedup-append to an existing finding), so a caller can
// notify only on genuinely new findings.
func (r *Repository) SaveFindingInserted(ctx context.Context, event *output.ResultEvent, httpRecordUUIDs []string, scanUUID string, projectUUID string) (bool, error) {
	if event == nil {
		return false, fmt.Errorf("invalid ResultEvent")
	}

	finding := &Finding{
		HTTPRecordUUIDs: append([]string(nil), httpRecordUUIDs...),
		ScanUUID:        scanUUID,
		ProjectUUID:     defaultProjectUUID(projectUUID),
	}
	if err := finding.FromResultEvent(event); err != nil {
		return false, fmt.Errorf("failed to convert finding: %w", err)
	}

	inserted, err := r.saveFindingTx(ctx, finding, httpRecordUUIDs)
	if err != nil {
		return false, err
	}
	r.emitFindingCommitted(finding, inserted)
	return inserted, nil
}

// SaveFindingsBatch persists a batch of findings in a single transaction,
// coalescing what would otherwise be one transaction (and fsync) per finding.
// Findings are converted up front so a conversion error skips just that finding
// rather than aborting the batch. If the transaction itself fails (e.g. a
// database-level error), every finding is retried individually so one bad
// finding can't drop the rest — preserving the error isolation of per-finding
// SaveFinding while keeping the fast path a single transaction.
func (r *Repository) SaveFindingsBatch(ctx context.Context, writes []FindingWrite) error {
	return firstResultErr(r.SaveFindingsBatchResults(ctx, writes))
}

// SaveFindingsBatchResults is SaveFindingsBatch with the per-finding outcomes,
// aligned 1:1 with writes — results[i] describes writes[i], including the entries
// this method itself rejects (a nil Event or one that will not convert, each
// carrying its own Err at its own index).
//
// The alignment is what makes a partial batch countable. SaveFindingsBatch
// collapses to a single error, so FindingWriter could only ever attribute a
// failure to the whole batch: one bad finding in a batch of sixty-four was
// reported as sixty-four dropped findings, and a transaction that failed and then
// succeeded on retry for all but one was reported the same way. Operators read
// those counters to decide whether a scan's results are complete.
func (r *Repository) SaveFindingsBatchResults(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
	results := make([]FindingSaveResult, len(writes))
	if len(writes) == 0 {
		return results
	}

	// findings holds only the convertible entries; index maps each back to its
	// position in writes so the core's aligned result can be scattered home.
	findings := make([]*Finding, 0, len(writes))
	index := make([]int, 0, len(writes))
	for i := range writes {
		w := &writes[i]
		if w.Event == nil {
			results[i].Err = fmt.Errorf("invalid ResultEvent")
			continue
		}
		f := &Finding{
			HTTPRecordUUIDs: w.HTTPRecordUUIDs,
			ScanUUID:        w.ScanUUID,
			ProjectUUID:     defaultProjectUUID(w.ProjectUUID),
		}
		if err := f.FromResultEvent(w.Event); err != nil {
			zap.L().Warn("SaveFindingsBatch: skipping unconvertible finding", zap.Error(err))
			results[i].Err = fmt.Errorf("failed to convert finding: %w", err)
			continue
		}
		findings = append(findings, f)
		index = append(index, i)
	}
	if len(findings) == 0 {
		return results
	}

	for j, res := range r.saveFindingsBatchCore(ctx, findings) {
		results[index[j]] = res
	}
	return results
}

// saveFindingIDB inserts a single finding using the given bun.IDB, which may be
// the shared *DB (single write) or a bun.Tx (batched write). The dedup/append
// and junction logic is identical in both cases. Returns inserted=true only when
// a new finding row was written (false on a dedup-append to an existing finding),
// so callers fire the OnFindingSaved hook exactly once per genuinely new finding.
func (r *Repository) saveFindingIDB(ctx context.Context, idb bun.IDB, finding *Finding, httpRecordUUIDs []string) (bool, error) {
	if err := checkAgenticParentProject(ctx, idb, finding.ProjectUUID, finding.AgenticScanUUID, r.db.Driver()); err != nil {
		return false, err
	}
	if err := checkFindingScanProject(ctx, idb, finding.ProjectUUID, finding.ScanUUID, r.db.Driver()); err != nil {
		return false, err
	}
	// Missing records are soft references (imports can arrive out of order), but
	// an existing record owned by another project must never become proof here.
	refs := append(append([]string{}, httpRecordUUIDs...), finding.OriginRecordUUID)
	if err := checkFindingRecordProjects(ctx, idb, finding.ProjectUUID, refs); err != nil {
		return false, err
	}
	finding.HTTPRecordUUIDs = mergeUniqueStrings(nil, httpRecordUUIDs)
	httpRecordUUIDs = finding.HTTPRecordUUIDs
	// Cap fresh inserts without discarding the original candidates: on conflict,
	// duplicates of the survivor must be removed BEFORE selecting the sample.
	// Record identities remain uncapped.
	candidate := *finding
	candidate.AdditionalEvidence = appendUniqueEvidence(nil, buildEvidence(finding.Request, finding.Response), finding.AdditionalEvidence...)
	// Atomic dedup: INSERT with conflict resolution on finding_hash.
	// If a duplicate hash exists, the row is silently skipped.
	if finding.LastSeenAt == nil {
		seen := finding.FoundAt
		if seen.IsZero() {
			seen = time.Now()
		}
		finding.LastSeenAt = &seen
	}
	var res sql.Result
	var err error
	if finding.FindingHash != "" {
		res, err = idb.NewInsert().Model(&candidate).
			On("CONFLICT (project_uuid, finding_hash) DO NOTHING").
			Exec(ctx)
	} else {
		res, err = idb.NewInsert().Model(&candidate).Exec(ctx)
	}
	if err != nil {
		return false, fmt.Errorf("failed to insert finding: %w", err)
	}

	// If ON CONFLICT fired, no row was inserted — append records and evidence to existing finding
	if finding.FindingHash != "" {
		if n, _ := res.RowsAffected(); n == 0 {
			if err := r.appendRecordsToFinding(ctx, idb, finding); err != nil {
				return false, err
			}
			return false, r.persistFindingEvidence(ctx, idb, finding)
		}
	}

	// Preserve Bun-populated defaults (timestamps, lifecycle, etc.) as well as
	// the assigned ID on a fresh insert, just as inserting the caller's model did.
	*finding = candidate
	// A finding row without its evidence links is a finding whose proof cannot be
	// resolved, so surface the failure rather than committing a half-written one.
	// Inside a transaction this rolls the row back with it.
	if err := r.insertFindingRecords(ctx, idb, finding.ID, httpRecordUUIDs); err != nil {
		return false, err
	}
	if err := recordFindingObservation(ctx, idb, finding.ProjectUUID, finding.ID, finding.FindingHash, finding.ScanUUID); err != nil {
		return false, err
	}
	if err := r.persistFindingEvidence(ctx, idb, finding); err != nil {
		return false, err
	}

	return true, nil
}

// saveFindingTx is saveFindingIDB in its own transaction, for the single-finding
// paths: the finding row, its evidence links and its observation commit
// together or not at all.
func (r *Repository) saveFindingTx(ctx context.Context, finding *Finding, httpRecordUUIDs []string) (bool, error) {
	if err := prepareFindingEvidence(finding); err != nil {
		return false, err
	}
	snapshot := *finding
	var inserted bool
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		var err error
		inserted, err = r.saveFindingIDB(ctx, tx, finding, httpRecordUUIDs)
		return err
	})
	if err != nil {
		*finding = snapshot
		return false, err
	}
	return inserted, nil
}

// SaveFindingDirect inserts a pre-built Finding directly (without ResultEvent conversion).
// Uses INSERT ON CONFLICT for atomic dedup when finding_hash is non-empty.
func (r *Repository) SaveFindingDirect(ctx context.Context, finding *Finding) error {
	_, err := r.SaveFindingReported(ctx, finding)
	return err
}

// SaveFindingReported is SaveFindingDirect that additionally reports whether a
// new finding row was inserted (true) vs collapsed into an existing finding by
// dedup (false). The autopilot report_finding tool uses it so its run counter
// only tallies distinct findings.
func (r *Repository) SaveFindingReported(ctx context.Context, finding *Finding) (bool, error) {
	if finding == nil {
		return false, fmt.Errorf("invalid Finding")
	}

	finding.ProjectUUID = defaultProjectUUID(finding.ProjectUUID)

	inserted, err := r.saveFindingTx(ctx, finding, finding.HTTPRecordUUIDs)
	if err != nil {
		return false, err
	}
	r.emitFindingCommitted(finding, inserted)
	return inserted, nil
}

// FindingSaveResult reports the outcome of persisting one finding in a batched
// direct save, aligned by index with the input slice passed to
// SaveFindingsDirectBatch.
type FindingSaveResult struct {
	Inserted bool  // a new finding row was written (false on a dedup-append to an existing finding)
	Err      error // non-nil if this finding failed to save
}

// SaveFindingsDirectBatch persists a batch of pre-built findings in a single
// transaction — the batch analogue of SaveFindingDirect, used by bulk importers
// to coalesce what would otherwise be one transaction (and fsync) per finding.
// The returned slice is aligned with the input; the top-level error is the first
// per-finding error, if any.
func (r *Repository) SaveFindingsDirectBatch(ctx context.Context, findings []*Finding) ([]FindingSaveResult, error) {
	for _, f := range findings {
		if f != nil {
			f.ProjectUUID = defaultProjectUUID(f.ProjectUUID)
		}
	}
	results := r.saveFindingsBatchCore(ctx, findings)
	return results, firstResultErr(results)
}

// saveFindingsBatchCore persists pre-built findings in one transaction, retrying
// each finding individually if the transaction fails so one bad finding can't
// drop the rest, and firing new-finding and occurrence hooks only after commit
// so a mirror never sees a rolled-back finding. nil entries are tolerated (zero-value
// result). The returned slice is aligned with the input. This is the shared
// engine behind SaveFindingsBatch (which adapts []FindingWrite) and
// SaveFindingsDirectBatch (pre-built []*Finding); callers own input conversion
// and ProjectUUID defaulting.
func (r *Repository) saveFindingsBatchCore(ctx context.Context, findings []*Finding) []FindingSaveResult {
	results := make([]FindingSaveResult, len(findings))
	if len(findings) == 0 {
		return results
	}

	// Prepare owned receipts before the transaction. Keep snapshots so a rolled
	// back Bun-assigned ID/default cannot poison the per-finding retry.
	snapshots := make([]Finding, len(findings))
	for i, f := range findings {
		if f == nil {
			continue
		}
		if err := prepareFindingEvidence(f); err != nil {
			results[i].Err = err
			continue
		}
		snapshots[i] = *f
	}
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for i, f := range findings {
			if f == nil || results[i].Err != nil {
				continue
			}
			inserted, err := r.saveFindingIDB(ctx, tx, f, f.HTTPRecordUUIDs)
			if err != nil {
				return err
			}
			results[i].Inserted = inserted
		}
		return nil
	})
	if err == nil {
		for i, f := range findings {
			if f != nil && results[i].Err == nil {
				r.emitFindingCommitted(f, results[i].Inserted)
			}
		}
		return results
	}

	zap.L().Warn("saveFindingsBatchCore: transaction failed, retrying findings individually", zap.Error(err))
	for i, f := range findings {
		if f == nil || results[i].Err != nil {
			continue
		}
		*f = snapshots[i]
		results[i] = FindingSaveResult{}
		inserted, e := r.saveFindingTx(ctx, f, f.HTTPRecordUUIDs)
		results[i].Inserted = inserted
		results[i].Err = e
		if e == nil {
			r.emitFindingCommitted(f, inserted)
		}
	}
	return results
}

// emitFindingCommitted keeps new-row accounting separate from occurrence
// notifications. Snapshot before invoking the legacy hook so even a consumer
// modifying that model cannot change the occurrence handed to another consumer.
// No receipt/manifest hydration is performed: doing so would turn a small later
// occurrence into the survivor's entire history, including unrelated bodies.
func (r *Repository) emitFindingCommitted(f *Finding, inserted bool) {
	var occurrence *Finding
	if r.OnFindingOccurrenceSaved != nil {
		snapshot := *f
		snapshot.HTTPRecordUUIDs = append([]string(nil), f.HTTPRecordUUIDs...)
		snapshot.Tags = append([]string(nil), f.Tags...)
		snapshot.MatchedAt = append([]string(nil), f.MatchedAt...)
		snapshot.ExtractedResults = append([]string(nil), f.ExtractedResults...)
		snapshot.AdditionalEvidence = append([]string(nil), f.AdditionalEvidence...)
		snapshot.Evidence = evidence.CloneEntries(f.Evidence)
		if f.InsertionPoint != nil {
			point := *f.InsertionPoint
			snapshot.InsertionPoint = &point
		}
		if f.Verification != nil {
			verification := *f.Verification
			snapshot.Verification = &verification
		}
		if f.VerifiedAt != nil {
			at := *f.VerifiedAt
			snapshot.VerifiedAt = &at
		}
		if f.StatusUpdatedAt != nil {
			at := *f.StatusUpdatedAt
			snapshot.StatusUpdatedAt = &at
		}
		occurrence = &snapshot
	}
	if inserted {
		r.emitFindingSaved(f)
	}
	if occurrence != nil {
		r.OnFindingOccurrenceSaved(occurrence)
	}
}

// firstResultErr returns the first non-nil per-finding error in a batch result,
// collapsing the aligned results into the single-error contract used by callers
// (e.g. SaveFindingsBatch) that don't need per-finding outcomes.
func firstResultErr(results []FindingSaveResult) error {
	for i := range results {
		if results[i].Err != nil {
			return results[i].Err
		}
	}
	return nil
}

// insertFindingRecords batch-inserts finding↔record junction rows in a single
// statement using the given bun.IDB (the shared *DB or a transaction).
// It returns the insert error instead of only logging it: a finding whose
// junction rows failed to write looks complete in the findings table while its
// evidence links are missing, and the caller could not tell.
func (r *Repository) insertFindingRecords(ctx context.Context, idb bun.IDB, findingID int64, recordUUIDs []string) error {
	if len(recordUUIDs) == 0 {
		return nil
	}

	// Driver is a property of the connection, identical for *DB and any tx.
	postgres := r.db.Driver() == "postgres"

	var b strings.Builder
	if postgres {
		b.WriteString("INSERT INTO finding_records (finding_id, record_uuid) VALUES ")
	} else {
		b.WriteString("INSERT OR IGNORE INTO finding_records (finding_id, record_uuid) VALUES ")
	}
	args := make([]interface{}, 0, len(recordUUIDs)*2)
	for i, uuid := range recordUUIDs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("(?, ?)")
		args = append(args, findingID, uuid)
	}
	if postgres {
		b.WriteString(" ON CONFLICT DO NOTHING")
	}
	if _, err := idb.ExecContext(ctx, b.String(), args...); err != nil {
		zap.L().Warn("Failed to insert finding_records",
			zap.Int64("finding_id", findingID),
			zap.Error(err))
		return fmt.Errorf("insert finding_records for finding %d: %w", findingID, err)
	}
	return nil
}

// appendRecordsToFinding looks up an existing finding by (project, hash) and appends new
// record UUIDs and additional evidence (request/response pair) to it. The lookup is
// project-scoped so evidence from one project is never merged into another project's
// finding, even when both share a finding_hash.
//
// A re-detection also updates what the later scan says about the issue (see
// recordRedetectionTx): last_seen_at, the latest severity/confidence/description,
// and a `fixed` finding reopens.
func (r *Repository) appendRecordsToFinding(ctx context.Context, idb bun.IDB, incoming *Finding) error {
	projectUUID, findingHash, scanUUID := incoming.ProjectUUID, incoming.FindingHash, incoming.ScanUUID
	evidence := buildEvidence(incoming.Request, incoming.Response)
	// Load the survivor's primary pair to deduplicate all incoming supporting
	// pairs and fill inline proof only when the entire historic pair is empty.
	existing := &Finding{}
	sel := idb.NewSelect().Model(existing).
		Column("id", "http_record_uuids", "additional_evidence", "status",
			"description", "remediation", "cwe_id", "cvss_score", "origin_record_uuid", "agentic_scan_uuid", "evidence_status").
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).
		Where("finding_hash = ?", findingHash)
	if evidence != "" || len(incoming.AdditionalEvidence) > 0 {
		sel = sel.Column("request", "response")
	}
	if r.db.Driver() == "postgres" {
		// Serialize read/union/write appenders on the survivor. Transactions alone
		// do not prevent lost supporting pairs under PostgreSQL READ COMMITTED.
		sel = sel.For("UPDATE")
	}
	if err := sel.Scan(ctx); err != nil {
		return fmt.Errorf("failed to look up existing finding: %w", err)
	}

	// INSERT ... DO NOTHING may leave incoming.ID unset or stale. Report the
	// canonical survivor, never the id of the rejected candidate.
	incoming.ID = existing.ID
	merged, err := syncFindingRecordRefs(ctx, idb, existing.ID, incoming.HTTPRecordUUIDs)
	if err != nil {
		return err
	}
	// A re-detection is an observation too: without it a finding first seen by
	// an earlier scan would look absent from every later scan that found it again.
	if err := recordFindingObservation(ctx, idb, projectUUID, existing.ID, findingHash, scanUUID); err != nil {
		return err
	}

	q, reopened := recordRedetectionTx(idb, existing.ID, existing.Status, incoming)
	q = q.Set("http_record_uuids = ?", merged)
	if reopened != nil {
		if _, err := idb.NewInsert().Model(reopened).Exec(ctx); err != nil {
			return fmt.Errorf("record reopen status event: %w", err)
		}
	}

	// Attribute the finding to the scan that most recently observed it. Finding
	// uniqueness is project-wide, so the earliest row is kept — but leaving its
	// scan_uuid pinned to the FIRST scan means a re-detected finding silently
	// escapes the current scan's fail-on gate, printed summary, and scan-scoped
	// report. Bumping scan_uuid to the re-detecting scan keeps the finding
	// attributed to the run that actually saw it. Skipped when the re-detection
	// carries no scan id (e.g. an out-of-band import).
	if scanUUID != "" {
		q = q.Set("scan_uuid = ?", scanUUID)
	}

	// Skip evidence that just duplicates the survivor's own primary
	// request/response (or an entry it already has) — otherwise re-emitting the
	// same finding shows its response twice (primary + Additional Evidence).
	// Retain the earliest supporting pairs: existing evidence first, incoming
	// primary next, then incoming support in order, up to maxAdditionalEvidence.
	// This sample is not per-occurrence history; linked identities remain uncapped.
	primary := buildEvidence(existing.Request, existing.Response)
	if primary == "" && evidence != "" {
		// Fill the pair together; never combine two exchanges' halves.
		q = q.Set("request = ?", incoming.Request).Set("response = ?", incoming.Response)
		primary = evidence
	}
	if len(existing.AdditionalEvidence) < maxAdditionalEvidence {
		candidates := append([]string{evidence}, incoming.AdditionalEvidence...)
		if updated := appendUniqueEvidence(existing.AdditionalEvidence, primary, candidates...); len(updated) > len(existing.AdditionalEvidence) {
			q = q.Set("additional_evidence = ?", updated)
		}
	}
	// Empty enrichment may be filled, but historic attribution and lifecycle
	// decisions are not overwritten by a re-detection/import. The description
	// follows the latest detection (recordRedetectionTx).
	for _, field := range []struct{ column, old, value string }{
		{"remediation", existing.Remediation, incoming.Remediation},
		{"cwe_id", existing.CWEID, incoming.CWEID},
		{"origin_record_uuid", existing.OriginRecordUUID, incoming.OriginRecordUUID},
		{"agentic_scan_uuid", existing.AgenticScanUUID, incoming.AgenticScanUUID},
		{"evidence_status", existing.EvidenceStatus, incoming.EvidenceStatus},
	} {
		if field.old == "" && field.value != "" {
			q = q.Set(field.column+" = ?", field.value)
		}
	}
	if existing.CVSSScore == 0 && incoming.CVSSScore != 0 {
		q = q.Set("cvss_score = ?", incoming.CVSSScore)
	}

	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("failed to update finding record UUIDs: %w", err)
	}
	return nil
}

// checkFindingScanProject rejects a known scan whose stored owner differs from
// the finding project. Missing scan IDs remain valid correlation references for
// imports and out-of-band callers.
func checkFindingScanProject(ctx context.Context, idb bun.IDB, project, scanUUID, driver string) error {
	if scanUUID == "" {
		return nil
	}
	query := idb.NewSelect().Model((*Scan)(nil)).Column("project_uuid").Where("uuid = ?", scanUUID)
	if driver == driverPostgres {
		// Keep the checked owner stable through the finding transaction on PG.
		query = query.For("UPDATE")
	}
	var owner string
	if err := query.Scan(ctx, &owner); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return fmt.Errorf("check finding scan project: %w", err)
	}
	owner = defaultProjectUUID(owner)
	project = defaultProjectUUID(project)
	if owner != project {
		return fmt.Errorf("%w: scan %s belongs to project %s, not %s", ErrScanProjectMismatch, scanUUID, owner, project)
	}
	return nil
}

// checkFindingRecordProjects rejects only existing foreign records, not missing
// soft references. Legacy ghosts are preserved; readers label them unavailable.
func checkFindingRecordProjects(ctx context.Context, idb bun.IDB, project string, refs []string) error {
	for chunk := range slices.Chunk(filterEmpty(refs), SQLChunkSize) {
		var foreign string
		err := idb.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
			Where("uuid IN (?)", bun.List(chunk)).Where("project_uuid != ?", defaultProjectUUID(project)).
			Limit(1).Scan(ctx, &foreign)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return fmt.Errorf("check finding record project: %w", err)
		}
		return fmt.Errorf("finding record reference %q belongs to another project", foreign)
	}
	return nil
}

// syncFindingRecordRefs synchronizes BOTH representations inside the caller's
// transaction. The stable union retains array-only and junction-only soft/ghost
// references, with no URL inference and no cap on identities.
func syncFindingRecordRefs(ctx context.Context, idb bun.IDB, id int64, extra []string) ([]string, error) {
	f := &Finding{}
	if err := idb.NewSelect().Model(f).Column("http_record_uuids").Where("id = ?", id).Scan(ctx); err != nil {
		return nil, err
	}
	var links []string
	if err := idb.NewRaw("SELECT record_uuid FROM finding_records WHERE finding_id = ? ORDER BY record_uuid", id).Scan(ctx, &links); err != nil {
		return nil, err
	}
	union := mergeUniqueStrings(mergeUniqueStrings(f.HTTPRecordUUIDs, extra), links)
	for chunk := range slices.Chunk(union, SQLChunkSize) {
		var query strings.Builder
		query.WriteString("INSERT INTO finding_records (finding_id, record_uuid) VALUES ")
		args := make([]any, 0, len(chunk)*2)
		for i, ref := range chunk {
			if i > 0 {
				query.WriteByte(',')
			}
			query.WriteString("(?, ?)")
			args = append(args, id, ref)
		}
		query.WriteString(" ON CONFLICT DO NOTHING")
		if _, err := idb.ExecContext(ctx, query.String(), args...); err != nil {
			return nil, err
		}
	}
	if _, err := idb.NewUpdate().Model((*Finding)(nil)).Set("http_record_uuids = ?", union).Where("id = ?", id).Exec(ctx); err != nil {
		return nil, err
	}
	return union, nil
}

// HydrateFindingRecordRefs exposes the union of legacy relation representations
// for selected findings without repairing the store. Missing/foreign references
// stay visible as identities, but must be resolved via project-scoped readers.
func (r *Repository) HydrateFindingRecordRefs(ctx context.Context, findings []*Finding) error {
	idx := make(map[int64]*Finding, len(findings))
	var ids []int64
	for _, f := range findings {
		if f != nil && f.ID != 0 {
			idx[f.ID] = f
			ids = append(ids, f.ID)
		}
	}
	for chunk := range slices.Chunk(ids, SQLChunkSize) {
		var rows []struct {
			ID      int64  `bun:"id"`
			Project string `bun:"project_uuid"`
			Ref     string `bun:"record_uuid"`
		}
		if err := r.db.NewRaw(`SELECT f.id, f.project_uuid, fr.record_uuid FROM finding_records fr
			JOIN findings f ON f.id = fr.finding_id
			WHERE f.id IN (?) ORDER BY f.id, fr.record_uuid`, bun.List(chunk)).Scan(ctx, &rows); err != nil {
			return err
		}
		links := make(map[int64][]string)
		for _, row := range rows {
			if f := idx[row.ID]; f != nil && defaultProjectUUID(f.ProjectUUID) == row.Project {
				links[row.ID] = append(links[row.ID], row.Ref)
			}
		}
		for id, refs := range links {
			f := idx[id]
			f.HTTPRecordUUIDs = mergeUniqueStrings(f.HTTPRecordUUIDs, refs)
		}
	}
	return nil
}

// GetFindingRecordsScoped resolves exact references only in their finding's
// project (blank means default, NEVER all projects), including out-of-order
// imports whose unavailable references should remain on the finding.
func (r *Repository) GetFindingRecordsScoped(ctx context.Context, project string, refs []string) ([]*HTTPRecord, error) {
	var records []*HTTPRecord
	for chunk := range slices.Chunk(refs, SQLChunkSize) {
		var page []*HTTPRecord
		q := r.db.NewSelect().Model(&page).Where("uuid IN (?)", bun.List(chunk)).
			Where("project_uuid = ?", defaultProjectUUID(project))
		if r.db.readOnly {
			// CLI raw finding/view hydration reads archived rows in place. Missing
			// pre-v10 capture states must remain zero without weakening project scope.
			q = q.ColumnExpr("r.*")
		}
		if err := q.Scan(ctx); err != nil {
			return nil, err
		}
		records = append(records, page...)
	}
	return records, nil
}

// GetFindingRecordUUIDsScoped resolves only the identity inventory, never HTTP
// bodies. Missing and foreign-project references are both absent from the result,
// so detail readers can label them unavailable without revealing foreign owners.
func (r *Repository) GetFindingRecordUUIDsScoped(ctx context.Context, project string, refs []string) ([]string, error) {
	var available []string
	for chunk := range slices.Chunk(refs, SQLChunkSize) {
		var page []string
		if err := r.db.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
			Where("uuid IN (?)", bun.List(chunk)).Where("project_uuid = ?", defaultProjectUUID(project)).Scan(ctx, &page); err != nil {
			return nil, err
		}
		available = append(available, page...)
	}
	return available, nil
}

// HydrateFindingEvidence loads inline proof only for a selected page, matching
// each row's project before loading bodies. Metadata-only list queries stay light.
func (r *Repository) HydrateFindingEvidence(ctx context.Context, findings []*Finding) error {
	byProject := make(map[string]map[int64]*Finding)
	for _, f := range findings {
		if f == nil || f.ID == 0 {
			continue
		}
		project := defaultProjectUUID(f.ProjectUUID)
		if byProject[project] == nil {
			byProject[project] = make(map[int64]*Finding)
		}
		byProject[project][f.ID] = f
	}
	for project, idx := range byProject {
		ids := make([]int64, 0, len(idx))
		for id := range idx {
			ids = append(ids, id)
		}
		for chunk := range slices.Chunk(ids, SQLChunkSize) {
			var rows []*Finding
			if err := r.db.NewSelect().Model(&rows).Column("id", "request", "response", "additional_evidence").
				Where("id IN (?)", bun.List(chunk)).Where("project_uuid = ?", project).Scan(ctx); err != nil {
				return err
			}
			for _, row := range rows {
				f := idx[row.ID]
				f.Request, f.Response, f.AdditionalEvidence = row.Request, row.Response, row.AdditionalEvidence
			}
		}
	}
	return r.HydrateFindingEvidenceManifest(ctx, findings)
}

// GetFindingByID retrieves a single finding by numeric ID.
func (r *Repository) GetFindingByID(ctx context.Context, id int64) (*Finding, error) {
	finding := &Finding{}
	err := r.db.NewSelect().
		Model(finding).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.HydrateFindingEvidenceManifest(ctx, []*Finding{finding}); err != nil {
		return nil, err
	}
	return finding, nil
}

// GetFindingByHash retrieves one exact hash in a project, with manifest metadata
// only for selected receipts. Blank project means the default project.
func (r *Repository) GetFindingByHash(ctx context.Context, hash, projectUUID string) (*Finding, error) {
	finding := &Finding{}
	if err := r.db.NewSelect().Model(finding).Where("finding_hash = ?", hash).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).Scan(ctx); err != nil {
		return nil, err
	}
	if err := r.HydrateFindingEvidenceManifest(ctx, []*Finding{finding}); err != nil {
		return nil, err
	}
	return finding, nil
}

// FindingProjectUUID returns just the project a finding belongs to, for the
// existence-plus-scope check the mutating handlers perform before acting on it.
// Returns sql.ErrNoRows when the finding does not exist, like GetFindingByID.
//
// Projected on purpose: the callers read only this one field, and a finding
// carries its own inline request/response blobs.
func (r *Repository) FindingProjectUUID(ctx context.Context, id int64) (string, error) {
	finding := &Finding{}
	err := r.db.NewSelect().
		Model(finding).
		Column("project_uuid").
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		return "", err
	}
	return finding.ProjectUUID, nil
}

// HydrateFindingRequests populates the Request field on findings that were
// loaded without it — the list query (FindingsQueryBuilder) omits the
// request/response blobs for speed. It fetches id→request for the given findings
// in as few round-trips as one statement's worth of ids allows; findings that
// already carry a Request, or that have no id, are skipped. Used by display
// paths that need a finding's own PoC request (e.g. the tree's attack-URL
// rendering) without pulling the full raw view.
func (r *Repository) HydrateFindingRequests(ctx context.Context, findings []*Finding) {
	idx := make(map[int64]*Finding, len(findings))
	ids := make([]int64, 0, len(findings))
	for _, f := range findings {
		if f == nil || f.ID == 0 || f.Request != "" {
			continue
		}
		idx[f.ID] = f
		ids = append(ids, f.ID)
	}
	if len(ids) == 0 {
		return
	}
	for chunk := range slices.Chunk(ids, SQLChunkSize) {
		var loaded []*Finding
		if err := r.db.NewSelect().
			Model(&loaded).
			Column("id", "request").
			Where("id IN (?)", bun.List(chunk)).
			Scan(ctx); err != nil {
			return
		}
		for _, row := range loaded {
			if f, ok := idx[row.ID]; ok {
				f.Request = row.Request
			}
		}
	}
}

// GetFindingsByRecordUUID retrieves findings that reference a specific HTTP record UUID.
// Since http_record_uuids is a JSONB array, we use json_each to search inside it.
func (r *Repository) GetFindingsByRecordUUID(ctx context.Context, uuid string) ([]*Finding, error) {
	var findings []*Finding
	err := r.db.NewSelect().
		Model(&findings).
		Where("f.id IN (SELECT finding_id FROM finding_records WHERE record_uuid = ?)", uuid).
		Where("(f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)", RecordKindFinding).
		Order("found_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.HydrateFindingEvidenceManifest(ctx, findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// ListFindings runs a filtered findings query and returns the matching
// page plus the total unfiltered count, in a single round-trip. The
// canonical entry point for callers that want paginated results — keeps
// FindingsQueryBuilder behind the repository boundary so they don't need
// to reach for Repository.DB().
func (r *Repository) ListFindings(ctx context.Context, filters QueryFilters) ([]*Finding, int64, error) {
	return NewFindingsQueryBuilder(r.db, filters).ExecuteWithCount(ctx)
}

// GetFindingsBySeverity retrieves findings filtered by severity within a project.
func (r *Repository) GetFindingsBySeverity(ctx context.Context, projectUUID, sev string, limit int) ([]*Finding, error) {
	var findings []*Finding
	q := r.db.NewSelect().
		Model(&findings).
		Where("severity = ?", sev).
		Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", RecordKindFinding).
		Order("found_at DESC").
		Limit(int64(limit))
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	err := q.Scan(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.HydrateFindingEvidenceManifest(ctx, findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// IsValidFindingStatus reports whether s is a recognised Finding lifecycle status.
func IsValidFindingStatus(s string) bool {
	return slices.Contains(FindingStatuses, s)
}

// UpdateFindingStatusByHash sets the lifecycle status of findings matching a finding_hash
// within a project and an agentic_scan_uuid scope. Used by the swarm triage writeback to
// promote draft findings to triaged / false_positive based on agent verdicts. Either
// scope may be empty (dropping that predicate); the swarm path passes both so a hash
// shared across projects only ever touches the run's own project.
// Returns the number of rows updated.
func (r *Repository) UpdateFindingStatusByHash(ctx context.Context, projectUUID, agenticScanUUID, findingHash, status string) (int64, error) {
	if !IsValidFindingStatus(status) {
		return 0, fmt.Errorf("UpdateFindingStatusByHash: invalid status %q", status)
	}
	if findingHash == "" {
		return 0, fmt.Errorf("UpdateFindingStatusByHash: empty finding_hash")
	}
	q := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("status = ?", status).
		Where("finding_hash = ?", findingHash)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	if agenticScanUUID != "" {
		q = q.Where("agentic_scan_uuid = ?", agenticScanUUID)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("UpdateFindingStatusByHash: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

// IsValidFindingSeverity reports whether s is a recognised Finding severity level.
func IsValidFindingSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeveritySuspect:
		return true
	}
	return false
}

// UpdateFindingSeverity sets the severity of a single finding by ID.
// Returns sql.ErrNoRows if no finding matches.
func (r *Repository) UpdateFindingSeverity(ctx context.Context, id int64, severity string) error {
	if !IsValidFindingSeverity(severity) {
		return fmt.Errorf("UpdateFindingSeverity: invalid severity %q", severity)
	}
	res, err := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("severity = ?", severity).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateFindingSeverity: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateFindingTriage sets severity and description on a single finding in one
// statement. Used by the agent triage flow so a false-positive verdict can't
// land a half-updated row (severity downgraded but reasoning lost) if the
// process is killed between two separate UPDATEs. Project-scoped like
// UpdateFindingStatusScoped: projectUUID == "" drops the predicate, and a
// finding outside the project returns sql.ErrNoRows.
func (r *Repository) UpdateFindingTriage(ctx context.Context, projectUUID string, id int64, severity, description string) error {
	if !IsValidFindingSeverity(severity) {
		return fmt.Errorf("UpdateFindingTriage: invalid severity %q", severity)
	}
	q := r.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("severity = ?", severity).
		Set("description = ?", description).
		Where("id = ?", id)
	if projectUUID != "" {
		q = q.Where("project_uuid = ?", projectUUID)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return fmt.Errorf("UpdateFindingTriage: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteFindingByHash deletes the finding(s) with the given content hash within a
// project, including their findingChildTables rows. Used by the OAST
// collector to replace a weaker finding (e.g. a DNS-resolution lead) with a
// stronger one (the HTTP-fetch confirmation) for the same callback payload, so each
// payload yields exactly one finding reflecting the strongest evidence. No-op when
// findingHash is empty or no such finding exists.
func (r *Repository) DeleteFindingByHash(ctx context.Context, projectUUID, findingHash string) error {
	if findingHash == "" {
		return nil
	}
	projectUUID = defaultProjectUUID(projectUUID)
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// Clear the junction rows via a subquery on the same predicate, then drop the
		// finding(s) — both are no-ops when nothing matches, so no pre-SELECT is needed.
		for _, table := range findingChildTables {
			if _, err := tx.NewRaw(
				"DELETE FROM "+table+" WHERE finding_id IN (SELECT id FROM findings WHERE project_uuid = ? AND finding_hash = ?)",
				projectUUID, findingHash,
			).Exec(ctx); err != nil {
				return fmt.Errorf("failed to delete %s: %w", table, err)
			}
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).
			Where("project_uuid = ? AND finding_hash = ?", projectUUID, findingHash).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding: %w", err)
		}
		return nil
	})
}

// DeleteFinding deletes a finding by its numeric ID, including its
// findingChildTables rows (evidence junction, observations, status history).
func (r *Repository) DeleteFinding(ctx context.Context, id int64) error {
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if err := deleteFindingChildrenTx(ctx, tx, []int64{id}); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*Finding)(nil)).Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("failed to delete finding: %w", err)
		}
		return nil
	})
}
