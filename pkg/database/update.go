package database

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// RecordResponseUpdate contains response fields to update on an existing HTTP record.
// Used by the traffic --replay --in-replace feature.
type RecordResponseUpdate struct {
	StatusCode            int
	StatusPhrase          string
	ResponseHTTPVersion   string
	ResponseContentType   string
	ResponseContentLength int64
	RawResponse           []byte
	ResponseHash          string
	ResponseTimeMs        int64
}

// UpdateRecordResponse guards the former in-place replay API. A response-only
// update cannot prove which request was actually sent. Identical response bytes
// are a no-op; changed responses require SaveRecordVersion with the full exchange
// and adoption of its returned UUID. The old row and all references stay intact.
func (r *Repository) UpdateRecordResponse(ctx context.Context, uuid string, update *RecordResponseUpdate) error {
	if update == nil {
		return fmt.Errorf("UpdateRecordResponse: missing response update")
	}
	record, err := r.GetRecordByUUID(ctx, uuid)
	if err != nil {
		return fmt.Errorf("UpdateRecordResponse: load record: %w", err)
	}
	if record.HasResponse && bytes.Equal(record.RawResponse, update.RawResponse) {
		return nil
	}
	return fmt.Errorf("UpdateRecordResponse: %w; save the complete replay as a version", ErrImmutableRecordExchange)
}

// BackfillRecordResponse guards the former stub mutation API. Response absence
// is itself part of a captured exchange, even before references are committed.
// An rr without a response remains a no-op for compatibility. An identical
// complete exchange is also a no-op; otherwise callers must SaveRecordVersion
// (or save an observation normally) and adopt the returned UUID.
func (r *Repository) BackfillRecordResponse(ctx context.Context, uuid string, rr *httpmsg.HttpRequestResponse) error {
	if rr == nil || rr.Response() == nil {
		return nil
	}

	record, err := r.GetRecordByUUID(ctx, uuid)
	if err != nil {
		return fmt.Errorf("BackfillRecordResponse: load record: %w", err)
	}
	candidate := &HTTPRecord{ProjectUUID: record.ProjectUUID}
	if err := candidate.PrepareIdentity(rr); err != nil {
		return fmt.Errorf("BackfillRecordResponse: convert identity: %w", err)
	}
	prepareRecordExchangeIdentity(candidate, rr)
	if recordExchangeBytesValid(record) && recordDedupKey(candidate) == recordDedupKey(record) {
		return nil
	}
	return fmt.Errorf("BackfillRecordResponse: %w; save the fetched exchange as a version", ErrImmutableRecordExchange)
}

// DeleteRequestOnlyStubs removes request-only records that a check against the
// live target found not worth scanning: a 404/410, a soft-404, or a host that
// did not answer at all. Returns how many rows were deleted.
//
// Every row is guarded on project, source AND has_response = false, so the
// delete can only ever take a stub the caller's own phase wrote. A harvested URL
// that deduped onto an existing record adopts that row's UUID — which may be a
// fully fetched record from another phase or an earlier scan — and the guard is
// what keeps a dead archive URL from deleting real evidence that happens to
// share its identity. finding_records junction rows go in the same transaction,
// mirroring DeleteRecord.
func (r *Repository) DeleteRequestOnlyStubs(ctx context.Context, projectUUID, source string, uuids []string) (int64, error) {
	if len(uuids) == 0 {
		return 0, nil
	}
	projectUUID = defaultProjectUUID(projectUUID)
	var deleted int64
	err := r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		for chunk := range slices.Chunk(uuids, SQLChunkSize) {
			stubs := tx.NewSelect().Model((*HTTPRecord)(nil)).Column("uuid").
				Where("uuid IN (?)", bun.List(chunk)).
				Where("project_uuid = ?", projectUUID).
				Where("source = ?", source).
				Where("has_response = ?", false)
			if _, err := tx.NewDelete().TableExpr("finding_records").
				Where("record_uuid IN (?)", stubs).Exec(ctx); err != nil {
				return fmt.Errorf("delete stub finding_records: %w", err)
			}
			res, err := tx.NewDelete().Model((*HTTPRecord)(nil)).
				Where("uuid IN (?)", bun.List(chunk)).
				Where("project_uuid = ?", projectUUID).
				Where("source = ?", source).
				Where("has_response = ?", false).
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("delete request-only stubs: %w", err)
			}
			if n, err := res.RowsAffected(); err == nil {
				deleted += n
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
