package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// mergeSelectedEvidence copies receipts set-based (binary columns unchanged),
// remapping only finding IDs. It validates source receipts in bounded pages;
// neither source nor destination's complete receipt corpus enters Go memory.
func mergeSelectedEvidence(ctx context.Context, tx *sql.Tx, idMap map[int64]int64) error {
	hasTable := func(table string) (bool, error) {
		var count int
		err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM src.sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count)
		return count != 0, err
	}
	hasExchanges, err := hasTable("evidence_exchanges")
	if err != nil {
		return err
	}
	if hasExchanges {
		if err := validateMergeEvidence(ctx, tx); err != nil {
			return err
		}
		// Reject reused IDs, including a dishonest digest with different bytes.
		// Compare in SQLite without hydrating the destination's messages.
		var mismatch string
		err := tx.QueryRowContext(ctx, `SELECT s.id FROM src.evidence_exchanges s
			JOIN main.evidence_exchanges d ON d.project_uuid = s.project_uuid AND d.id = s.id
			WHERE s.content_hash IS NOT d.content_hash OR s.url IS NOT d.url OR s.service IS NOT d.service
			OR COALESCE(s.raw_request, X'') IS NOT COALESCE(d.raw_request, X'')
			OR COALESCE(s.raw_response, X'') IS NOT COALESCE(d.raw_response, X'')
			OR s.request_state IS NOT d.request_state OR s.response_state IS NOT d.response_state
			OR s.provenance IS NOT d.provenance LIMIT 1`).Scan(&mismatch)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil {
			return fmt.Errorf("immutable evidence exchange %s identity/content mismatch during merge", mismatch)
		}
		if err := validateMergeEvidenceTimes(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO main.evidence_exchanges
			(project_uuid, id, url, service, raw_request, raw_response, request_state, response_state, provenance, content_hash, captured_at)
			SELECT project_uuid, id, url, service, raw_request, raw_response, request_state, response_state, provenance, content_hash, captured_at
			FROM src.evidence_exchanges`); err != nil {
			return err
		}
	}
	hasRelations, err := hasTable("finding_evidence")
	if err != nil || !hasRelations || len(idMap) == 0 {
		return err
	}
	// A temporary identity map allows a SQL-only relation copy even when source
	// and destination IDs differ or hash conflicts fold into existing findings.
	if _, err := tx.ExecContext(ctx, "CREATE TEMP TABLE evidence_finding_id_map (source_id INTEGER PRIMARY KEY, destination_id INTEGER NOT NULL)"); err != nil {
		return err
	}
	for src, dst := range idMap {
		if _, err := tx.ExecContext(ctx, "INSERT INTO evidence_finding_id_map VALUES (?, ?)", src, dst); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO main.finding_evidence
		(finding_id, association_hash, exchange_id, role, is_primary, label, occurrence_id, finding_url, scan_uuid)
		SELECT m.destination_id, e.association_hash, e.exchange_id, e.role, e.is_primary, e.label, e.occurrence_id, e.finding_url, e.scan_uuid
		FROM src.finding_evidence e JOIN evidence_finding_id_map m ON m.source_id = e.finding_id
		JOIN src.findings s ON s.id = m.source_id
		JOIN main.findings d ON d.id = m.destination_id AND d.project_uuid = s.project_uuid
		ORDER BY e.id ASC`); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DROP TABLE evidence_finding_id_map")
	return err
}

// Compare time instants rather than backend/timezone spelling, without SQL date
// functions (which discard nanoseconds) or loading either raw receipt corpus.
func validateMergeEvidenceTimes(ctx context.Context, tx *sql.Tx) error {
	project, id := "", ""
	for {
		var sourceAt, destAt bun.NullTime
		err := tx.QueryRowContext(ctx, `SELECT s.project_uuid, s.id, s.captured_at, d.captured_at
			FROM src.evidence_exchanges s JOIN main.evidence_exchanges d ON d.project_uuid = s.project_uuid AND d.id = s.id
			WHERE (s.project_uuid > ? OR (s.project_uuid = ? AND s.id > ?)) AND s.captured_at IS NOT d.captured_at
			ORDER BY s.project_uuid, s.id LIMIT 1`, project, project, id).Scan(&project, &id, &sourceAt, &destAt)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if !sourceAt.Time.Equal(destAt.Time) {
			return fmt.Errorf("immutable evidence exchange %s capture time mismatch during merge", id)
		}
	}
}

func validateMergeEvidence(ctx context.Context, tx *sql.Tx) error {
	project, id := "", ""
	first := true
	for {
		q := `SELECT project_uuid, id, url, service, raw_request, raw_response, request_state, response_state, provenance, content_hash, captured_at FROM src.evidence_exchanges`
		var args []any
		if !first {
			q += " WHERE project_uuid > ? OR (project_uuid = ? AND id > ?)"
			args = []any{project, project, id}
		}
		q += " ORDER BY project_uuid, id LIMIT 16"
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			x := &evidence.Exchange{}
			var captured bun.NullTime
			if err := rows.Scan(&project, &x.ID, &x.URL, &x.Service, &x.Request, &x.Response,
				&x.RequestState, &x.ResponseState, &x.Provenance, &x.ContentHash, &captured); err != nil {
				_ = rows.Close()
				return err
			}
			x.CapturedAt = captured.Time
			if err := x.Validate(); err != nil {
				_ = rows.Close()
				return err
			}
			id = x.ID
			count++
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		first = false
	}
}
