package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// validateMergeOASTPayloads prevents the older OR IGNORE payload copy from
// silently adopting destination intent for a source planting receipt. Validation
// is set-based and runs before any context is copied, in the merge transaction.
func validateMergeOASTPayloads(ctx context.Context, tx *sql.Tx) error {
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM src.sqlite_master WHERE type = 'table' AND name = 'oast_payloads'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	var hasLabel int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('oast_payloads', 'src') WHERE name = 'injection_type'").Scan(&hasLabel); err != nil {
		return err
	}
	label := "''"
	if hasLabel > 0 {
		label = "COALESCE(s.injection_type, '')"
	}
	var nonce string
	err := tx.QueryRowContext(ctx, `SELECT s.nonce FROM src.oast_payloads s JOIN main.oast_payloads d ON d.nonce = s.nonce
		WHERE s.project_uuid IS NOT d.project_uuid OR COALESCE(s.scan_uuid, '') IS NOT COALESCE(d.scan_uuid, '')
		OR COALESCE(s.class, '') IS NOT COALESCE(d.class, '') OR COALESCE(s.module_id, '') IS NOT COALESCE(d.module_id, '')
		OR COALESCE(s.target_url, '') IS NOT COALESCE(d.target_url, '') OR COALESCE(s.param, '') IS NOT COALESCE(d.param, '')
		OR COALESCE(s.request_hash, '') IS NOT COALESCE(d.request_hash, '') OR COALESCE(s.payload, '') IS NOT COALESCE(d.payload, '')
		OR `+label+` IS NOT COALESCE(d.injection_type, '') LIMIT 1`).Scan(&nonce)
	if err == nil {
		return fmt.Errorf("%w: nonce %s payload context changed", ErrOASTPlantingReceiptConflict, nonce)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Only differently spelled timestamps need decoding; SQL date functions
	// would discard fractional precision. Closed one-row reads retain nanoseconds
	// and accept the same instant after a JSONL round trip/timezone normalization.
	var after string
	for {
		var sourceAt, destAt bun.NullTime
		err := tx.QueryRowContext(ctx, `SELECT s.nonce, s.created_at, d.created_at
			FROM src.oast_payloads s JOIN main.oast_payloads d ON d.nonce = s.nonce
			WHERE s.nonce > ? AND s.created_at IS NOT d.created_at ORDER BY s.nonce LIMIT 1`, after).Scan(&nonce, &sourceAt, &destAt)
		if errors.Is(err, sql.ErrNoRows) {
			break
		}
		if err != nil {
			return err
		}
		if !sourceAt.Time.Equal(destAt.Time) {
			return fmt.Errorf("%w: nonce %s context timestamp changed", ErrOASTPlantingReceiptConflict, nonce)
		}
		after = nonce
	}
	err = tx.QueryRowContext(ctx, `SELECT s.nonce FROM src.oast_payloads s JOIN main.oast_planting_receipts d ON d.nonce = s.nonce
		WHERE s.project_uuid IS NOT d.project_uuid OR COALESCE(s.scan_uuid, '') IS NOT d.scan_uuid LIMIT 1`).Scan(&nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return validateMergeOASTBoundContexts(ctx, tx, label)
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: nonce %s planting ownership changed", ErrOASTPlantingReceiptConflict, nonce)
}

// A payload-only source may add context to an already-pending destination
// binding. Validate that declared slot before copying it, even when the source
// has no planting table/receipts. Reads close before hydrating one exact exchange.
func validateMergeOASTBoundContexts(ctx context.Context, tx *sql.Tx, label string) error {
	var after string
	for {
		var row OASTPlantingReceipt
		var p OASTPayload
		err := tx.QueryRowContext(ctx, `SELECT s.nonce, s.project_uuid, COALESCE(s.scan_uuid, ''), COALESCE(s.class, ''),
			`+label+`, COALESCE(s.param, ''), COALESCE(s.payload, ''), b.exchange_id
			FROM src.oast_payloads s JOIN main.oast_planting_receipts b ON b.project_uuid = s.project_uuid AND b.nonce = s.nonce
			WHERE s.nonce > ? ORDER BY s.nonce LIMIT 1`, after).
			Scan(&p.Nonce, &p.ProjectUUID, &p.ScanUUID, &p.Class, &p.InjectionType, &p.Param, &p.Payload, &row.ExchangeID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		row.ProjectUUID, row.Nonce, row.ScanUUID = p.ProjectUUID, p.Nonce, p.ScanUUID
		x, err := loadMergeOASTExchange(ctx, tx, "main", row.ProjectUUID, row.ExchangeID)
		if err != nil {
			return err
		}
		if err := validateOASTPlantingContext(&row, x, &p); err != nil {
			return err
		}
		after = p.Nonce
	}
}

// mergeOASTPlantingReceipts copies canonical bytes and bindings atomically, one
// receipt at a time, even with SkipFindings/SkipRecordBodies. Legacy TEXT sources
// are decoded only at this boundary; the destination never stores receipt JSON.
func mergeOASTPlantingReceipts(ctx context.Context, tx *sql.Tx, stats *MergeStats) error {
	var exists, canonical int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM src.sqlite_master WHERE type = 'table' AND name = 'oast_planting_receipts'").Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return nil
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_table_info('oast_planting_receipts', 'src') WHERE name = 'exchange_id'").Scan(&canonical); err != nil {
		return err
	}
	column := "receipt"
	if canonical > 0 {
		column = "exchange_id"
	}
	var project, nonce string
	for {
		var row OASTPlantingReceipt
		var data string
		query := "SELECT project_uuid, nonce, scan_uuid, " + column + " FROM src.oast_planting_receipts"
		var args []any
		if nonce != "" {
			query += " WHERE project_uuid > ? OR (project_uuid = ? AND nonce > ?)"
			args = []any{project, project, nonce}
		}
		err := tx.QueryRowContext(ctx, query+" ORDER BY project_uuid, nonce LIMIT 1", args...).
			Scan(&row.ProjectUUID, &row.Nonce, &row.ScanUUID, &data)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if canonical > 0 {
			row.ExchangeID = data
			x, err := loadMergeOASTExchange(ctx, tx, "src", row.ProjectUUID, row.ExchangeID)
			if err != nil {
				return fmt.Errorf("source OAST nonce %s: %w", row.Nonce, err)
			}
			encoded, err := json.Marshal(x)
			if err != nil {
				return err
			}
			row.Receipt = string(encoded)
		} else {
			row.Receipt = data
		}
		x, err := row.Exchange()
		if err != nil {
			return fmt.Errorf("source OAST nonce %s: %w", row.Nonce, err)
		}
		row.ExchangeID = x.ID
		var p OASTPayload
		var created bun.NullTime
		err = tx.QueryRowContext(ctx, `SELECT nonce, project_uuid, COALESCE(scan_uuid, ''), COALESCE(class, ''),
			COALESCE(injection_type, ''), COALESCE(module_id, ''), COALESCE(target_url, ''), COALESCE(param, ''),
			COALESCE(request_hash, ''), COALESCE(payload, ''), created_at FROM main.oast_payloads WHERE nonce = ?`, row.Nonce).
			Scan(&p.Nonce, &p.ProjectUUID, &p.ScanUUID, &p.Class, &p.InjectionType, &p.ModuleID, &p.TargetURL, &p.Param, &p.RequestHash, &p.Payload, &created)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if err := validateOASTPlantingContext(&row, x, &p); err != nil {
				return err
			}
		}
		var oldScan, oldID string
		err = tx.QueryRowContext(ctx, "SELECT scan_uuid, exchange_id FROM main.oast_planting_receipts WHERE project_uuid = ? AND nonce = ?", row.ProjectUUID, row.Nonce).Scan(&oldScan, &oldID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		existing := err == nil
		if existing && (oldScan != row.ScanUUID || oldID != row.ExchangeID) {
			return fmt.Errorf("%w: nonce %s changed execution or ownership", ErrOASTPlantingReceiptConflict, row.Nonce)
		}
		if err := persistMergeOASTExchange(ctx, tx, row.ProjectUUID, x); err != nil {
			return err
		}
		if !existing {
			if _, err := tx.ExecContext(ctx, "INSERT INTO main.oast_planting_receipts (project_uuid, nonce, scan_uuid, exchange_id) VALUES (?, ?, ?, ?)", row.ProjectUUID, row.Nonce, row.ScanUUID, row.ExchangeID); err != nil {
				return err
			}
			stats.OASTPlantingReceiptsMerged++
		}
		project, nonce = row.ProjectUUID, row.Nonce
	}
}

func loadMergeOASTExchange(ctx context.Context, tx *sql.Tx, schema, project, id string) (*evidence.Exchange, error) {
	x := &evidence.Exchange{}
	var captured bun.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT id, url, service, raw_request, raw_response, request_state, response_state,
		provenance, content_hash, captured_at FROM `+schema+`.evidence_exchanges WHERE project_uuid = ? AND id = ?`, project, id).
		Scan(&x.ID, &x.URL, &x.Service, &x.Request, &x.Response, &x.RequestState, &x.ResponseState, &x.Provenance, &x.ContentHash, &captured); err != nil {
		return nil, err
	}
	x.CapturedAt = captured.Time
	if err := x.Validate(); err != nil {
		return nil, err
	}
	return x, nil
}

func persistMergeOASTExchange(ctx context.Context, tx *sql.Tx, project string, x *evidence.Exchange) error {
	old, err := loadMergeOASTExchange(ctx, tx, "main", project, x.ID)
	if err == nil {
		if !equalEvidenceExchanges(old, x) {
			return fmt.Errorf("%w: immutable exchange %s changed", ErrOASTPlantingReceiptConflict, x.ID)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO main.evidence_exchanges
		(project_uuid, id, url, service, raw_request, raw_response, request_state, response_state, provenance, content_hash, captured_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, project, x.ID, x.URL, x.Service, x.Request, x.Response,
		x.RequestState, x.ResponseState, x.Provenance, x.ContentHash, evidenceCaptureTime(x.CapturedAt))
	return err
}
