package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
)

// Only central schema code supplies these table/column identifiers. Legacy
// timestamp columns already lost sub-microsecond precision; preserve their UTC
// instant while new writes retain all supplied nanoseconds in text metadata.
func migrateOASTTimestampColumn(ctx context.Context, tx bun.Tx, table, column string, currentDefault bool) error {
	var timestampType string
	if err := tx.NewRaw("SELECT COALESCE(MAX(data_type), 'text') FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?", table, column).Scan(ctx, &timestampType); err != nil {
		return err
	}
	if timestampType == "text" {
		return nil
	}
	value := column
	switch timestampType {
	case "timestamp without time zone":
		// The legacy writer stored UTC wall-clock timestamps.
	case "timestamp with time zone":
		value += " AT TIME ZONE 'UTC'"
	default:
		return fmt.Errorf("unsupported %s.%s type %s", table, column, timestampType)
	}
	prefix := "ALTER TABLE " + table + " ALTER COLUMN " + column
	if _, err := tx.ExecContext(ctx, prefix+" DROP DEFAULT"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, prefix+" TYPE TEXT USING to_char("+value+", 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '000Z'"); err != nil {
		return err
	}
	if currentDefault {
		if _, err := tx.ExecContext(ctx, prefix+" SET DEFAULT CURRENT_TIMESTAMP"); err != nil {
			return err
		}
	}
	return nil
}

// migrateOASTPlantingStorage replaces the former JSON/TEXT authority without
// dropping user receipts. One closed keyset read at a time bounds raw retention;
// any invalid/conflicting identity rolls back both canonical inserts and DDL.
// This runs only from central schema readiness, never from a transport callback.
func (db *DB) migrateOASTPlantingStorage(ctx context.Context) error {
	return db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		var legacy int
		query := "SELECT COUNT(*) FROM pragma_table_info('oast_planting_receipts') WHERE name = 'receipt'"
		if db.Driver() == "postgres" {
			query = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'oast_planting_receipts' AND column_name = 'receipt'"
			if err := migrateOASTTimestampColumn(ctx, tx, "oast_payloads", "created_at", true); err != nil {
				return err
			}
			if err := migrateOASTTimestampColumn(ctx, tx, "oast_interactions", "interacted_at", false); err != nil {
				return err
			}
		}
		if err := tx.NewRaw(query).Scan(ctx, &legacy); err != nil {
			return err
		}
		if legacy == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE oast_planting_receipts_canonical (
			project_uuid TEXT NOT NULL, nonce TEXT NOT NULL, scan_uuid TEXT NOT NULL,
			exchange_id TEXT NOT NULL, PRIMARY KEY (project_uuid, nonce))`); err != nil {
			return err
		}
		project, nonce := "", ""
		first := true
		for {
			var row OASTPlantingReceipt
			q := "SELECT project_uuid, nonce, scan_uuid, receipt FROM oast_planting_receipts"
			var args []any
			if !first {
				q += " WHERE project_uuid > ? OR (project_uuid = ? AND nonce > ?)"
				args = []any{project, project, nonce}
			}
			err := tx.QueryRowContext(ctx, q+" ORDER BY project_uuid, nonce LIMIT 1", args...).
				Scan(&row.ProjectUUID, &row.Nonce, &row.ScanUUID, &row.Receipt)
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			if err != nil {
				return err
			}
			x, err := row.Exchange()
			if err != nil {
				return fmt.Errorf("legacy nonce %s: %w", row.Nonce, err)
			}
			var p OASTPayload
			err = tx.NewSelect().Model(&p).Where("nonce = ?", row.Nonce).Scan(ctx)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err == nil {
				if err := validateOASTPlantingContext(&row, x, &p); err != nil {
					return err
				}
			}
			if err := persistEvidenceExchange(ctx, tx, row.ProjectUUID, x); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO oast_planting_receipts_canonical (project_uuid, nonce, scan_uuid, exchange_id) VALUES (?, ?, ?, ?)", row.ProjectUUID, row.Nonce, row.ScanUUID, x.ID); err != nil {
				return err
			}
			project, nonce = row.ProjectUUID, row.Nonce
			first = false
		}
		if _, err := tx.ExecContext(ctx, "DROP TABLE oast_planting_receipts"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "ALTER TABLE oast_planting_receipts_canonical RENAME TO oast_planting_receipts")
		return err
	})
}
