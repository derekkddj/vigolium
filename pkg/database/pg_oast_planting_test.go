package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

func TestPg_OASTPlantingCanonicalBinaryAndContextNanoseconds(t *testing.T) {
	db := openPGTestDB(t) // dedicated disposable database, never an application store
	repo, ctx := NewRepository(db), context.Background()
	row := testOASTPlantingRow(t, "project-a", "abcdefghijklmnopqrst", "scan-a")
	x, err := row.Exchange()
	require.NoError(t, err)
	p := &OASTPayload{Nonce: row.Nonce, ProjectUUID: row.ProjectUUID, ScanUUID: row.ScanUUID,
		Class: "ssrf", InjectionType: "header", Param: "X-OAST", Payload: row.Nonce + ".cb.test",
		CreatedAt: time.Date(2026, 11, 3, 1, 2, 3, 987654321, time.UTC)}
	require.NoError(t, repo.ImportOASTPayloadContext(ctx, p))
	require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, row))
	require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, row), "idempotent receipt must retain its identity")
	got, err := repo.GetOASTPlantingReceipt(ctx, row.ProjectUUID, row.Nonce, row.ScanUUID)
	require.NoError(t, err)
	require.NoError(t, equalOASTPlantingReceipts(row, got))
	require.Equal(t, x.ID, got.ExchangeID)
	var reqType, respType string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_typeof(raw_request)::text, pg_typeof(raw_response)::text
		FROM evidence_exchanges WHERE project_uuid = ? AND id = ?`, row.ProjectUUID, x.ID).Scan(&reqType, &respType))
	require.Equal(t, "bytea", reqType)
	require.Equal(t, "bytea", respType)
	var legacyColumns int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'oast_planting_receipts' AND column_name = 'receipt'`).Scan(&legacyColumns))
	require.Zero(t, legacyColumns)
	contexts, err := repo.GetOASTPayloadsByNonce(ctx, row.ProjectUUID, []string{row.Nonce})
	require.NoError(t, err)
	require.True(t, p.CreatedAt.Equal(contexts[row.Nonce].CreatedAt))
	interaction := &OASTInteraction{ProjectUUID: row.ProjectUUID, ScanUUID: row.ScanUUID,
		UniqueID: row.Nonce, FullID: row.Nonce + ".cb.test", Protocol: "http",
		RawRequest:   "GET / HTTP/1.1\r\nHost: " + row.Nonce + ".cb.test\r\n\r\n",
		RawResponse:  "HTTP/1.1 204 No Content\r\n\r\n",
		InteractedAt: time.Date(2026, 11, 3, 9, 2, 3, 123456789, time.FixedZone("collector", 8*60*60))}
	require.NoError(t, repo.SaveOASTInteraction(ctx, interaction))
	observed, err := repo.GetOASTInteractionByID(ctx, interaction.ID)
	require.NoError(t, err)
	require.True(t, interaction.InteractedAt.Equal(observed.InteractedAt), "collector nanoseconds and UTC instant must survive")
	require.Equal(t, interaction.RawRequest, observed.RawRequest)
	require.Equal(t, interaction.RawResponse, observed.RawResponse)
	var storedAt string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT interacted_at FROM oast_interactions WHERE id = ?", interaction.ID).Scan(&storedAt))
	require.Equal(t, evidenceCaptureTime(interaction.InteractedAt), storedAt)
	changed := *p
	changed.CreatedAt = changed.CreatedAt.Add(time.Nanosecond)
	require.ErrorIs(t, repo.ImportOASTPayloadContext(ctx, &changed), ErrOASTPlantingReceiptConflict)
	_, err = repo.GetOASTPlantingReceipt(ctx, "project-b", row.Nonce, row.ScanUUID)
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = repo.GetOASTPlantingReceipt(ctx, row.ProjectUUID, row.Nonce, "foreign-scan")
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestPg_OASTMetadataLegacyTimestampMigration(t *testing.T) {
	db := openPGTestDB(t) // schema is dropped; only a dedicated disposable database
	repo, ctx := NewRepository(db), context.Background()
	at := time.Date(2026, 11, 3, 1, 2, 3, 123456000, time.UTC)
	p := &OASTPayload{Nonce: "abcdefghijklmnopqrst", ProjectUUID: "project-a", ScanUUID: "scan-a", CreatedAt: at}
	require.NoError(t, repo.SaveOASTPayloads(ctx, []*OASTPayload{p}))
	interaction := &OASTInteraction{ProjectUUID: p.ProjectUUID, ScanUUID: p.ScanUUID,
		UniqueID: p.Nonce, FullID: p.Nonce + ".cb.test", Protocol: "dns", InteractedAt: at}
	require.NoError(t, repo.SaveOASTInteraction(ctx, interaction))
	require.NoError(t, db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		// Exercise both legacy PostgreSQL types under a non-UTC timezone. The
		// without-zone column is a retained UTC wall clock, not local time.
		for _, query := range []string{
			"SET LOCAL TIME ZONE 'Pacific/Auckland'",
			"ALTER TABLE oast_payloads ALTER COLUMN created_at DROP DEFAULT",
			"ALTER TABLE oast_payloads ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE USING created_at::timestamp without time zone",
			"ALTER TABLE oast_payloads ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP",
			"ALTER TABLE oast_interactions ALTER COLUMN interacted_at TYPE TIMESTAMP WITH TIME ZONE USING interacted_at::timestamptz",
		} {
			if _, err := tx.ExecContext(ctx, query); err != nil {
				return err
			}
		}
		for range 2 {
			if err := migrateOASTTimestampColumn(ctx, tx, "oast_payloads", "created_at", true); err != nil {
				return err
			}
			if err := migrateOASTTimestampColumn(ctx, tx, "oast_interactions", "interacted_at", false); err != nil {
				return err
			}
		}
		var payloadAt, interactionAt string
		if err := tx.QueryRowContext(ctx, "SELECT created_at FROM oast_payloads WHERE nonce = ?", p.Nonce).Scan(&payloadAt); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, "SELECT interacted_at FROM oast_interactions WHERE id = ?", interaction.ID).Scan(&interactionAt); err != nil {
			return err
		}
		require.Equal(t, evidenceCaptureTime(at), payloadAt)
		require.Equal(t, evidenceCaptureTime(at), interactionAt)
		return nil
	}))
	require.NoError(t, db.CreateSchema(ctx), "central schema migration remains idempotent")
	observed, err := repo.GetOASTInteractionByID(ctx, interaction.ID)
	require.NoError(t, err)
	require.True(t, at.Equal(observed.InteractedAt))
	contexts, err := repo.GetOASTPayloadsByNonce(ctx, p.ProjectUUID, []string{p.Nonce})
	require.NoError(t, err)
	require.True(t, at.Equal(contexts[p.Nonce].CreatedAt))
}
