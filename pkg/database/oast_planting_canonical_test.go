package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestOASTPlantingCanonicalBinaryBindingAndAtomicConflict(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
	x, err := row.Exchange()
	require.NoError(t, err)
	require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, row))
	require.False(t, columnExists(t, db, "oast_planting_receipts", "receipt"))
	require.True(t, columnExists(t, db, "oast_planting_receipts", "exchange_id"))
	require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence"), "pending is not selected")
	var binding, reqType, respType string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT b.exchange_id, typeof(e.raw_request), typeof(e.raw_response)
		FROM oast_planting_receipts b JOIN evidence_exchanges e ON e.project_uuid = b.project_uuid AND e.id = b.exchange_id`).Scan(&binding, &reqType, &respType))
	require.Equal(t, x.ID, binding)
	require.Equal(t, "blob", reqType)
	require.Equal(t, "blob", respType)
	got, err := repo.GetOASTPlantingReceipt(ctx, "a", row.Nonce, "scan")
	require.NoError(t, err)
	require.NoError(t, equalOASTPlantingReceipts(row, got))
	_, err = repo.GetOASTPlantingReceipt(ctx, "b", row.Nonce, "scan")
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = repo.GetOASTPlantingReceipt(ctx, "a", row.Nonce, "other-scan")
	require.ErrorIs(t, err, sql.ErrNoRows)

	other := x.Clone()
	other.ID = "another-execution"
	encoded, err := json.Marshal(other)
	require.NoError(t, err)
	changed := *row
	changed.Receipt = string(encoded)
	require.ErrorIs(t, repo.SaveOASTPlantingReceipt(ctx, &changed), ErrOASTPlantingReceiptConflict)
	require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"), "binding conflict must roll back the new canonical exchange")

	// A corrupt destination cannot hide changed bytes behind the claimed digest.
	mustExec(t, db, "UPDATE evidence_exchanges SET raw_response = ? WHERE project_uuid = ? AND id = ?", []byte("forged"), row.ProjectUUID, x.ID)
	require.ErrorIs(t, repo.SaveOASTPlantingReceipt(ctx, row), ErrOASTPlantingReceiptConflict)
}

func TestOASTPlantingOrphanCleanupRetainsPendingAndSelectedStorage(t *testing.T) {
	for _, scope := range []string{"", "a"} {
		t.Run("scope="+scope, func(t *testing.T) {
			db := newTestDB(t)
			repo, ctx := NewRepository(db), context.Background()
			pending := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
			require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, pending))
			selected := testOASTPlantingRow(t, "a", "uvwxyzabcdefghijklmn", "scan")
			require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, selected))
			x, err := selected.Exchange()
			require.NoError(t, err)
			f := receiptFinding("selected-planting", "a", evidence.Select(x, evidence.RoleAttack, true, "actual planting"))
			require.NoError(t, repo.SaveFindingDirect(ctx, f))
			require.NoError(t, repo.SaveFindingDirect(ctx, receiptFinding("orphan", "a")))
			require.Equal(t, int64(2), scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"), "selection reuses the same execution")
			n, err := NewDeleteBuilder(db, QueryFilters{ProjectUUID: scope}).DeleteOrphans(ctx, false)
			require.NoError(t, err)
			require.Equal(t, int64(1), n)
			got, err := repo.GetOASTPlantingReceipt(ctx, "a", pending.Nonce, "scan")
			require.NoError(t, err)
			require.NoError(t, equalOASTPlantingReceipts(pending, got))
			n, err = NewDeleteBuilder(db, QueryFilters{ProjectUUID: scope}).DeleteTable(ctx, "oast_planting_receipts", true)
			require.NoError(t, err)
			require.Equal(t, int64(2), n)
			require.Equal(t, int64(2), scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"))
			_, err = NewDeleteBuilder(db, QueryFilters{ProjectUUID: scope}).DeleteTable(ctx, "oast_planting_receipts", false)
			require.NoError(t, err)
			require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts"))
			require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"), "selected canonical evidence must survive binding cleanup")
			require.NoError(t, repo.HydrateFindingEvidenceForExport(ctx, f))
			require.Equal(t, x.Response, f.Evidence[0].Exchange.Response)
		})
	}
}

func TestOASTPlantingLegacyJSONMigrationIsAtomicAndBinary(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "invalid"}[valid], func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
			mustExec(t, db, "DROP TABLE oast_planting_receipts")
			mustExec(t, db, `CREATE TABLE oast_planting_receipts (project_uuid TEXT NOT NULL, nonce TEXT NOT NULL,
				scan_uuid TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY (project_uuid, nonce))`)
			mustExec(t, db, "INSERT INTO oast_planting_receipts VALUES (?, ?, ?, ?)", row.ProjectUUID, row.Nonce, row.ScanUUID, row.Receipt)
			if !valid {
				mustExec(t, db, "INSERT INTO oast_planting_receipts VALUES ('a', 'uvwxyzabcdefghijklmn', 'scan', 'invalid-json')")
			}
			err := db.CreateSchema(ctx)
			if !valid {
				require.Error(t, err)
				require.True(t, columnExists(t, db, "oast_planting_receipts", "receipt"))
				require.Equal(t, int64(2), scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts"))
				require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"), "partial migration must roll back")
				return
			}
			require.NoError(t, err)
			require.False(t, columnExists(t, db, "oast_planting_receipts", "receipt"))
			got, err := NewRepository(db).GetOASTPlantingReceipt(ctx, "a", row.Nonce, "scan")
			require.NoError(t, err)
			require.NoError(t, equalOASTPlantingReceipts(row, got))
			require.NoError(t, db.CreateSchema(ctx), "migration is idempotent")
		})
	}
}

func TestOASTPlantingLegacyMergeMaterializesCanonicalBytes(t *testing.T) {
	ctx := context.Background()
	src, path := newFileDB(t, "source-legacy.db")
	dest, _ := newFileDB(t, "destination.db")
	row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
	mustExec(t, src, "DROP TABLE oast_planting_receipts")
	mustExec(t, src, `CREATE TABLE oast_planting_receipts (project_uuid TEXT NOT NULL, nonce TEXT NOT NULL,
		scan_uuid TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY (project_uuid, nonce))`)
	mustExec(t, src, "INSERT INTO oast_planting_receipts VALUES (?, ?, ?, ?)", row.ProjectUUID, row.Nonce, row.ScanUUID, row.Receipt)
	require.NoError(t, src.Close())
	stats, err := MergeSQLiteFileWithOptions(ctx, dest, path, MergeOptions{SkipFindings: true, SkipHTTPRecords: true})
	require.NoError(t, err)
	require.Equal(t, 1, stats.OASTPlantingReceiptsMerged)
	got, err := NewRepository(dest).GetOASTPlantingReceipt(ctx, "a", row.Nonce, "scan")
	require.NoError(t, err)
	require.NoError(t, equalOASTPlantingReceipts(row, got))
	require.False(t, columnExists(t, dest, "oast_planting_receipts", "receipt"))
}

func TestOASTLegacyExportBoundaryDoesNotMigrateOrLoseContext(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
	x, err := row.Exchange()
	require.NoError(t, err)
	mustExec(t, db, "DROP TABLE oast_planting_receipts")
	mustExec(t, db, `CREATE TABLE oast_planting_receipts (project_uuid TEXT NOT NULL, nonce TEXT NOT NULL,
		scan_uuid TEXT NOT NULL, receipt TEXT NOT NULL, PRIMARY KEY (project_uuid, nonce))`)
	mustExec(t, db, "INSERT INTO oast_planting_receipts VALUES (?, ?, ?, ?)", row.ProjectUUID, row.Nonce, row.ScanUUID, row.Receipt)
	mustExec(t, db, "ALTER TABLE oast_payloads DROP COLUMN injection_type")
	mustExec(t, db, `INSERT INTO oast_payloads (nonce, project_uuid, scan_uuid, class, param, payload, created_at)
		VALUES (?, ?, ?, 'header-harvest', 'X-OAST', ?, ?)`, row.Nonce, row.ProjectUUID, row.ScanUUID, row.Nonce+".cb.test", evidenceCaptureTime(x.CapturedAt))
	var exported *OASTPlantingReceipt
	require.NoError(t, repo.WalkOASTPlantingReceipts(ctx, "a", []string{"scan"}, func(got *OASTPlantingReceipt) error {
		copy := *got
		exported = &copy
		return nil
	}))
	require.NotNil(t, exported)
	require.NoError(t, equalOASTPlantingReceipts(row, exported))
	var p *OASTPayload
	require.NoError(t, repo.WalkOASTPayloadContexts(ctx, "a", []string{"scan"}, func(got *OASTPayload) error {
		copy := *got
		p = &copy
		return nil
	}))
	require.NotNil(t, p)
	require.True(t, columnExists(t, db, "oast_planting_receipts", "receipt"), "read/export must not migrate")
	require.False(t, columnExists(t, db, "oast_payloads", "injection_type"))
	dest := newTestDB(t)
	importer := NewRepository(dest)
	require.NoError(t, importer.ImportOASTPayloadContext(ctx, p))
	require.NoError(t, importer.SaveOASTPlantingReceipt(ctx, exported))
	got, err := importer.GetOASTPlantingReceipt(ctx, "a", row.Nonce, "scan")
	require.NoError(t, err)
	require.NoError(t, equalOASTPlantingReceipts(row, got))
}

func TestOASTPayloadOnlyMergeValidatesDestinationPendingSlot(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{true: "valid", false: "wrong-slot"}[valid], func(t *testing.T) {
			ctx := context.Background()
			src, path := newFileDB(t, "payload-only.db")
			dest, _ := newFileDB(t, "destination.db")
			row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
			require.NoError(t, NewRepository(dest).SaveOASTPlantingReceipt(ctx, row))
			param, label := "url", "parameter"
			if valid {
				param, label = "X-OAST", "explicit header injection"
			}
			p := &OASTPayload{Nonce: row.Nonce, ProjectUUID: row.ProjectUUID, ScanUUID: row.ScanUUID,
				Class: "ssrf", InjectionType: label, Param: param, Payload: row.Nonce + ".cb.test", CreatedAt: time.Now().UTC()}
			require.NoError(t, NewRepository(src).SaveOASTPayloads(ctx, []*OASTPayload{p}))
			mustExec(t, src, "DROP TABLE oast_planting_receipts")
			insertHTTPRecord(t, src, "rollback-marker", "a")
			require.NoError(t, src.Close())
			_, err := MergeSQLiteFileWithOptions(ctx, dest, path, MergeOptions{SkipFindings: true})
			if !valid {
				require.ErrorIs(t, err, ErrOASTPlantingReceiptConflict)
				require.Zero(t, scalarInt(t, dest, "SELECT COUNT(*) FROM oast_payloads"))
				require.Zero(t, scalarInt(t, dest, "SELECT COUNT(*) FROM http_records WHERE uuid = 'rollback-marker'"))
				return
			}
			require.NoError(t, err)
			got, err := NewRepository(dest).GetOASTPayloadsByNonce(ctx, "a", []string{row.Nonce})
			require.NoError(t, err)
			require.Equal(t, p.InjectionType, got[row.Nonce].InjectionType)
		})
	}
}

func TestOASTPayloadContextNanosecondsAndExplicitHeaderLabel(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
	p := &OASTPayload{Nonce: row.Nonce, ProjectUUID: row.ProjectUUID, ScanUUID: row.ScanUUID,
		Class: "ssrf", InjectionType: "explicit header injection", Param: "X-OAST", Payload: row.Nonce + ".cb.test",
		CreatedAt: time.Date(2026, 11, 3, 1, 2, 3, 987654321, time.UTC)}
	require.NoError(t, repo.ImportOASTPayloadContext(ctx, p))
	require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, row))
	got, err := repo.GetOASTPayloadsByNonce(ctx, "a", []string{row.Nonce})
	require.NoError(t, err)
	require.True(t, got[row.Nonce].CreatedAt.Equal(p.CreatedAt))
	require.Equal(t, p.InjectionType, got[row.Nonce].InjectionType)
	changed := *p
	changed.CreatedAt = changed.CreatedAt.Add(time.Nanosecond)
	require.ErrorIs(t, repo.ImportOASTPayloadContext(ctx, &changed), ErrOASTPlantingReceiptConflict)
}
