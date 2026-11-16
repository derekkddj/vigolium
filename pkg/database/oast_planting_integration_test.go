package database

import (
	"context"
	"encoding/json"
	"github.com/vigolium/vigolium/internal/config"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func testOASTPlantingRow(t *testing.T, project, nonce, scan string) *OASTPlantingReceipt {
	t.Helper()
	x := evidence.NewExchange("https://plant.test:443", "https://plant.test/plant", []byte("POST /plant HTTP/1.1\r\nX-OAST: "+nonce+".cb.test\r\n\r\n\x00\xff"), []byte("HTTP/1.1 202 Accepted\r\n\r\nplant\xff\x00"), evidence.ProvenanceCaptured)
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 123456789, time.UTC)
	encoded, err := json.Marshal(x)
	require.NoError(t, err)
	return &OASTPlantingReceipt{ProjectUUID: project, Nonce: nonce, ScanUUID: scan, Receipt: string(encoded)}
}

func TestOASTPlantingCentralSchemaAndGenericDenial(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	require.True(t, db.tableExists(ctx, "oast_planting_receipts"), "schema must precede any OAST send")
	require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_oast_planting_receipts_project_scan'"))
	mustExec(t, db, "DROP TABLE oast_planting_receipts")
	// A missing current object is never created implicitly on open...
	t.Setenv(config.AutoMigrateEnvVar, "")
	var outdated *SchemaOutdatedError
	require.ErrorAs(t, db.EnsureSchemaReady(ctx), &outdated)
	require.False(t, db.tableExists(ctx, "oast_planting_receipts"))
	// ...only with the explicit auto-migrate opt-in.
	t.Setenv(config.AutoMigrateEnvVar, "1")
	require.NoError(t, db.EnsureSchemaReady(ctx))
	require.True(t, db.tableExists(ctx, "oast_planting_receipts"))
	const table = "oast_planting_receipts"
	require.NoError(t, ValidateTableName(ctx, db, table))
	columns, err := ListColumns(ctx, db, table)
	require.NoError(t, err)
	require.Len(t, columns, 4)
	_, _, _, err = QueryGenericTable(ctx, db, table, 10, 0)
	require.ErrorIs(t, err, ErrGenericTableAccessDenied)
	_, _, _, err = QueryGenericTableFiltered(ctx, db, table, GenericQueryOptions{})
	require.ErrorIs(t, err, ErrGenericTableAccessDenied)
	_, err = GetGenericRecord(ctx, db, table, "nonce")
	require.ErrorIs(t, err, ErrGenericTableAccessDenied)
	require.ErrorIs(t, InsertGenericRecord(ctx, db, table, map[string]interface{}{"receipt": "raw"}), ErrGenericTableAccessDenied)
	require.ErrorIs(t, UpdateGenericRecord(ctx, db, table, "nonce", map[string]interface{}{"receipt": "raw"}), ErrGenericTableAccessDenied)
	require.ErrorIs(t, DeleteGenericRecord(ctx, db, table, "nonce"), ErrGenericTableAccessDenied)
}

func TestOASTPlantingScopedAndGlobalCleanup(t *testing.T) {
	for _, operation := range []string{"table", "full", "purge", "reassign"} {
		t.Run(operation, func(t *testing.T) {
			db := newTestDB(t)
			repo, ctx := NewRepository(db), context.Background()
			for _, project := range []string{"a", "b"} {
				require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, testOASTPlantingRow(t, project, "abcdefghijklmnopqrst", "scan")))
			}
			clean := NewDeleteBuilder(db, QueryFilters{ProjectUUID: "a"})
			switch operation {
			case "table":
				n, err := clean.DeleteTable(ctx, "oast_planting_receipts", true)
				require.NoError(t, err)
				require.Equal(t, int64(1), n)
				n, err = clean.DeleteTable(ctx, "oast_planting_receipts", false)
				require.NoError(t, err)
				require.Equal(t, int64(1), n)
			case "full":
				counts, err := clean.DeleteAllTables(ctx, true)
				require.NoError(t, err)
				require.Equal(t, int64(1), counts["oast_planting_receipts"])
				require.Equal(t, int64(2), scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts"))
				require.Equal(t, int64(1), counts["evidence_exchanges"])
				counts, err = clean.DeleteAllTables(ctx, false)
				require.NoError(t, err)
				require.Equal(t, int64(1), counts["oast_planting_receipts"])
				require.Equal(t, int64(1), counts["evidence_exchanges"])
			case "purge":
				require.NoError(t, repo.PurgeProjectData(ctx, "a"))
			case "reassign":
				require.Error(t, repo.ReassignProjectData(ctx, "a", "b"), "nonce collision rolls back reassignment")
				require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts WHERE project_uuid = 'a'"))
				require.NoError(t, repo.ReassignProjectData(ctx, "a", "c"))
				require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts WHERE project_uuid = 'c'"))
			}
			require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts WHERE project_uuid = 'b'"))
			require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges WHERE project_uuid = 'b'"))
			if operation != "reassign" {
				require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges WHERE project_uuid = 'a'"))
			}
			counts, err := NewDeleteBuilder(db, QueryFilters{}).DeleteAllTables(ctx, false)
			require.NoError(t, err)
			require.Positive(t, counts["oast_planting_receipts"])
			require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM oast_planting_receipts"))
		})
	}
}

func TestOASTPlantingMergePendingBinaryAndImmutableConflicts(t *testing.T) {
	for _, mutation := range []string{"none", "same-instant", "execution", "bytes", "forged-digest", "nanosecond", "scan", "context-project"} {
		t.Run(mutation, func(t *testing.T) {
			ctx := context.Background()
			src, path := newFileDB(t, "source.db")
			dest, _ := newFileDB(t, "dest.db")
			row := testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")
			require.NoError(t, NewRepository(src).SaveOASTPlantingReceipt(ctx, row))
			require.NoError(t, NewRepository(dest).SaveOASTPlantingReceipt(ctx, row))
			x, err := row.Exchange()
			require.NoError(t, err)
			switch mutation {
			case "same-instant":
				x.CapturedAt = x.CapturedAt.In(time.FixedZone("plus-one", 3600))
			case "execution":
				x.ID = "another-execution"
			case "bytes":
				x.Response = append(x.Response, 'x')
				x.ContentHash = x.Hash()
			case "forged-digest":
				x.Response = append(x.Response, 'x')
			case "nanosecond":
				x.CapturedAt = x.CapturedAt.Add(time.Nanosecond)
			case "scan":
				row.ScanUUID = "foreign-scan"
			case "context-project":
				require.NoError(t, NewRepository(src).SaveOASTPayloads(ctx, []*OASTPayload{{Nonce: row.Nonce, ProjectUUID: "foreign", ScanUUID: "scan", CreatedAt: time.Now()}}))
			}
			captured := evidenceCaptureTime(x.CapturedAt)
			if mutation == "same-instant" {
				captured = x.CapturedAt.Format(time.RFC3339Nano)
			}
			mustExec(t, src, "UPDATE evidence_exchanges SET id = ?, raw_request = ?, raw_response = ?, content_hash = ?, captured_at = ?", x.ID, x.Request, x.Response, x.ContentHash, captured)
			mustExec(t, src, "UPDATE oast_planting_receipts SET exchange_id = ?, scan_uuid = ?", x.ID, row.ScanUUID)
			pending := testOASTPlantingRow(t, "a", "uvwxyzabcdefghijklmn", "scan")
			require.NoError(t, NewRepository(src).SaveOASTPlantingReceipt(ctx, pending))
			insertHTTPRecord(t, src, "rollback-marker", "a")
			require.NoError(t, src.Close())
			stats, err := MergeSQLiteFileWithOptions(ctx, dest, path, MergeOptions{SkipFindings: true, SkipRecordBodies: true})
			if mutation != "none" && mutation != "same-instant" {
				require.Error(t, err)
				require.Equal(t, int64(1), scalarInt(t, dest, "SELECT COUNT(*) FROM oast_planting_receipts"))
				require.Zero(t, scalarInt(t, dest, "SELECT COUNT(*) FROM http_records WHERE uuid = 'rollback-marker'"))
				return
			}
			require.NoError(t, err)
			require.Equal(t, 1, stats.OASTPlantingReceiptsMerged)
			stats, err = MergeSQLiteFileWithOptions(ctx, dest, path, MergeOptions{SkipFindings: true, SkipHTTPRecords: true})
			require.NoError(t, err)
			require.Zero(t, stats.OASTPlantingReceiptsMerged)
			got, err := NewRepository(dest).GetOASTPlantingReceipt(ctx, pending.ProjectUUID, pending.Nonce, pending.ScanUUID)
			require.NoError(t, err)
			require.NoError(t, equalOASTPlantingReceipts(pending, got))
			require.Equal(t, int64(2), scalarInt(t, dest, "SELECT COUNT(*) FROM evidence_exchanges"))
		})
	}
}

func TestOASTPlantingHistoricalLookupDoesNotMigrate(t *testing.T) {
	db := newTestDB(t)
	mustExec(t, db, "DROP TABLE oast_planting_receipts")
	repo, ctx := NewRepository(db), context.Background()
	require.NoError(t, repo.WalkOASTPlantingReceipts(ctx, "a", nil, func(*OASTPlantingReceipt) error { t.Fatal("unexpected historical receipt"); return nil }))
	require.False(t, db.tableExists(ctx, "oast_planting_receipts"))
	require.Error(t, repo.SaveOASTPlantingReceipt(ctx, testOASTPlantingRow(t, "a", "abcdefghijklmnopqrst", "scan")))
	require.False(t, db.tableExists(ctx, "oast_planting_receipts"), "sender write must not run lazy DDL")
}
