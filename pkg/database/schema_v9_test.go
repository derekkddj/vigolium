package database

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func testSchemaV9Migration(t *testing.T, db *DB) {
	t.Helper()
	repo, ctx := NewRepository(db), context.Background()
	id, err := repo.SaveRecord(ctx, destinationExchange(t), RecordKindObservation, "")
	require.NoError(t, err)
	before, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	for _, column := range recordCaptureStateColumns {
		mustExec(t, db, "ALTER TABLE http_records DROP COLUMN "+column)
	}
	forceSchemaVersion(t, db, 8)
	require.NoError(t, db.CreateSchema(ctx))
	require.Equal(t, currentSchemaVersion, db.schemaVersion(ctx))
	columns, err := ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	for _, name := range recordCaptureStateColumns {
		found := false
		for _, column := range columns {
			if column.Name == name {
				found = true
				require.Equal(t, "yes", strings.ToLower(column.Nullable))
				require.Empty(t, column.Default, "migration must not backfill complete or unknown")
			}
		}
		require.True(t, found, name)
	}
	after, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after, "migration changed historical bytes/time/source/classification")
	rr, err := RecordToHttpRequestResponse(after)
	require.NoError(t, err)
	require.Nil(t, rr.Evidence(), "old observations must not acquire capture/proof metadata")
	known := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)
	knownID, err := repo.SaveRecord(ctx, known, "baseline", "")
	require.NoError(t, err)
	require.NotEqual(t, id, knownID)
	record, err := repo.GetRecordByUUID(ctx, knownID)
	require.NoError(t, err)
	assertRecordFidelity(t, record, known)
	// Reopening schema/readiness remains idempotent without touching old rows.
	require.NoError(t, db.CreateSchema(ctx))
	require.NoError(t, db.CheckSchema(ctx))
	after, err = repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestSchemaV9CaptureFidelityMigration(t *testing.T) {
	testSchemaV9Migration(t, newTestDB(t))
}

func TestPg_SchemaV9CaptureFidelityMigration(t *testing.T) {
	testSchemaV9Migration(t, openPGTestDB(t))
}

func TestPg_RecordCaptureFidelityWrites(t *testing.T) {
	testRecordCaptureFidelityWrites(t, openPGTestDB(t))
}

func TestPg_RecordCaptureFidelityDedup(t *testing.T) {
	testRecordCaptureFidelityDedup(t, openPGTestDB(t))
}

func TestPg_RecordCaptureFidelityInvalidAndNormalized(t *testing.T) {
	testRecordCaptureFidelityInvalidAndNormalized(t, openPGTestDB(t))
}
