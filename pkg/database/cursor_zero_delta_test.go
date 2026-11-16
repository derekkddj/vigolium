package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testScanCursorZeroDelta(t *testing.T, db *DB) {
	t.Helper()
	repo, ctx := NewRepository(db), context.Background()
	id := createTestScan(t, repo)
	at := time.Date(2026, 11, 3, 1, 2, 3, 123456000, time.UTC)
	require.NoError(t, repo.AdvanceScanCursorBy(ctx, id, at, "excluded-last-row", 0))
	before, err := repo.GetScanByUUID(ctx, id)
	require.NoError(t, err)
	require.Zero(t, before.ProcessedCount)
	require.Equal(t, "excluded-last-row", before.CursorUUID)
	require.True(t, at.Equal(before.CursorAt))
	require.Error(t, repo.AdvanceScanCursorBy(ctx, id, at.Add(time.Second), "invalid", -1))
	after, err := repo.GetScanByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestScanCursorZeroDeltaDoesNotInventProcessedWork(t *testing.T) {
	testScanCursorZeroDelta(t, newTestDB(t))
}

func TestPg_ScanCursorZeroDeltaDoesNotInventProcessedWork(t *testing.T) {
	testScanCursorZeroDelta(t, openPGTestDB(t))
}
