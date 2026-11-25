package database

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestRiskPrioritizedExplicitExclusionPrecedesCoalescing(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	seed, err := httpmsg.GetRawRequestFromURL("http://adoption.test/item?q=1")
	require.NoError(t, err)
	seedID, err := repo.SaveRecord(ctx, seed, RecordSourceHarvest, DefaultProjectUUID)
	require.NoError(t, err)
	x := evidence.NewExchange("http://adoption.test:80", seed.Target(),
		[]byte("GET /item?q=1 HTTP/1.1\r\nHost: adoption.test\r\nAuthorization: Bearer actual\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nactual\x00\xff"), evidence.ProvenanceCaptured)
	observed, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	versionID, err := repo.SaveRecordVersion(ctx, seedID, observed)
	require.NoError(t, err)
	require.NotEqual(t, seedID, versionID)
	require.NoError(t, repo.UpdateRiskScores(ctx, map[string]int{seedID: 100}))
	ids := []string{seedID}
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).
		WithParamShapeCoalescing(1).WithExcludedRecordUUIDs(ids)
	ids[0] = versionID // configuration owns the supplied IDs
	item, err := source.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, versionID, item.RecordUUID, "the high-risk seed cannot occupy the observed version's shape slot")
	item.Complete()
	_, err = source.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 1, source.ExcludedRecords())
	require.NoError(t, source.FlushCursor(ctx))
	scan, err := repo.GetScanByUUID(ctx, scanID)
	require.NoError(t, err)
	require.Equal(t, int64(1), scan.ProcessedCount, "historical exclusions are not assessed inputs")
	feedback := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithExcludedRecordUUIDs([]string{seedID})
	_, err = feedback.Next(ctx)
	require.ErrorIs(t, err, io.EOF, "snapshot acknowledgements cover both seed and observed row")
	history, err := repo.GetRecordByUUID(ctx, seedID)
	require.NoError(t, err)
	require.False(t, history.HasResponse)
	require.Equal(t, seed.Request().Raw(), history.RawRequest)
}

func TestRiskPrioritizedExcludedPagesStillCheckpoint(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	ids := insertTestRecordsWithHost(t, repo, "excluded.test", riskPrefetchBatchSize+2)
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithExcludedRecordUUIDs(ids)
	_, err := source.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, len(ids), source.ExcludedRecords())
	require.Zero(t, source.Unresolved())
	require.NoError(t, source.FlushCursor(ctx))
	scan, err := repo.GetScanByUUID(ctx, scanID)
	require.NoError(t, err)
	require.Zero(t, scan.ProcessedCount)
	remaining, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, scan.CursorAt, scan.CursorUUID, HostTarget{Hostname: "excluded.test"})
	require.NoError(t, err)
	require.Zero(t, remaining, "an all-excluded page must advance without fake work callbacks")
	count, err := repo.DB().NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(len(ids)), count, "admission pruning never deletes historical traffic")
}
