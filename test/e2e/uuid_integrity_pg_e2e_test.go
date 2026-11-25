//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Validate the same finding ownership gate through PostgreSQL's transactional
// path, including mixed-batch retry isolation and historical correlation IDs.
// setupPostgresDB is destructive only to the explicitly selected disposable DB.
func TestPg_UUIDFindingAdmissionAndHistoryIntegrity(t *testing.T) {
	db, repo := setupPostgresDB(t)
	ctx := context.Background()
	const owner, foreign, scan = "uuid-project-a", "uuid-project-b", "uuid-owned-scan"
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{
		UUID: scan, ProjectUUID: owner, Status: "running", Name: "UUID ownership fixture",
	}))
	event := func(module string) *output.ResultEvent {
		return &output.ResultEvent{
			ModuleID: module, Info: output.Info{Name: module, Severity: severity.High},
			Host: "uuid.example.test", URL: "https://uuid.example.test/owned",
		}
	}
	require.ErrorIs(t, repo.SaveFinding(ctx, event("foreign-only"), nil, scan, foreign), database.ErrScanProjectMismatch)
	results := repo.SaveFindingsBatchResults(ctx, []database.FindingWrite{
		{Event: event("valid-batch"), ScanUUID: scan, ProjectUUID: owner},
		{Event: event("foreign-batch"), ScanUUID: scan, ProjectUUID: foreign},
		{Event: event("external-import"), ScanUUID: "unknown-external-correlation", ProjectUUID: foreign},
	})
	require.Len(t, results, 3)
	require.NoError(t, results[0].Err)
	require.True(t, results[0].Inserted)
	require.ErrorIs(t, results[1].Err, database.ErrScanProjectMismatch)
	require.False(t, results[1].Inserted)
	require.NoError(t, results[2].Err)

	// Same-project dedup/rescan stays valid, with no foreign occurrence attached.
	require.NoError(t, repo.SaveFinding(ctx, event("valid-batch"), nil, scan, owner))
	var bad int
	require.NoError(t, db.NewSelect().Model((*database.Finding)(nil)).
		Where("scan_uuid = ? AND project_uuid <> ?", scan, owner).ColumnExpr("COUNT(*)").Scan(ctx, &bad))
	require.Zero(t, bad)
	require.NoError(t, db.NewSelect().TableExpr("finding_observations").
		Where("scan_uuid = ? AND project_uuid <> ?", scan, owner).ColumnExpr("COUNT(*)").Scan(ctx, &bad))
	require.Zero(t, bad)
	stored, err := repo.GetScanByUUID(ctx, scan)
	require.NoError(t, err)
	require.Equal(t, owner, stored.ProjectUUID)
	require.Equal(t, "running", stored.Status)
}
