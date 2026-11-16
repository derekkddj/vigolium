package database

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCountAgenticScanFindingsCrossPhaseScope(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	project, root, audit, leaf, native, foreign := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, run := range []*AgenticScan{
		{UUID: root, ProjectUUID: project, Mode: "autopilot"},
		{UUID: audit, ProjectUUID: project, Mode: "audit", ParentAgenticScanUUID: root},
		{UUID: leaf, ProjectUUID: project, Mode: "audit", ParentAgenticScanUUID: audit},
		{UUID: foreign, ProjectUUID: uuid.NewString(), Mode: "autopilot"},
	} {
		require.NoError(t, repo.CreateAgenticScan(ctx, run))
	}
	require.NoError(t, repo.CreateScan(ctx, &Scan{UUID: native, ProjectUUID: project, Name: "native", AgenticScanUUID: root}))
	var originals []*Finding
	for _, f := range []*Finding{
		{ProjectUUID: project, AgenticScanUUID: root, Severity: "HIGH"}, // auth/operator, legacy NULL scan
		{ProjectUUID: project, AgenticScanUUID: audit, Severity: "high"},
		{ProjectUUID: project, AgenticScanUUID: leaf, Severity: "medium"},
		{ProjectUUID: project, AgenticScanUUID: root, ScanUUID: native, Severity: "low"}, // both paths, counted once
		{ProjectUUID: project, ScanUUID: native, Severity: "low"},                        // not yet stamped
		{ProjectUUID: project, AgenticScanUUID: foreign, Severity: "critical"},           // malformed historical cross-project parent
		{ProjectUUID: project, AgenticScanUUID: root, Severity: "critical", RecordKind: "candidate"},
		{ProjectUUID: project, ScanUUID: native, AgenticScanUUID: uuid.NewString(), Severity: "critical"}, // retain older owner
		{ProjectUUID: uuid.NewString(), AgenticScanUUID: root, Severity: "critical"},                      // malformed historical foreign finding
	} {
		f.FindingHash, f.ModuleID, f.ModuleName, f.Confidence = uuid.NewString(), "test", "test", "firm"
		f.HTTPRecordUUIDs = []string{}
		// Seed deliberately malformed historical rows without weakening admission.
		_, err := repo.DB().NewInsert().Model(f).Exec(ctx)
		require.NoError(t, err)
		originals = append(originals, f)
	}
	// A foreign historical child must not be followed, even when linked to root.
	_, err := repo.DB().NewUpdate().Model((*AgenticScan)(nil)).Set("parent_run_uuid = ?", root).Where("uuid = ?", foreign).Exec(ctx)
	require.NoError(t, err)
	// Cycles are bounded by the recursive query's UNION.
	_, err = repo.DB().NewUpdate().Model((*AgenticScan)(nil)).Set("parent_run_uuid = ?", leaf).Where("uuid = ?", root).Exec(ctx)
	require.NoError(t, err)
	for range 2 {
		total, counts, err := repo.CountAgenticScanFindings(ctx, project, root)
		require.NoError(t, err)
		require.EqualValues(t, 5, total)
		require.Equal(t, map[string]int64{"high": 2, "medium": 1, "low": 2}, counts)
		findings, err := repo.ListAgenticScanFindings(ctx, project, root, 10)
		require.NoError(t, err)
		require.Len(t, findings, 5)
		for _, f := range findings {
			require.Equal(t, project, f.ProjectUUID)
			require.NotEqual(t, "critical", f.Severity, "foreign owners and candidates are excluded from summaries too")
		}
		findings, err = repo.ListAgenticScanFindings(ctx, project, root, 1)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.Equal(t, "high", strings.ToLower(findings[0].Severity))
	}
	for _, f := range originals {
		stored := &Finding{}
		require.NoError(t, repo.DB().NewSelect().Model(stored).Where("id = ?", f.ID).Scan(ctx))
		require.Equal(t, f.ScanUUID, stored.ScanUUID)
		require.Equal(t, f.AgenticScanUUID, stored.AgenticScanUUID, "counting must not rewrite attribution")
	}
	_, _, err = repo.CountAgenticScanFindings(ctx, uuid.NewString(), root)
	require.ErrorIs(t, err, ErrScanProjectMismatch)
	_, err = repo.ListAgenticScanFindings(ctx, uuid.NewString(), root, 10)
	require.ErrorIs(t, err, ErrScanProjectMismatch)
	_, err = repo.ListAgenticScanFindings(ctx, project, root, 0)
	require.Error(t, err)
	_, _, err = repo.CountAgenticScanFindings(ctx, project, uuid.NewString())
	require.Error(t, err)
	_, _, err = repo.CountAgenticScanFindings(ctx, project, "")
	require.Error(t, err)
}

func TestCountAgenticScanFindingsZeroDefaultAndUnavailable(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	root := uuid.NewString()
	require.NoError(t, repo.CreateAgenticScan(context.Background(), &AgenticScan{UUID: root, Mode: "autopilot"}))
	total, counts, err := repo.CountAgenticScanFindings(context.Background(), "", root)
	require.NoError(t, err)
	require.Zero(t, total)
	require.Empty(t, counts)
	require.NoError(t, repo.DB().Close())
	_, _, err = repo.CountAgenticScanFindings(context.Background(), "", root)
	require.Error(t, err)
}
