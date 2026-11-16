package autopilot

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestReportFindingWithoutRunRemainsUnattributed(t *testing.T) {
	repo := newSectionTestRepo(t)
	project := uuid.NewString()
	result := executeReportFinding(t, &ReportFindingContext{Repo: repo, ProjectUUID: project}, reportFindingArgs("out of band"))
	require.False(t, result.IsError, result.Content)
	finding, err := repo.GetFindingByHash(context.Background(), hashFinding("out of band", "high", "", "", "A reproducible security issue."), project)
	require.NoError(t, err)
	require.Empty(t, finding.ScanUUID)
	observations, err := repo.ListFindingObservations(context.Background(), project, finding.ID)
	require.NoError(t, err)
	require.Empty(t, observations)
}

func TestReportFindingRejectsForeignRun(t *testing.T) {
	repo := newSectionTestRepo(t)
	project, parent := uuid.NewString(), uuid.NewString()
	require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: uuid.NewString(), Mode: "autopilot"}))
	report := &ReportFindingContext{Repo: repo, ProjectUUID: project, AgenticScanUUID: parent}
	result := executeReportFinding(t, report, reportFindingArgs("foreign run"))
	require.True(t, result.IsError)
	requireFindingNotSaved(t, repo, project, "foreign run")
	require.Zero(t, report.Count.Load())
}

func TestReportFindingLinksAgentRunObservation(t *testing.T) {
	for _, nativeScan := range []bool{false, true} {
		t.Run(map[bool]string{false: "agent-only", true: "explicit-native"}[nativeScan], func(t *testing.T) {
			repo := newSectionTestRepo(t)
			project, parent := uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot"}))
			scan, wantScan := "", parent
			if nativeScan {
				scan = uuid.NewString()
				wantScan = scan
				require.NoError(t, repo.CreateScan(context.Background(), &database.Scan{UUID: scan, ProjectUUID: project, Name: "native"}))
			}
			report := &ReportFindingContext{Repo: repo, ProjectUUID: project, ScanUUID: scan, AgenticScanUUID: parent}
			args := reportFindingArgs("agent run finding")
			for range 2 {
				result := executeReportFinding(t, report, args)
				require.False(t, result.IsError, result.Content)
			}
			finding, err := repo.GetFindingByHash(context.Background(), hashFinding("agent run finding", "high", "", "", "A reproducible security issue."), project)
			require.NoError(t, err)
			require.Equal(t, wantScan, finding.ScanUUID, "a run finding must retain a scan correlation, without inventing a native scan")
			require.Equal(t, parent, finding.AgenticScanUUID)
			observations, err := repo.ListFindingObservations(context.Background(), project, finding.ID)
			require.NoError(t, err)
			require.Len(t, observations, 1, "deduplicated reports are one run observation")
			require.Equal(t, wantScan, observations[0].ScanUUID)
			require.EqualValues(t, 1, report.Count.Load(), "tool rate-limit count stays insert-only")
			if !nativeScan {
				exists, err := repo.DB().NewSelect().Model((*database.Scan)(nil)).Where("uuid = ?", parent).Exists(context.Background())
				require.NoError(t, err)
				require.False(t, exists, "agent correlation must not create a native scan")
			}
		})
	}
}
