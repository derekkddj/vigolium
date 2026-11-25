package cli

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/autopilot"
)

func TestAutopilotDocumentPersistedTreeCounts(t *testing.T) {
	repo := database.NewRepository(newExportTestDB(t))
	ctx := context.Background()
	project, parent, child, leaf, native := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, run := range []*database.AgenticScan{
		{UUID: parent, ProjectUUID: project, Mode: "autopilot"},
		{UUID: child, ProjectUUID: project, Mode: "audit", ParentAgenticScanUUID: parent},
		{UUID: leaf, ProjectUUID: project, Mode: "audit", ParentAgenticScanUUID: child},
	} {
		require.NoError(t, repo.CreateAgenticScan(ctx, run))
	}
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: native, ProjectUUID: project, AgenticScanUUID: parent, Name: "native"}))
	for _, f := range []*database.Finding{
		{AgenticScanUUID: parent, Severity: "high"},
		{AgenticScanUUID: leaf, Severity: "medium"},
		{ScanUUID: native, Severity: "critical"},
	} {
		f.ProjectUUID, f.ModuleID, f.ModuleName, f.FindingHash, f.Confidence = project, "test", "test", uuid.NewString(), "firm"
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}
	var doc map[string]any
	data, err := json.Marshal(agentRunEnvelope(&agentRunOutcome{Mode: "autopilot", ProjectUUID: project, AgenticScanUUID: parent, Repo: repo, FindingCount: 99}))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &doc))
	require.EqualValues(t, 3, doc["total"])
	require.Equal(t, true, doc["finding_count_available"])
	require.Len(t, doc["items"], 3, "items and total use the same run-tree predicate, including unstamped native findings")
	items := doc["items"].([]any)
	require.Equal(t, "critical", items[0].(map[string]any)["severity"])
	counts := doc["counts_by_severity"].(map[string]any)
	require.EqualValues(t, 1, counts["high"])
	require.EqualValues(t, 1, counts["medium"])
	require.EqualValues(t, 1, counts["critical"])
}

func TestAutopilotDocumentCountUnavailable(t *testing.T) {
	for _, scenario := range []string{"zero", "closed-store", "foreign-root"} {
		t.Run(scenario, func(t *testing.T) {
			repo := database.NewRepository(newExportTestDB(t))
			project, root := uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: root, ProjectUUID: project, Mode: "autopilot"}))
			if scenario == "closed-store" {
				require.NoError(t, repo.DB().Close())
			}
			if scenario == "foreign-root" {
				project = uuid.NewString()
			}
			var doc map[string]any
			data, err := json.Marshal(agentRunEnvelope(&agentRunOutcome{Mode: "autopilot", ProjectUUID: project, AgenticScanUUID: root, Repo: repo, FindingCount: 99}))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, &doc))
			if scenario == "zero" {
				require.EqualValues(t, 0, doc["total"])
				require.Equal(t, true, doc["finding_count_available"])
			} else {
				require.EqualValues(t, -1, doc["total"], "a failed count must not fall back to a phase-local counter")
				require.Equal(t, false, doc["finding_count_available"])
				require.Nil(t, doc["counts_by_severity"])
				require.NotEmpty(t, doc["errors"])
			}
			require.Empty(t, doc["items"])
		})
	}
}

func TestAutopilotCLIFinalizersRecountAfterVerification(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "pipeline"}[pipeline], func(t *testing.T) {
			repo := database.NewRepository(newExportTestDB(t))
			ctx := context.Background()
			project, root := uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(ctx, &database.AgenticScan{UUID: root, ProjectUUID: project, Mode: "autopilot", FindingCount: 9}))
			direct := &autopilot.Result{FindingCount: 99, ReportedFindingCount: 2}
			result := &agent.AutopilotPipelineResult{TotalFindings: 99, OperatorFindingsCount: 2}
			for _, want := range []int{0, 1} {
				if want == 1 {
					// A verifier promotes a finding after the runtime's own reconciliation.
					require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{ProjectUUID: project, AgenticScanUUID: root, Severity: "high", Confidence: "firm", ModuleID: "verify", ModuleName: "verify", FindingHash: uuid.NewString()}))
				}
				end := database.AgenticRunEnd{Cancelled: true, Err: context.Canceled}
				if pipeline {
					finalizeOliumAutopilotPipelineRun(repo, project, root, time.Now(), result, context.Canceled, end)
					require.Equal(t, want, result.TotalFindings)
					require.True(t, result.FindingCountAvailable)
					require.Equal(t, 2, result.OperatorFindingsCount)
				} else {
					finalizeOliumAutopilotRun(repo, project, root, "", time.Now(), direct, context.Canceled, end)
					require.EqualValues(t, want, direct.FindingCount)
					require.True(t, direct.FindingCountAvailable)
					require.EqualValues(t, 2, direct.ReportedFindingCount)
				}
				stored, err := repo.GetAgenticScan(ctx, root)
				require.NoError(t, err)
				require.Equal(t, want, stored.FindingCount)
				require.Equal(t, "cancelled", stored.Status)
			}
		})
	}
}
