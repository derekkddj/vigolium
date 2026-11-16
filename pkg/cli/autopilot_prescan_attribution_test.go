package cli

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestAutopilotPrescanCountsPersistedFindings(t *testing.T) {
	previousNoPrescan, previousTarget, previousIntensity, previousDuration := autopilotNoPrescan, autopilotTarget, autopilotIntensity, autopilotMaxDuration
	autopilotNoPrescan, autopilotTarget, autopilotIntensity, autopilotMaxDuration = false, "https://fixture.invalid", "balanced", time.Minute
	t.Cleanup(func() {
		autopilotNoPrescan, autopilotTarget, autopilotIntensity, autopilotMaxDuration = previousNoPrescan, previousTarget, previousIntensity, previousDuration
	})
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "partial-cancel"}[cancelled], func(t *testing.T) {
			repo := database.NewRepository(newExportTestDB(t))
			project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot"}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			launch := func(_ context.Context, params runner.LaunchParams) (*runner.LaunchResult, error) {
				require.Equal(t, project, params.ProjectUUID)
				require.Equal(t, repo, params.Repository)
				require.NoError(t, repo.CreateScan(context.Background(), &database.Scan{UUID: child, ProjectUUID: project, Name: "prescan"}))
				require.NoError(t, repo.SaveFindingDirect(context.Background(), &database.Finding{ProjectUUID: project, ScanUUID: child, ModuleID: "passive", ModuleName: "passive", Severity: "high", Confidence: "firm", FindingHash: uuid.NewString()}))
				if cancelled {
					cancel()
					return &runner.LaunchResult{ScanUUID: child}, context.Canceled
				}
				return &runner.LaunchResult{ScanUUID: child, FindingCount: 1}, nil
			}
			buildPrescanInstructionWithLaunch(ctx, repo, project, parent, launch)
			total, _, available := findingCountForRun(repo, project, parent)
			require.True(t, available)
			require.EqualValues(t, 1, total, "pre-scan findings must belong to the run, even when it returns a partial failure")
			// A resumed run can then fail provider preflight before producing a
			// runtime Result. Its persisted findings still must not be reset.
			finalizeOliumAutopilotRun(repo, project, parent, "", time.Now(), nil, context.Canceled, database.AgenticRunEnd{Err: context.Canceled})
			stored, err := repo.GetAgenticScan(context.Background(), parent)
			require.NoError(t, err)
			require.Equal(t, 1, stored.FindingCount)
		})
	}
}
