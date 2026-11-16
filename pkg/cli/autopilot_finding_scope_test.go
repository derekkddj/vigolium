package cli

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/autopilot"
)

func TestAutopilotCLIFinalizersRejectForeignRoot(t *testing.T) {
	repo := database.NewRepository(newExportTestDB(t))
	ctx := context.Background()
	root, project, foreign := uuid.NewString(), uuid.NewString(), uuid.NewString()
	require.NoError(t, repo.CreateAgenticScan(ctx, &database.AgenticScan{UUID: root, ProjectUUID: project, Mode: "autopilot", Status: "running", FindingCount: 9}))
	before, err := repo.GetAgenticScan(ctx, root)
	require.NoError(t, err)
	finalizeOliumAutopilotRun(repo, foreign, root, "", time.Now(), &autopilot.Result{}, nil, database.AgenticRunEnd{})
	finalizeOliumAutopilotPipelineRun(repo, foreign, root, time.Now(), &agent.AutopilotPipelineResult{}, nil, database.AgenticRunEnd{})
	// The preflight-error exit has no runtime result, but uses the same scoped finalizer.
	finalizeOliumAutopilotRun(repo, foreign, root, "", time.Now(), nil, context.Canceled, database.AgenticRunEnd{Err: context.Canceled})
	after, err := repo.GetAgenticScan(ctx, root)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(before, after), "a pinned foreign root must remain untouched by count finalization")
	_, _, available := findingCountForRun(repo, foreign, root)
	require.False(t, available)
}

func TestAutopilotHumanSummaryUnavailableIsNotZero(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "pipeline"}[pipeline], func(t *testing.T) {
			repo := database.NewRepository(newExportTestDB(t))
			require.NoError(t, repo.DB().Close())
			out := captureStdout(t, func() {
				if pipeline {
					printOliumAutopilotPipelineSummary(&agent.AutopilotPipelineResult{}, "", repo, "", "unknown")
				} else {
					printOliumAutopilotSummary(&autopilot.Result{FindingCount: 99}, "", repo, "", "unknown")
				}
			})
			require.Contains(t, out, "unavailable")
			require.NotContains(t, out, "99", "a phase-local fallback must not be labelled persisted")
		})
	}
}
