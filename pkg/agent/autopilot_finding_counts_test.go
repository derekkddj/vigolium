package agent

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestAutopilotFallbackCountsPersistedNativeFindings(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "partial-cancel"}[cancelled], func(t *testing.T) {
			repo := newAuditTestRepo(t)
			project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot"}))
			r := NewAutopilotPipelineRunner(NewEngine(config.DefaultSettings(), repo), repo)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.launchNativeScan = func(_ context.Context, params runner.LaunchParams) (*runner.LaunchResult, error) {
				require.Equal(t, repo, params.Repository)
				require.Equal(t, project, params.ProjectUUID)
				require.NoError(t, repo.CreateScan(context.Background(), &database.Scan{UUID: child, ProjectUUID: project, Name: "fallback"}))
				attributionTestFinding(t, repo, project, child, "")
				if cancelled {
					cancel()
					return &runner.LaunchResult{ScanUUID: child}, context.Canceled
				}
				return &runner.LaunchResult{ScanUUID: child, FindingCount: 1}, nil
			}
			cfg := AutopilotPipelineConfig{ProjectUUID: project, ParentAgenticScanUUID: parent, TargetURL: "https://fixture.invalid", StreamWriter: io.Discard}
			result, err := r.runBlackboxFallback(ctx, cfg, time.Now(), errors.New("provider unavailable"))
			if cancelled {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.NoError(t, err)
			}
			r.reconcileAutopilotFindings(ctx, cfg, result)
			require.Equal(t, 1, result.TotalFindings, "fallback findings must be attributable even after cancellation")
			require.True(t, result.FindingCountAvailable)
			require.Zero(t, result.OperatorFindingsCount, "native work must not inflate the operator's insert-only tally")
			stored, err := repo.GetScanByUUID(context.Background(), child)
			require.NoError(t, err)
			require.Equal(t, parent, stored.AgenticScanUUID)
		})
	}
}

func TestAutopilotPipelineCountUnavailableAndPartialErrors(t *testing.T) {
	for _, scenario := range []string{"dry-run", "provider-error", "cancelled", "missing-root", "closed-store"} {
		t.Run(scenario, func(t *testing.T) {
			repo := newAuditTestRepo(t)
			project, parent := uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot"}))
			attributionTestFinding(t, repo, project, "", parent)
			settings := config.DefaultSettings()
			settings.Agent.Olium.Provider = "nonexistent-fixture-provider"
			r := NewAutopilotPipelineRunner(NewEngine(settings, repo), repo)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := AutopilotPipelineConfig{ProjectUUID: project, ParentAgenticScanUUID: parent, SourcePath: t.TempDir(), SessionDir: t.TempDir(), SkipPreflight: true, StreamWriter: io.Discard}
			if scenario == "dry-run" {
				cfg.DryRun = true
			}
			if scenario == "cancelled" {
				cancel()
			}
			if scenario == "missing-root" {
				cfg.ParentAgenticScanUUID = uuid.NewString()
			}
			if scenario == "closed-store" {
				require.NoError(t, repo.DB().Close())
			}
			result, err := r.RunAutonomous(ctx, cfg)
			require.NotNil(t, result, "a phase error must retain partial results")
			if scenario == "dry-run" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if scenario == "missing-root" || scenario == "closed-store" {
				require.Equal(t, -1, result.TotalFindings)
				require.False(t, result.FindingCountAvailable)
				require.Contains(t, result.Warnings, "persisted finding count unavailable")
			} else {
				require.Equal(t, 1, result.TotalFindings)
				require.True(t, result.FindingCountAvailable)
			}
		})
	}
}
