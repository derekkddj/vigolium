package autopilot

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

func TestRunCountsPersistedPreparationFindings(t *testing.T) {
	repo := newSectionTestRepo(t)
	project, parent := uuid.NewString(), uuid.NewString()
	require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot"}))
	// Preparation already committed a finding before the main operator starts.
	// It is a legacy pure-agent write: no native scan and no tool-local counter.
	require.NoError(t, repo.SaveFindingDirect(context.Background(), &database.Finding{
		ProjectUUID: project, AgenticScanUUID: parent, FindingHash: uuid.NewString(),
		ModuleID: "auth-analysis", ModuleName: "auth-analysis", Severity: "high", Confidence: "firm",
	}))
	result := runBudgeted(t, Options{Repo: repo, ProjectUUID: project, AgenticScanUUID: parent, MaxToolCalls: 1})
	require.EqualValues(t, 1, result.FindingCount, "the run total must include persisted preparation findings without a report_finding call")
	require.True(t, result.FindingCountAvailable)
	require.Zero(t, result.ReportedFindingCount, "persisted preparation must not consume the tool's insertion cap")
}

type findingCountFailProvider struct{}

func (findingCountFailProvider) Name() string { return "finding-count-failure" }
func (findingCountFailProvider) Stream(context.Context, provider.Request) (<-chan stream.Event, error) {
	return nil, errors.New("fixture provider failed")
}

func TestRunFindingCountLifecycle(t *testing.T) {
	for _, scenario := range []string{"zero", "resume", "provider-error", "cancelled", "invalid-options", "missing-root", "closed-store"} {
		t.Run(scenario, func(t *testing.T) {
			repo := newSectionTestRepo(t)
			project, root := uuid.NewString(), uuid.NewString()
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: root, ProjectUUID: project, Mode: "autopilot"}))
			if scenario != "zero" {
				require.NoError(t, repo.SaveFindingDirect(context.Background(), &database.Finding{ProjectUUID: project, AgenticScanUUID: root, FindingHash: uuid.NewString(), ModuleID: "prepared", ModuleName: "prepared", Severity: "high", Confidence: "firm"}))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := Options{Repo: repo, ProjectUUID: project, AgenticScanUUID: root, Provider: toolLoopProvider{in: 1, out: 1}, Target: "https://fixture.invalid", MaxToolCalls: 1, MaxTurns: 2, Out: io.Discard, ToolLog: io.Discard}
			switch scenario {
			case "provider-error":
				opts.Provider = findingCountFailProvider{}
			case "cancelled":
				cancel()
			case "invalid-options":
				opts.Provider = nil
			case "missing-root":
				opts.AgenticScanUUID = uuid.NewString()
			case "closed-store":
				require.NoError(t, repo.DB().Close())
			}
			result, err := Run(ctx, opts)
			require.NotNil(t, result)
			if scenario == "provider-error" || scenario == "cancelled" || scenario == "invalid-options" {
				require.Error(t, err)
			}
			require.Zero(t, result.ReportedFindingCount)
			if scenario == "missing-root" || scenario == "closed-store" {
				require.EqualValues(t, -1, result.FindingCount)
				require.False(t, result.FindingCountAvailable)
				require.NotEmpty(t, result.FindingCountError)
			} else {
				want := 1
				if scenario == "zero" {
					want = 0
				}
				require.EqualValues(t, want, result.FindingCount)
				require.True(t, result.FindingCountAvailable)
				require.Empty(t, result.FindingCountError)
			}
		})
	}
}
