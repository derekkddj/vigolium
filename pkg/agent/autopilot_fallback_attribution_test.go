package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestAutopilotFallbackAttributionPreservesOwnership(t *testing.T) {
	for _, scenario := range []string{"rejected-identity", "foreign-scan", "foreign-parent", "existing-owner", "older-finding-owner", "missing-scan"} {
		t.Run(scenario, func(t *testing.T) {
			repo := newAuditTestRepo(t)
			project, parent, native, owner := uuid.NewString(), uuid.NewString(), uuid.NewString(), ""
			parentProject, nativeProject := project, project
			if scenario == "foreign-parent" {
				parentProject = uuid.NewString()
			}
			if scenario == "foreign-scan" {
				nativeProject = uuid.NewString()
			}
			if scenario == "existing-owner" {
				owner = uuid.NewString()
			}
			require.NoError(t, repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: parentProject, Mode: "autopilot"}))
			if scenario != "missing-scan" {
				require.NoError(t, repo.CreateScan(context.Background(), &database.Scan{UUID: native, ProjectUUID: nativeProject, AgenticScanUUID: owner, Name: "native"}))
			}
			findingOwner := ""
			if scenario == "older-finding-owner" {
				findingOwner = uuid.NewString()
			}
			finding := attributionTestFinding(t, repo, nativeProject, native, findingOwner)
			runErr := errors.New("scan failed")
			if scenario == "rejected-identity" {
				runErr = &runner.NativeScanIdentityError{ScanUUID: native, ProjectUUID: project, Err: errors.New("admission rejected")}
			}
			err := NewAutopilotPipelineRunner(nil, repo).attributeAutopilotFallback(context.Background(), AutopilotPipelineConfig{ProjectUUID: project, ParentAgenticScanUUID: parent}, &runner.LaunchResult{ScanUUID: native}, runErr)
			if scenario == "older-finding-owner" {
				require.NoError(t, err)
				owner = parent // scan can be linked; its older canonical finding cannot.
			} else if scenario != "rejected-identity" {
				require.Error(t, err)
			}
			if scenario != "missing-scan" {
				stored, err := repo.GetScanByUUID(context.Background(), native)
				require.NoError(t, err)
				require.Equal(t, owner, stored.AgenticScanUUID)
			}
			storedFinding, err := repo.GetFindingByID(context.Background(), finding.ID)
			require.NoError(t, err)
			require.Equal(t, findingOwner, storedFinding.AgenticScanUUID)
			require.Equal(t, native, storedFinding.ScanUUID)
		})
	}
}
