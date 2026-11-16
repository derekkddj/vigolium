package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

func (r *AutopilotPipelineRunner) attributeAutopilotFallback(ctx context.Context, cfg AutopilotPipelineConfig, res *runner.LaunchResult, runErr error) error {
	return AttributeAutopilotNativeScan(ctx, r.repo, cfg.ProjectUUID, cfg.ParentAgenticScanUUID, res, runErr)
}

// AttributeAutopilotNativeScan links only the exact, initialized native receipt
// of an autopilot pre-scan or fallback invocation, including partial failures.
// It never uses URLs or stale counters to infer ownership.
func AttributeAutopilotNativeScan(ctx context.Context, repo *database.Repository, project, parent string, res *runner.LaunchResult, runErr error) error {
	var identityErr *runner.NativeScanIdentityError
	if repo == nil || parent == "" || res == nil || res.ScanUUID == "" ||
		errors.As(runErr, &identityErr) || errors.Is(runErr, database.ErrScanProjectMismatch) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if project == "" {
		project = database.DefaultProjectUUID
	}
	scan, err := repo.GetScanByUUID(ctx, res.ScanUUID)
	if err != nil {
		return err
	}
	if scan.ProjectUUID != project {
		return fmt.Errorf("%w: native autopilot scan belongs to another project", database.ErrScanProjectMismatch)
	}
	return repo.AttributeScanToAgenticScan(ctx, res.ScanUUID, parent)
}

func (r *AutopilotPipelineRunner) reconcileAutopilotFindings(ctx context.Context, cfg AutopilotPipelineConfig, result *AutopilotPipelineResult) {
	result.TotalFindings = -1
	result.FindingCountAvailable = false
	if r.repo != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		total, _, err := r.repo.CountAgenticScanFindings(ctx, cfg.ProjectUUID, cfg.ParentAgenticScanUUID)
		if err == nil {
			result.TotalFindings = int(total)
			result.FindingCountAvailable = true
			return
		}
	}
	result.Degraded = true
	result.Warnings = append(result.Warnings, "persisted finding count unavailable")
}
