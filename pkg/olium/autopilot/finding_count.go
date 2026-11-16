package autopilot

import (
	"context"
	"fmt"
	"time"
)

func reconcileRunFindingCount(ctx context.Context, opts Options, result *Result) {
	if opts.Repo == nil || opts.AgenticScanUUID == "" {
		return // library/no-store calls retain their tool-local count
	}
	result.FindingCountAvailable = false
	result.FindingCountError = ""
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	total, _, err := opts.Repo.CountAgenticScanFindings(ctx, opts.ProjectUUID, opts.AgenticScanUUID)
	if err != nil {
		result.FindingCount = -1
		result.FindingCountError = "persisted finding count unavailable"
		if opts.ToolLog != nil {
			_, _ = fmt.Fprintln(opts.ToolLog, result.FindingCountError)
		}
		return
	}
	result.FindingCount = total
	result.FindingCountAvailable = true
}
