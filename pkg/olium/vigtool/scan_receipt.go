package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"go.uber.org/zap"
)

// reconcileScanReceipt runs even when LaunchScan returns a UUID with an error.
// Count means persisted canonical findings, not deduplicated occurrence history.
// No ownership is moved to make a receipt look complete.
func reconcileScanReceipt(ctx context.Context, c *ScanContext, res *runner.LaunchResult) map[string]any {
	details := map[string]any{"finding_count_available": false}
	warnings := []string{}
	if res == nil || res.ScanUUID == "" {
		details["warnings"] = []string{"scan UUID and persisted finding count unavailable"}
		return details
	}
	details["scan_uuid"] = res.ScanUUID
	details["status"] = res.Status
	details["duration_ms"] = res.DurationMs
	if c == nil || c.Repo == nil {
		details["warnings"] = []string{"persisted finding count unavailable: no repository"}
		return details
	}
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	// Verify the native row's project before attribution or stored counters.
	scan, err := c.Repo.GetScanByUUID(finalCtx, res.ScanUUID)
	projectUUID := c.ProjectUUID
	if projectUUID == "" {
		projectUUID = database.DefaultProjectUUID
	}
	if err == nil && scan.ProjectUUID != projectUUID {
		err = fmt.Errorf("native scan belongs to another project")
	}
	if err == nil {
		if c.AgenticScanUUID != "" {
			if attrErr := c.Repo.AttributeScanToAgenticScan(finalCtx, res.ScanUUID, c.AgenticScanUUID); attrErr != nil {
				warnings = append(warnings, "child scan attribution failed: "+attrErr.Error())
				zap.L().Warn("Child scan attribution failed", zap.String("scan_uuid", res.ScanUUID), zap.Error(attrErr))
			}
		}
		details["status"] = scan.Status
		res.Status = scan.Status
		var count int64
		count, err = c.Repo.DB().NewSelect().Model((*database.Finding)(nil)).
			Where("scan_uuid = ?", res.ScanUUID).Where("project_uuid = ?", scan.ProjectUUID).
			Where("(record_kind IS NULL OR record_kind = '' OR record_kind = ?)", database.RecordKindFinding).Count(finalCtx)
		if err == nil {
			details["finding_count"] = int64(count)
			details["finding_count_available"] = true
			res.FindingCount = int64(count)
		}
	}
	if err != nil {
		warnings = append(warnings, "persisted finding count unavailable: "+err.Error())
		zap.L().Warn("Child scan count unavailable", zap.String("scan_uuid", res.ScanUUID), zap.Error(err))
		// A negative sentinel prevents an unavailable read from looking like zero
		// in the legacy success JSON summary; Details carries explicit availability.
		res.FindingCount = -1
	}
	if len(warnings) > 0 {
		details["warnings"] = warnings
	}
	return details
}

func successfulScanReceipt(res *runner.LaunchResult, details map[string]any) tool.Result {
	available, _ := details["finding_count_available"].(bool)
	warnings, _ := details["warnings"].([]string)
	body, _ := json.Marshal(struct {
		*runner.LaunchResult
		FindingCountAvailable bool     `json:"finding_count_available"`
		Warnings              []string `json:"warnings,omitempty"`
	}{res, available, warnings})
	return tool.Result{Content: string(body), Details: details}
}

func failedScanReceipt(label string, res *runner.LaunchResult, err error, details map[string]any) tool.Result {
	uuid := ""
	if res != nil {
		uuid = res.ScanUUID
	}
	content := fmt.Sprintf("%s failed (uuid=%s): %v", label, uuid, err)
	if available, _ := details["finding_count_available"].(bool); available {
		content += fmt.Sprintf("; persisted findings=%v", details["finding_count"])
	} else {
		content += "; warning: persisted finding count unavailable"
	}
	if warnings, ok := details["warnings"].([]string); ok && len(warnings) > 0 {
		content += fmt.Sprintf("; warnings: %v", warnings)
	}
	return tool.Result{Content: content, IsError: true, Details: details}
}
