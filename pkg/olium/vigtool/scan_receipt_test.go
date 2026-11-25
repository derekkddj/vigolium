package vigtool

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestFailedToolScanUUIDReconciledOnCancelledContext(t *testing.T) {
	// Exercise the shared path called immediately after every LaunchScan result,
	// with no provider, target traffic, or native-module execution.
	for _, label := range []string{"scan", "run_module", "extension run"} {
		t.Run(label, func(t *testing.T) {
			repo := newVigtoolTestRepo(t)
			project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
			if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot", Status: "running"}); err != nil {
				t.Fatal(err)
			}
			if err := repo.CreateScan(context.Background(), &database.Scan{UUID: child, ProjectUUID: project, Name: "child", Status: "failed"}); err != nil {
				t.Fatal(err)
			}
			finding := &database.Finding{ProjectUUID: project, ScanUUID: child, ModuleID: "passive", ModuleName: "Passive", Severity: "high", Confidence: "firm", FindingHash: uuid.NewString()}
			if err := repo.SaveFindingDirect(context.Background(), finding); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			res := &runner.LaunchResult{ScanUUID: child} // failed readback would be zero
			details := reconcileScanReceipt(ctx, &ScanContext{Repo: repo, ProjectUUID: project, AgenticScanUUID: parent}, res)
			launchErr := errors.New("native launch failed")
			receipt := failedScanReceipt(label, res, launchErr, details)
			if !receipt.IsError || !strings.Contains(receipt.Content, launchErr.Error()) || !strings.Contains(receipt.Content, "persisted findings=1") {
				t.Fatalf("receipt=%+v", receipt)
			}
			if details["finding_count_available"] != true || details["finding_count"] != int64(1) || details["status"] != "failed" {
				t.Fatalf("details=%v", details)
			}
			stored, err := repo.GetScanByUUID(context.Background(), child)
			if err != nil {
				t.Fatal(err)
			}
			if stored.AgenticScanUUID != parent || stored.Status != "failed" {
				t.Fatalf("stored=%+v", stored)
			}
			f := &database.Finding{}
			if err := repo.DB().NewSelect().Model(f).Where("id = ?", finding.ID).Scan(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.AgenticScanUUID != parent {
				t.Fatal("failed child finding orphaned")
			}
		})
	}
}

func TestScanReceiptUnavailableAndCrossProject(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "autopilot", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScan(context.Background(), &database.Scan{UUID: child, ProjectUUID: project, Name: "child", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	res := &runner.LaunchResult{ScanUUID: child}
	details := reconcileScanReceipt(context.Background(), &ScanContext{Repo: repo, ProjectUUID: uuid.NewString(), AgenticScanUUID: parent}, res)
	if details["finding_count_available"] != false || res.FindingCount != -1 {
		t.Fatalf("foreign count looks available: %v", details)
	}
	success := successfulScanReceipt(res, details)
	if !strings.Contains(success.Content, `"finding_count_available":false`) || !strings.Contains(success.Content, `"warnings"`) {
		t.Fatalf("success receipt hid the unavailable count: %s", success.Content)
	}
	stored, err := repo.GetScanByUUID(context.Background(), child)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AgenticScanUUID != "" {
		t.Fatal("foreign child attributed before scope validation")
	}
	for _, res := range []*runner.LaunchResult{nil, {ScanUUID: uuid.NewString()}} {
		details := reconcileScanReceipt(context.Background(), &ScanContext{Repo: repo, ProjectUUID: project, AgenticScanUUID: parent}, res)
		receipt := failedScanReceipt("scan", res, errors.New("launch error"), details)
		if details["finding_count_available"] != false || !strings.Contains(receipt.Content, "count unavailable") {
			t.Fatalf("unavailable read looks zero: %+v", receipt)
		}
	}
}
