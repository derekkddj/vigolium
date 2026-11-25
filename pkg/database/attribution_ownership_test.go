package database

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestAttributeScanOwnershipAndRollback(t *testing.T) {
	for _, scenario := range []string{"cross-project-parent", "existing-native-owner", "foreign-finding", "missing-parent", "missing-native", "finding-update-failure"} {
		t.Run(scenario, func(t *testing.T) {
			repo := NewRepository(newTestDB(t))
			ctx := context.Background()
			project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
			parentProject := project
			if scenario == "cross-project-parent" {
				parentProject = uuid.NewString()
			}
			if scenario != "missing-parent" {
				if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: parent, ProjectUUID: parentProject, Mode: "swarm", Status: "running"}); err != nil {
					t.Fatal(err)
				}
			}
			owner := ""
			if scenario == "existing-native-owner" {
				owner = uuid.NewString()
			}
			if scenario != "missing-native" {
				if err := repo.CreateScan(ctx, &Scan{UUID: child, ProjectUUID: project, AgenticScanUUID: owner, Name: "child", Status: "failed"}); err != nil {
					t.Fatal(err)
				}
			}
			findingProject := project
			if scenario == "foreign-finding" {
				findingProject = uuid.NewString()
			}
			finding := &Finding{
				ProjectUUID: findingProject, HTTPRecordUUIDs: []string{}, ScanUUID: child,
				ModuleID: "mod", ModuleName: "mod", Severity: SeverityMedium,
				Confidence: "firm", FindingHash: uuid.NewString(),
			}
			var id int64
			if scenario == "foreign-finding" {
				// This intentionally malformed parent is historical state used to
				// exercise the attribution guard, not a supported current write.
				if _, err := repo.DB().NewInsert().Model(finding).Exec(ctx); err != nil {
					t.Fatalf("insert historical foreign finding fixture: %v", err)
				}
				id = finding.ID
			} else {
				id = saveFindingFull(t, repo, finding)
			}
			if scenario == "finding-update-failure" {
				_, err := repo.DB().ExecContext(ctx, `CREATE TRIGGER attribution_failure BEFORE UPDATE OF agentic_scan_uuid ON findings BEGIN SELECT RAISE(FAIL, 'injected finding write failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := repo.AttributeScanToAgenticScan(ctx, child, parent)
			if err == nil {
				t.Fatal("unsafe attribution succeeded")
			}
			if scenario == "cross-project-parent" || scenario == "foreign-finding" {
				if !errors.Is(err, ErrScanProjectMismatch) {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if scenario != "missing-native" {
				scan, err := repo.GetScanByUUID(ctx, child)
				if err != nil {
					t.Fatal(err)
				}
				if scan.AgenticScanUUID != owner || scan.Status != "failed" {
					t.Fatalf("native row changed: %+v", scan)
				}
			}
			if got := findingAgenticUUID(t, repo, id); got != "" {
				t.Fatalf("finding ownership changed to %s", got)
			}
		})
	}
}

func TestAttributeScanPreservesHistoricalFindingParents(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	project, parent, child, olderParent, olderScan := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: parent, ProjectUUID: project, Mode: "swarm", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScan(ctx, &Scan{UUID: child, ProjectUUID: project, Name: "child", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	oldInChild := saveFindingFull(t, repo, &Finding{ProjectUUID: project, ScanUUID: child, AgenticScanUUID: olderParent})
	oldInOldScan := saveFindingFull(t, repo, &Finding{ProjectUUID: project, ScanUUID: olderScan, AgenticScanUUID: olderParent})
	fresh := saveFindingFull(t, repo, &Finding{ProjectUUID: project, ScanUUID: child})
	for range 2 {
		if err := repo.AttributeScanToAgenticScan(ctx, child, parent); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []int64{oldInChild, oldInOldScan} {
		if got := findingAgenticUUID(t, repo, id); got != olderParent {
			t.Fatalf("historical parent overwritten: %s", got)
		}
	}
	if got := findingAgenticUUID(t, repo, fresh); got != parent {
		t.Fatalf("fresh finding missing parent: %s", got)
	}
	f := &Finding{}
	if err := repo.DB().NewSelect().Model(f).Where("id = ?", oldInOldScan).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if f.ScanUUID != olderScan {
		t.Fatal("historical scan UUID overwritten")
	}
}
