package database

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestCompleteScanWithOutcomeForProjectRefusesForeignAndMissingRows(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScan(ctx, &Scan{
		UUID: "original-scan", ProjectUUID: "project-a", Status: "running", Name: "original",
		Target: "https://original.invalid", AgenticScanUUID: "original-parent", TotalFindings: 7,
	}); err != nil {
		t.Fatal(err)
	}
	before, err := repo.GetScanByUUID(ctx, "original-scan")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ project, scan string }{
		{project: "project-b", scan: before.UUID},
		{project: "", scan: before.UUID}, // Empty means default, never the stored project.
		{project: "project-a", scan: "missing-scan"},
	} {
		if err := repo.CompleteScanWithOutcomeForProject(ctx, tc.project, tc.scan, "replacement failure", ScanCompletion{Completeness: CompletenessPartial, StopReason: ReasonCancelled}); err == nil {
			t.Fatalf("unowned completion succeeded: %+v", tc)
		}
		stored, err := repo.GetScanByUUID(ctx, before.UUID)
		if err != nil || !reflect.DeepEqual(before, stored) {
			t.Fatalf("unowned completion changed row: stored=%+v err=%v", stored, err)
		}
	}
	if n, err := repo.DB().NewSelect().Model((*Scan)(nil)).Count(ctx); err != nil || n != 1 {
		t.Fatalf("completion fabricated a row: count=%d err=%v", n, err)
	}
}

func TestCompleteScanWithOutcomeForProjectCountsOnlyOwnedFindings(t *testing.T) {
	for _, project := range []string{"project-a", ""} {
		t.Run(defaultProjectUUID(project), func(t *testing.T) {
			ctx := context.Background()
			repo := NewRepository(newTestDB(t))
			scan := &Scan{UUID: "owned-scan", ProjectUUID: project, Status: "running", StartedAt: time.Now().Add(-time.Second), TotalFindings: 99, AgenticScanUUID: "original-parent"}
			if err := repo.CreateScan(ctx, scan); err != nil {
				t.Fatal(err)
			}
			// Insert legacy inconsistent evidence directly: the finalizer must
			// exclude it, not rewrite/delete it or rely on today's save guards.
			for i, entry := range []struct{ project, severity, kind string }{
				{defaultProjectUUID(project), SeverityHigh, RecordKindFinding},
				{"project-b", SeverityCritical, RecordKindFinding},
				{defaultProjectUUID(project), SeverityCritical, RecordKindCandidate},
			} {
				finding := &Finding{
					ProjectUUID: entry.project, ScanUUID: scan.UUID, Severity: entry.severity, RecordKind: entry.kind,
					ModuleID: "test", ModuleName: "test", FindingHash: string(rune('a' + i)), HTTPRecordUUIDs: []string{},
				}
				if _, err := repo.DB().NewInsert().Model(finding).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			completion := ScanCompletion{Completeness: CompletenessComplete, Phases: []PhaseOutcome{{Phase: "dynamic-assessment"}}}
			if err := repo.CompleteScanWithOutcomeForProject(ctx, project, scan.UUID, "", completion); err != nil {
				t.Fatal(err)
			}
			stored, err := repo.GetScanByUUID(ctx, scan.UUID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.ProjectUUID != defaultProjectUUID(project) || stored.AgenticScanUUID != "original-parent" || stored.Status != "completed" || stored.FinishedAt.IsZero() || stored.DurationMs < 1 || stored.TotalFindings != 1 || stored.HighCount != 1 || stored.CriticalCount != 0 || stored.Completeness != completion.Completeness || !reflect.DeepEqual(stored.PhaseOutcomes, completion.Phases) {
				t.Fatalf("scoped completion=%+v", stored)
			}
			if n, err := repo.DB().NewSelect().Model((*Finding)(nil)).Count(ctx); err != nil || n != 3 {
				t.Fatalf("completion changed evidence: count=%d err=%v", n, err)
			}
		})
	}
}

func TestCompleteScanWithOutcomeForProjectRequiresTerminalWrite(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	scan := newScan(t, repo, "project-a")
	before, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil {
		t.Fatal(err)
	}
	// A terminal UPDATE that affects no rows must not report success, even
	// when the preceding project-scoped reads succeeded.
	if _, err := repo.DB().ExecContext(ctx, `CREATE TRIGGER ignore_scan_completion BEFORE UPDATE ON scans BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteScanWithOutcomeForProject(ctx, "project-a", scan.UUID, "", ScanCompletion{}); err == nil {
		t.Fatal("ignored terminal write reported success")
	}
	stored, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil || !reflect.DeepEqual(before, stored) {
		t.Fatalf("ignored write mutated row: stored=%+v err=%v", stored, err)
	}
}

func TestCompleteScanWithOutcomeForProjectCountFailureLeavesRowUntouched(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	scan := newScan(t, repo, "project-a")
	before, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB().ExecContext(ctx, "ALTER TABLE findings RENAME TO unavailable_findings"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CompleteScanWithOutcomeForProject(ctx, "project-a", scan.UUID, "", ScanCompletion{}); err == nil {
		t.Fatal("failed scoped count must not silently zero the row")
	}
	stored, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil || !reflect.DeepEqual(before, stored) {
		t.Fatalf("failed count mutated row: stored=%+v err=%v", stored, err)
	}
}
