package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestSwarmInitializationCreationCollisionRefusesForeignProject(t *testing.T) {
	ctx := context.Background()
	repo := newAuditTestRepo(t)
	original := &database.AgenticScan{
		UUID: "shared-run", ProjectUUID: "project-a", ScanUUID: "native-a",
		Mode: "swarm", Status: "pending", AgentName: "original-agent",
		ParentAgenticScanUUID: "original-parent", FindingCount: 7,
		StartedAt: time.Unix(100, 0).UTC(), TargetURL: "https://original.invalid",
	}
	if err := repo.CreateAgenticScan(ctx, original); err != nil {
		t.Fatal(err)
	}
	before, err := repo.GetAgenticScan(ctx, original.UUID)
	if err != nil {
		t.Fatal(err)
	}
	// The initializer's INSERT hits the get-or-create conflict path. Neither
	// seeding, callbacks nor the common finalizer may write the foreign row.
	result, err := NewSwarmRunner(nil, repo).Run(ctx, SwarmConfig{
		AgenticScanUUID: original.UUID, ProjectUUID: "project-b", ScanUUID: "native-b",
		AgentName: "replacement-agent", SessionDir: t.TempDir(), SkipPreflight: true,
		DiscoverFunc:  func(context.Context) error { t.Fatal("discovery ran after failed guard"); return nil },
		ScanFunc:      func(context.Context, ScanRequest) error { t.Fatal("scan ran after failed guard"); return nil },
		PhaseCallback: func(string) { t.Fatal("phase ran after failed guard") },
	})
	if !errors.Is(err, database.ErrScanProjectMismatch) || result == nil || result.AgenticScanUUID != original.UUID {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	after, err := repo.GetAgenticScan(ctx, original.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("foreign run changed:\nbefore=%+v\nafter=%+v", before, after)
	}
}

func TestSwarmInitializationRefusesIncompatibleReuse(t *testing.T) {
	for _, tc := range []struct {
		name             string
		existing         *database.AgenticScan
		child            *database.Scan
		wantProjectError bool
	}{
		{
			name:             "foreign-native-project",
			child:            &database.Scan{UUID: "requested-child", ProjectUUID: "project-b", Name: "native", Status: "pending"},
			wantProjectError: true,
		},
		{
			name:  "native-has-another-parent",
			child: &database.Scan{UUID: "requested-child", ProjectUUID: "project-a", AgenticScanUUID: "original-parent", Name: "native", Status: "failed"},
		},
		{
			name:     "existing-run-pins-another-native",
			existing: &database.AgenticScan{UUID: "requested-run", ProjectUUID: "project-a", ScanUUID: "original-child", Mode: "swarm", Status: "pending", ParentAgenticScanUUID: "original-parent"},
		},
		{
			name:     "existing-nested-run-is-another-mode",
			existing: &database.AgenticScan{UUID: "requested-run", ProjectUUID: "project-a", Mode: "audit", Status: "pending", ParentAgenticScanUUID: "original-parent"},
		},
		{
			name:     "existing-run-reuses-owned-native",
			existing: &database.AgenticScan{UUID: "requested-run", ProjectUUID: "project-a", ScanUUID: "requested-child", Mode: "swarm", Status: "pending", ParentAgenticScanUUID: "original-parent"},
			child:    &database.Scan{UUID: "requested-child", ProjectUUID: "project-a", AgenticScanUUID: "other-parent", Name: "native", Status: "failed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			repo := newAuditTestRepo(t)
			if tc.existing != nil {
				if err := repo.CreateAgenticScan(ctx, tc.existing); err != nil {
					t.Fatal(err)
				}
			}
			if tc.child != nil {
				if err := repo.CreateScan(ctx, tc.child); err != nil {
					t.Fatal(err)
				}
			}
			var beforeRuns []*database.AgenticScan
			var beforeChildren []*database.Scan
			if err := repo.DB().NewSelect().Model(&beforeRuns).Order("uuid").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if err := repo.DB().NewSelect().Model(&beforeChildren).Order("uuid").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			_, err := NewSwarmRunner(nil, repo).Run(ctx, SwarmConfig{
				AgenticScanUUID: "requested-run", ProjectUUID: "project-a", ScanUUID: "requested-child",
				SessionDir: t.TempDir(), SkipPreflight: true,
				PhaseCallback: func(string) { t.Fatal("phase ran after failed guard") },
			})
			if err == nil || errors.Is(err, database.ErrScanProjectMismatch) != tc.wantProjectError {
				t.Fatalf("initialization error=%v, wantProjectError=%v", err, tc.wantProjectError)
			}
			var afterRuns []*database.AgenticScan
			var afterChildren []*database.Scan
			if err := repo.DB().NewSelect().Model(&afterRuns).Order("uuid").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if err := repo.DB().NewSelect().Model(&afterChildren).Order("uuid").Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(beforeRuns, afterRuns) || !reflect.DeepEqual(beforeChildren, afterChildren) {
				t.Fatalf("failed guard mutated rows or left a new parent: runs=%+v children=%+v", afterRuns, afterChildren)
			}
		})
	}
}

func TestSwarmInitializationSameProjectResumeIdempotent(t *testing.T) {
	for _, project := range []string{"project-a", database.DefaultProjectUUID} {
		t.Run(project, func(t *testing.T) {
			ctx := context.Background()
			repo := newAuditTestRepo(t)
			original := &database.AgenticScan{
				UUID: "resumed-run", ProjectUUID: project, ScanUUID: "original-child",
				Mode: "swarm", Status: "pending", TargetURL: "https://original.invalid",
				ParentAgenticScanUUID: "original-parent", FindingCount: 7,
				StartedAt: time.Unix(100, 0).UTC(), SessionDir: "/original/session",
			}
			if err := repo.CreateAgenticScan(ctx, original); err != nil {
				t.Fatal(err)
			}
			if err := repo.CreateScan(ctx, &database.Scan{UUID: original.ScanUUID, ProjectUUID: project, Name: "native", Status: "failed"}); err != nil {
				t.Fatal(err)
			}
			runner := NewSwarmRunner(nil, repo)
			var seeded *database.AgenticScan
			for attempt := range 3 {
				cfg := SwarmConfig{ProjectUUID: project, AgenticScanUUID: original.UUID, ResumeDir: original.SessionDir}
				if project == database.DefaultProjectUUID && attempt == 0 {
					cfg.ProjectUUID = "" // Empty and explicit default are the same scope.
				}
				if attempt == 2 {
					cfg.ScanUUID = original.ScanUUID // Explicit matching reuse is also valid.
				}
				run := &database.AgenticScan{
					UUID: original.UUID, Mode: "swarm", Status: "running", AgentName: "effective-agent",
					StartedAt:             time.Unix(200+int64(attempt), 0).UTC(),
					ParentAgenticScanUUID: "stale-caller-parent",
				}
				if err := runner.initializeSwarmRun(ctx, &cfg, run); err != nil {
					t.Fatal(err)
				}
				if cfg.ProjectUUID != project || run.ProjectUUID != project || cfg.ScanUUID != original.ScanUUID || run.ScanUUID != cfg.ScanUUID || cfg.AgenticScanUUID != run.UUID {
					t.Fatalf("cfg/run identity diverged: cfg=%+v run=%+v", cfg, run)
				}
				if run.ParentAgenticScanUUID != original.ParentAgenticScanUUID || !run.StartedAt.Equal(original.StartedAt) {
					t.Fatalf("stored run identity not retained: %+v", run)
				}
				stored, err := repo.GetAgenticScan(ctx, original.UUID)
				if err != nil {
					t.Fatal(err)
				}
				if stored.ParentAgenticScanUUID != original.ParentAgenticScanUUID || stored.TargetURL != original.TargetURL || stored.SessionDir != original.SessionDir || stored.FindingCount != 7 || stored.Status != "running" {
					t.Fatalf("caller metadata lost or run not seeded: %+v", stored)
				}
				if seeded != nil && !reflect.DeepEqual(seeded, stored) {
					t.Fatalf("repeated resume changed the row:\nbefore=%+v\nafter=%+v", seeded, stored)
				}
				seeded = stored
				child, err := repo.GetScanByUUID(ctx, original.ScanUUID)
				if err != nil || child.AgenticScanUUID != original.UUID || child.ProjectUUID != project || child.Status != "failed" {
					t.Fatalf("native identity/status changed: child=%+v err=%v", child, err)
				}
			}
			if n, err := repo.DB().NewSelect().Model((*database.AgenticScan)(nil)).Count(ctx); err != nil || n != 1 {
				t.Fatalf("resume created extra rows: count=%d err=%v", n, err)
			}
		})
	}
}

func TestSwarmInitializationOwnsIdentityForSubsequentPhases(t *testing.T) {
	ctx := context.Background()
	repo := newAuditTestRepo(t)
	projectBytes := []byte("project-a")
	scanBytes := []byte("native-a")
	runBytes := []byte("agent-run-a")
	project := unsafe.String(unsafe.SliceData(projectBytes), len(projectBytes))
	scan := unsafe.String(unsafe.SliceData(scanBytes), len(scanBytes))
	runUUID := unsafe.String(unsafe.SliceData(runBytes), len(runBytes))
	cfg := SwarmConfig{AgenticScanUUID: runUUID, ProjectUUID: project, ScanUUID: scan}
	run := &database.AgenticScan{UUID: runUUID, Mode: "swarm", Status: "running", StartedAt: time.Unix(100, 0).UTC()}

	if err := NewSwarmRunner(nil, repo).initializeSwarmRun(ctx, &cfg, run); err != nil {
		t.Fatal(err)
	}
	copy(projectBytes, "project-b")
	copy(scanBytes, "native-b")
	copy(runBytes, "agent-run-b")

	if cfg.ProjectUUID != "project-a" || cfg.ScanUUID != "native-a" || cfg.AgenticScanUUID != "agent-run-a" ||
		run.ProjectUUID != "project-a" || run.ScanUUID != "native-a" || run.UUID != "agent-run-a" {
		t.Fatalf("initialized run retained borrowed identity for later phases: cfg=%+v run=%+v", cfg, run)
	}
	stored, err := repo.GetAgenticScan(ctx, "agent-run-a")
	if err != nil || stored.ProjectUUID != "project-a" || stored.ScanUUID != "native-a" {
		t.Fatalf("stored admission scope changed: row=%+v err=%v", stored, err)
	}
}

func TestSwarmInitializationNewRunKeepsConfigIdentity(t *testing.T) {
	ctx := context.Background()
	repo := newAuditTestRepo(t)
	cfg := SwarmConfig{AgenticScanUUID: "new-run"}
	run := &database.AgenticScan{UUID: cfg.AgenticScanUUID, Mode: "swarm", Status: "running", StartedAt: time.Unix(100, 0).UTC()}
	if err := NewSwarmRunner(nil, repo).initializeSwarmRun(ctx, &cfg, run); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetAgenticScan(ctx, run.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ScanUUID == "" || cfg.ScanUUID != run.ScanUUID || cfg.ScanUUID != stored.ScanUUID || cfg.ProjectUUID != database.DefaultProjectUUID || cfg.ProjectUUID != stored.ProjectUUID || !stored.StartedAt.Equal(run.StartedAt) {
		t.Fatalf("new-run identity diverged: cfg=%+v run=%+v stored=%+v", cfg, run, stored)
	}
}

func TestSwarmInitializationSeedFailureRollsBackNativeClaim(t *testing.T) {
	ctx := context.Background()
	repo := newAuditTestRepo(t)
	if err := repo.CreateScan(ctx, &database.Scan{UUID: "unowned-child", ProjectUUID: "project-a", Name: "native", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB().ExecContext(ctx, `CREATE TRIGGER seed_failure BEFORE UPDATE ON agentic_scans BEGIN SELECT RAISE(FAIL, 'injected seed failure'); END`); err != nil {
		t.Fatal(err)
	}
	cfg := SwarmConfig{AgenticScanUUID: "new-run", ProjectUUID: "project-a", ScanUUID: "unowned-child"}
	run := &database.AgenticScan{UUID: cfg.AgenticScanUUID, Mode: "swarm", Status: "running"}
	if err := NewSwarmRunner(nil, repo).initializeSwarmRun(ctx, &cfg, run); err == nil {
		t.Fatal("seed failure ignored")
	}
	if n, err := repo.DB().NewSelect().Model((*database.AgenticScan)(nil)).Count(ctx); err != nil || n != 0 {
		t.Fatalf("failed seed left a parent: count=%d err=%v", n, err)
	}
	child, err := repo.GetScanByUUID(ctx, cfg.ScanUUID)
	if err != nil || child.AgenticScanUUID != "" || child.Status != "failed" {
		t.Fatalf("failed seed left a native claim: child=%+v err=%v", child, err)
	}
}

func TestSwarmInitializationDatabaseErrorStopsRun(t *testing.T) {
	repo := newAuditTestRepo(t)
	if err := repo.DB().Close(); err != nil {
		t.Fatal(err)
	}
	_, err := NewSwarmRunner(nil, repo).Run(context.Background(), SwarmConfig{
		AgenticScanUUID: "requested-run", ProjectUUID: "project-a", SkipPreflight: true,
		PhaseCallback: func(string) { t.Fatal("phase ran with unavailable database") },
	})
	if err == nil {
		t.Fatal("initialization ignored a database error")
	}
}
