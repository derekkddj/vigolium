package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPg_CreateDuplicateIgnoresStaleForeignParent(t *testing.T) {
	ctx := context.Background()
	db := openPGTestDB(t)
	repo := NewRepository(db)
	parentA, parentB := createIdempotencyParents(t, repo)
	startedAt := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(15 * time.Minute)
	completedAt := startedAt.Add(20 * time.Minute)

	scan := &Scan{
		UUID: uuid.NewString(), ProjectUUID: "create-project-a", AgenticScanUUID: parentA,
		Name: "postgres original scan", Description: "postgres original description",
		Target: "https://postgres-original.example", Status: "completed",
		StartedAt: startedAt, FinishedAt: finishedAt, DurationMs: 900000,
	}
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan(original): %v", err)
	}
	run := &AgenticScan{
		UUID: uuid.NewString(), ProjectUUID: "create-project-a", ParentAgenticScanUUID: parentA,
		Mode: "autopilot", AgentName: "postgres-original-agent", TemplateID: "postgres-original-template",
		SourcePath: "/postgres/original/source", Status: "completed", StartedAt: startedAt,
		CompletedAt: completedAt, ErrorMessage: "postgres original result",
	}
	if err := repo.CreateAgenticScan(ctx, run); err != nil {
		t.Fatalf("CreateAgenticScan(original): %v", err)
	}

	staleScan := &Scan{
		UUID: scan.UUID, ProjectUUID: "create-project-a", AgenticScanUUID: parentB,
		Name: "stale scan", Description: "stale description", Target: "https://stale.example",
		Status: "running", StartedAt: startedAt.Add(time.Hour), DurationMs: 1,
	}
	if err := repo.CreateScan(ctx, staleScan); err != nil {
		t.Fatalf("CreateScan(same-project duplicate with stale parent): %v", err)
	}
	assertIdempotentScanUnchanged(t, repo, scan)

	staleRun := &AgenticScan{
		UUID: run.UUID, ProjectUUID: "create-project-a", ParentAgenticScanUUID: parentB,
		Mode: "swarm", AgentName: "postgres-stale-agent", TemplateID: "postgres-stale-template",
		SourcePath: "/postgres/stale/source", Status: "running", StartedAt: startedAt.Add(time.Hour),
		ErrorMessage: "stale result",
	}
	if err := repo.CreateAgenticScan(ctx, staleRun); err != nil {
		t.Fatalf("CreateAgenticScan(same-project duplicate with stale parent): %v", err)
	}
	assertIdempotentAgenticScanUnchanged(t, repo, run)

	foreignProjectScan := &Scan{
		UUID: scan.UUID, ProjectUUID: "create-project-b", AgenticScanUUID: parentB,
		Name: "foreign project", Status: "failed",
	}
	if err := repo.CreateScan(ctx, foreignProjectScan); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateScan(foreign-project duplicate) error = %v, want ErrScanProjectMismatch", err)
	}
	foreignProjectRun := &AgenticScan{
		UUID: run.UUID, ProjectUUID: "create-project-b", ParentAgenticScanUUID: parentB,
		Mode: "pipeline", AgentName: "foreign-agent", Status: "failed",
	}
	if err := repo.CreateAgenticScan(ctx, foreignProjectRun); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateAgenticScan(foreign-project duplicate) error = %v, want ErrScanProjectMismatch", err)
	}
	assertIdempotentScanUnchanged(t, repo, scan)
	assertIdempotentAgenticScanUnchanged(t, repo, run)

	newScanUUID := uuid.NewString()
	if err := repo.CreateScan(ctx, &Scan{
		UUID: newScanUUID, ProjectUUID: "create-project-a", AgenticScanUUID: parentB,
		Name: "fresh foreign parent", Status: "running",
	}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateScan(fresh foreign parent) error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, fmt.Sprintf("SELECT COUNT(*) FROM scans WHERE uuid = '%s'", newScanUUID)); n != 0 {
		t.Fatalf("rejected fresh scan insert left %d rows", n)
	}

	newRunUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: newRunUUID, ProjectUUID: "create-project-a", ParentAgenticScanUUID: parentB,
		Mode: "audit", AgentName: "fresh-agent", Status: "running",
	}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateAgenticScan(fresh foreign parent) error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, fmt.Sprintf("SELECT COUNT(*) FROM agentic_scans WHERE uuid = '%s'", newRunUUID)); n != 0 {
		t.Fatalf("rejected fresh agentic scan insert left %d rows", n)
	}
}
