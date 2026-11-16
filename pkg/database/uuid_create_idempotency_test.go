package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func createIdempotencyParents(t *testing.T, repo *Repository) (string, string) {
	t.Helper()
	ctx := context.Background()
	parentA := uuid.NewString()
	parentB := uuid.NewString()
	for _, parent := range []*AgenticScan{
		{UUID: parentA, ProjectUUID: "create-project-a", Mode: "swarm", AgentName: "parent-a", Status: "running"},
		{UUID: parentB, ProjectUUID: "create-project-b", Mode: "swarm", AgentName: "parent-b", Status: "running"},
	} {
		if err := repo.CreateAgenticScan(ctx, parent); err != nil {
			t.Fatalf("CreateAgenticScan(parent %s): %v", parent.UUID, err)
		}
	}
	return parentA, parentB
}

func assertIdempotentScanUnchanged(t *testing.T, repo *Repository, want *Scan) {
	t.Helper()
	stored, err := repo.GetScanByUUID(context.Background(), want.UUID)
	if err != nil {
		t.Fatalf("GetScanByUUID(%s): %v", want.UUID, err)
	}
	if stored.ProjectUUID != want.ProjectUUID || stored.AgenticScanUUID != want.AgenticScanUUID ||
		stored.Name != want.Name || stored.Description != want.Description || stored.Target != want.Target ||
		stored.Status != want.Status || !stored.StartedAt.Equal(want.StartedAt) ||
		!stored.FinishedAt.Equal(want.FinishedAt) || stored.DurationMs != want.DurationMs {
		t.Fatalf("scan changed on duplicate create: got project/parent/name/description/target/status/start/finish/duration=%q/%q/%q/%q/%q/%q/%s/%s/%d; want %q/%q/%q/%q/%q/%q/%s/%s/%d",
			stored.ProjectUUID, stored.AgenticScanUUID, stored.Name, stored.Description, stored.Target,
			stored.Status, stored.StartedAt, stored.FinishedAt, stored.DurationMs,
			want.ProjectUUID, want.AgenticScanUUID, want.Name, want.Description, want.Target,
			want.Status, want.StartedAt, want.FinishedAt, want.DurationMs)
	}
}

func assertIdempotentAgenticScanUnchanged(t *testing.T, repo *Repository, want *AgenticScan) {
	t.Helper()
	stored, err := repo.GetAgenticScan(context.Background(), want.UUID)
	if err != nil {
		t.Fatalf("GetAgenticScan(%s): %v", want.UUID, err)
	}
	if stored.ProjectUUID != want.ProjectUUID || stored.ParentAgenticScanUUID != want.ParentAgenticScanUUID ||
		stored.Mode != want.Mode || stored.AgentName != want.AgentName || stored.TemplateID != want.TemplateID ||
		stored.SourcePath != want.SourcePath || stored.Status != want.Status ||
		!stored.StartedAt.Equal(want.StartedAt) || !stored.CompletedAt.Equal(want.CompletedAt) ||
		stored.ErrorMessage != want.ErrorMessage {
		t.Fatalf("agentic scan changed on duplicate create: got project/parent/mode/agent/template/source/status/start/completed/error=%q/%q/%q/%q/%q/%q/%q/%s/%s/%q; want %q/%q/%q/%q/%q/%q/%q/%s/%s/%q",
			stored.ProjectUUID, stored.ParentAgenticScanUUID, stored.Mode, stored.AgentName, stored.TemplateID,
			stored.SourcePath, stored.Status, stored.StartedAt, stored.CompletedAt, stored.ErrorMessage,
			want.ProjectUUID, want.ParentAgenticScanUUID, want.Mode, want.AgentName, want.TemplateID,
			want.SourcePath, want.Status, want.StartedAt, want.CompletedAt, want.ErrorMessage)
	}
}

func TestCreateScanDuplicateIgnoresStaleForeignParent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	parentA, parentB := createIdempotencyParents(t, repo)
	startedAt := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	finishedAt := time.Date(2026, 11, 10, 9, 15, 0, 0, time.UTC)
	original := &Scan{
		UUID: uuid.NewString(), ProjectUUID: "create-project-a", AgenticScanUUID: parentA,
		Name: "original scan", Description: "original description", Target: "https://original.example",
		Status: "completed", StartedAt: startedAt, FinishedAt: finishedAt, DurationMs: 900000,
	}
	if err := repo.CreateScan(ctx, original); err != nil {
		t.Fatalf("CreateScan(original): %v", err)
	}

	duplicate := &Scan{
		UUID: original.UUID, ProjectUUID: "create-project-a", AgenticScanUUID: parentB,
		Name: "stale scan", Description: "stale description", Target: "https://stale.example",
		Status: "running", StartedAt: startedAt.Add(time.Hour), FinishedAt: time.Time{}, DurationMs: 1,
	}
	if err := repo.CreateScan(ctx, duplicate); err != nil {
		t.Fatalf("CreateScan(same-project duplicate with stale foreign parent): %v", err)
	}
	assertIdempotentScanUnchanged(t, repo, original)

	// A duplicate UUID under a different project is still rejected, and its
	// submitted parent is valid for that attempted project so owner validation
	// is the reason for rejection.
	foreignProjectDuplicate := &Scan{
		UUID: original.UUID, ProjectUUID: "create-project-b", AgenticScanUUID: parentB,
		Name: "foreign project", Status: "failed", StartedAt: startedAt.Add(2 * time.Hour),
	}
	if err := repo.CreateScan(ctx, foreignProjectDuplicate); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateScan(foreign-project duplicate) error = %v, want ErrScanProjectMismatch", err)
	}
	assertIdempotentScanUnchanged(t, repo, original)

	// The known-foreign-parent guard continues to reject a genuinely new scan.
	newUUID := uuid.NewString()
	freshForeignParent := &Scan{
		UUID: newUUID, ProjectUUID: "create-project-a", AgenticScanUUID: parentB,
		Name: "fresh foreign parent", Status: "running",
	}
	if err := repo.CreateScan(ctx, freshForeignParent); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateScan(fresh known foreign parent) error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM scans WHERE uuid = '"+newUUID+"'"); n != 0 {
		t.Fatalf("rejected fresh scan write left %d rows", n)
	}
}

func TestCreateAgenticScanDuplicateIgnoresStaleForeignParent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	parentA, parentB := createIdempotencyParents(t, repo)
	startedAt := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	completedAt := time.Date(2026, 11, 10, 10, 20, 0, 0, time.UTC)
	original := &AgenticScan{
		UUID: uuid.NewString(), ProjectUUID: "create-project-a", ParentAgenticScanUUID: parentA,
		Mode: "autopilot", AgentName: "original-agent", TemplateID: "original-template",
		SourcePath: "/original/source", Status: "completed", StartedAt: startedAt,
		CompletedAt: completedAt, ErrorMessage: "original result",
	}
	if err := repo.CreateAgenticScan(ctx, original); err != nil {
		t.Fatalf("CreateAgenticScan(original): %v", err)
	}

	duplicate := &AgenticScan{
		UUID: original.UUID, ProjectUUID: "create-project-a", ParentAgenticScanUUID: parentB,
		Mode: "swarm", AgentName: "stale-agent", TemplateID: "stale-template",
		SourcePath: "/stale/source", Status: "running", StartedAt: startedAt.Add(time.Hour),
		CompletedAt: time.Time{}, ErrorMessage: "stale result",
	}
	if err := repo.CreateAgenticScan(ctx, duplicate); err != nil {
		t.Fatalf("CreateAgenticScan(same-project duplicate with stale foreign parent): %v", err)
	}
	assertIdempotentAgenticScanUnchanged(t, repo, original)

	// A duplicate UUID under another project must remain a project mismatch.
	foreignProjectDuplicate := &AgenticScan{
		UUID: original.UUID, ProjectUUID: "create-project-b", ParentAgenticScanUUID: parentB,
		Mode: "pipeline", AgentName: "foreign-agent", Status: "failed",
		StartedAt: startedAt.Add(2 * time.Hour),
	}
	if err := repo.CreateAgenticScan(ctx, foreignProjectDuplicate); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateAgenticScan(foreign-project duplicate) error = %v, want ErrScanProjectMismatch", err)
	}
	assertIdempotentAgenticScanUnchanged(t, repo, original)

	// The known-foreign-parent guard continues to reject a genuinely new run.
	newUUID := uuid.NewString()
	freshForeignParent := &AgenticScan{
		UUID: newUUID, ProjectUUID: "create-project-a", ParentAgenticScanUUID: parentB,
		Mode: "audit", AgentName: "fresh-agent", Status: "running",
	}
	if err := repo.CreateAgenticScan(ctx, freshForeignParent); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateAgenticScan(fresh known foreign parent) error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM agentic_scans WHERE uuid = '"+newUUID+"'"); n != 0 {
		t.Fatalf("rejected fresh agentic scan write left %d rows", n)
	}
}
