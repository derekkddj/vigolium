package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProjectSessionDirsAreProjectScopedAndRooted(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	projectUUID := uuid.NewString()
	otherProjectUUID := uuid.NewString()
	nativeRoot := filepath.Join(t.TempDir(), "native")
	agentRoot := filepath.Join(t.TempDir(), "agent")

	nativeUUID := uuid.NewString()
	otherNativeUUID := uuid.NewString()
	agentUUID := uuid.NewString()
	otherAgentUUID := uuid.NewString()
	for _, scan := range []struct{ id, project string }{
		{nativeUUID, projectUUID}, {otherNativeUUID, otherProjectUUID},
	} {
		if err := repo.CreateScan(ctx, &Scan{
			UUID: scan.id, ProjectUUID: scan.project, Name: "test", Status: "completed", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("create scan %s: %v", scan.id, err)
		}
	}
	for _, run := range []struct{ id, project string }{
		{agentUUID, projectUUID}, {otherAgentUUID, otherProjectUUID},
	} {
		if err := repo.CreateAgenticScan(ctx, &AgenticScan{
			UUID: run.id, ProjectUUID: run.project, Mode: "query", AgentName: "olium", Status: "completed",
		}); err != nil {
			t.Fatalf("create agent run %s: %v", run.id, err)
		}
	}

	dirs, err := repo.ProjectSessionDirs(ctx, projectUUID, nativeRoot, agentRoot)
	if err != nil {
		t.Fatalf("ProjectSessionDirs: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("got %d session dirs, want 2: %+v", len(dirs), dirs)
	}
	want := map[string]ProjectSessionDir{
		nativeUUID: {Kind: "native", UUID: nativeUUID, Root: nativeRoot, Path: filepath.Join(nativeRoot, nativeUUID)},
		agentUUID:  {Kind: "agent", UUID: agentUUID, Root: agentRoot, Path: filepath.Join(agentRoot, agentUUID)},
	}
	for _, dir := range dirs {
		expected, ok := want[dir.UUID]
		if !ok {
			t.Errorf("returned directory for another project: %+v", dir)
			continue
		}
		if dir != expected {
			t.Errorf("directory = %+v, want %+v", dir, expected)
		}
		if filepath.Base(dir.Path) != dir.UUID {
			t.Errorf("path basename = %q, want UUID %q", filepath.Base(dir.Path), dir.UUID)
		}
	}
}
