package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func updateOwnershipFixture(t *testing.T) (*Repository, *Scan, *AgenticScan, *AgenticScan) {
	t.Helper()
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	parent := &AgenticScan{
		UUID: uuid.NewString(), ProjectUUID: "update-project-a", Mode: "swarm", Status: "running",
	}
	foreignParent := &AgenticScan{
		UUID: uuid.NewString(), ProjectUUID: "update-project-b", Mode: "swarm", Status: "running",
	}
	for _, run := range []*AgenticScan{parent, foreignParent} {
		if err := repo.CreateAgenticScan(ctx, run); err != nil {
			t.Fatalf("CreateAgenticScan(%s): %v", run.UUID, err)
		}
	}
	run := &AgenticScan{
		UUID: uuid.NewString(), ProjectUUID: "update-project-a", ParentAgenticScanUUID: parent.UUID,
		Mode: "audit", Status: "running",
	}
	if err := repo.CreateAgenticScan(ctx, run); err != nil {
		t.Fatalf("CreateAgenticScan(child): %v", err)
	}
	scan := &Scan{
		UUID: uuid.NewString(), ProjectUUID: "update-project-a", AgenticScanUUID: parent.UUID,
		Name: "update child", Status: "running", StartedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
	}
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan(child): %v", err)
	}
	return repo, scan, run, foreignParent
}

func assertUpdatedScanUnchanged(t *testing.T, repo *Repository, uuid, project, parent, status string, finished time.Time) {
	t.Helper()
	stored, err := repo.GetScanByUUID(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetScanByUUID(%s): %v", uuid, err)
	}
	if stored.ProjectUUID != project || stored.AgenticScanUUID != parent || stored.Status != status || !stored.FinishedAt.Equal(finished) {
		t.Fatalf("scan changed: project=%q parent=%q status=%q finished=%s; want %q/%q/%q/%s",
			stored.ProjectUUID, stored.AgenticScanUUID, stored.Status, stored.FinishedAt,
			project, parent, status, finished)
	}
}

func assertUpdatedAgenticRunUnchanged(t *testing.T, repo *Repository, uuid, project, parent, status string, completed time.Time) {
	t.Helper()
	stored, err := repo.GetAgenticScan(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetAgenticScan(%s): %v", uuid, err)
	}
	if stored.ProjectUUID != project || stored.ParentAgenticScanUUID != parent || stored.Status != status || !stored.CompletedAt.Equal(completed) {
		t.Fatalf("agentic run changed: project=%q parent=%q status=%q completed=%s; want %q/%q/%q/%s",
			stored.ProjectUUID, stored.ParentAgenticScanUUID, stored.Status, stored.CompletedAt,
			project, parent, status, completed)
	}
}

func TestUpdateScanRejectsForeignProjectAndAgenticParent(t *testing.T) {
	t.Run("foreign-project", func(t *testing.T) {
		repo, scan, _, _ := updateOwnershipFixture(t)
		stored, err := repo.GetScanByUUID(context.Background(), scan.UUID)
		if err != nil {
			t.Fatal(err)
		}
		stored.ProjectUUID = "update-project-b"
		stored.Status = "completed"
		stored.FinishedAt = time.Date(2026, 11, 10, 12, 30, 0, 0, time.UTC)
		if err := repo.UpdateScan(context.Background(), stored); !errors.Is(err, ErrScanProjectMismatch) {
			t.Fatalf("UpdateScan foreign project error = %v, want ErrScanProjectMismatch", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "running", time.Time{})
	})

	t.Run("foreign-agentic-parent", func(t *testing.T) {
		repo, scan, _, foreignParent := updateOwnershipFixture(t)
		stored, err := repo.GetScanByUUID(context.Background(), scan.UUID)
		if err != nil {
			t.Fatal(err)
		}
		stored.AgenticScanUUID = foreignParent.UUID
		stored.Status = "completed"
		stored.FinishedAt = time.Date(2026, 11, 10, 12, 30, 0, 0, time.UTC)
		if err := repo.UpdateScan(context.Background(), stored); !errors.Is(err, ErrScanProjectMismatch) {
			t.Fatalf("UpdateScan foreign parent error = %v, want ErrScanProjectMismatch", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "running", time.Time{})
	})

	t.Run("valid-updates", func(t *testing.T) {
		repo, scan, _, _ := updateOwnershipFixture(t)
		stored, err := repo.GetScanByUUID(context.Background(), scan.UUID)
		if err != nil {
			t.Fatal(err)
		}
		stored.Status = "paused"
		if err := repo.UpdateScan(context.Background(), stored); err != nil {
			t.Fatalf("UpdateScan same owner: %v", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "paused", time.Time{})
		if err := repo.UpdateScanPartial(context.Background(), &Scan{UUID: scan.UUID, Status: "running"}); err != nil {
			t.Fatalf("UpdateScanPartial status: %v", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "running", time.Time{})
	})
}

func TestUpdateScanPartialRejectsForeignProjectAndAgenticParent(t *testing.T) {
	t.Run("foreign-project", func(t *testing.T) {
		repo, scan, _, _ := updateOwnershipFixture(t)
		patch := &Scan{UUID: scan.UUID, ProjectUUID: "update-project-b", Status: "completed", FinishedAt: time.Date(2026, 11, 10, 12, 45, 0, 0, time.UTC)}
		if err := repo.UpdateScanPartial(context.Background(), patch); !errors.Is(err, ErrScanProjectMismatch) {
			t.Fatalf("UpdateScanPartial foreign project error = %v, want ErrScanProjectMismatch", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "running", time.Time{})
	})

	t.Run("foreign-agentic-parent", func(t *testing.T) {
		repo, scan, _, foreignParent := updateOwnershipFixture(t)
		patch := &Scan{UUID: scan.UUID, AgenticScanUUID: foreignParent.UUID, Status: "completed", FinishedAt: time.Date(2026, 11, 10, 12, 45, 0, 0, time.UTC)}
		if err := repo.UpdateScanPartial(context.Background(), patch); !errors.Is(err, ErrScanProjectMismatch) {
			t.Fatalf("UpdateScanPartial foreign parent error = %v, want ErrScanProjectMismatch", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "running", time.Time{})
	})

	t.Run("empty-identity-fields-and-valid-status", func(t *testing.T) {
		repo, scan, _, _ := updateOwnershipFixture(t)
		if err := repo.UpdateScanPartial(context.Background(), &Scan{UUID: scan.UUID, ProjectUUID: "", AgenticScanUUID: "", Status: "paused"}); err != nil {
			t.Fatalf("UpdateScanPartial empty identity fields: %v", err)
		}
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "update-project-a", scan.AgenticScanUUID, "paused", time.Time{})
	})
}

func TestUpdateAgenticScanRejectsForeignProjectAndParent(t *testing.T) {
	t.Run("foreign-project", func(t *testing.T) {
		repo, _, run, _ := updateOwnershipFixture(t)
		patch := &AgenticScan{
			UUID: run.UUID, ProjectUUID: "update-project-b", Status: "completed",
			CompletedAt: time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC),
		}
		if err := repo.UpdateAgenticScan(context.Background(), patch); !errors.Is(err, ErrScanProjectMismatch) {
			t.Fatalf("UpdateAgenticScan foreign project error = %v, want ErrScanProjectMismatch", err)
		}
		assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, "update-project-a", run.ParentAgenticScanUUID, "running", time.Time{})
	})

	t.Run("foreign-agentic-parent", func(t *testing.T) {
		repo, _, run, foreignParent := updateOwnershipFixture(t)
		patch := &AgenticScan{
			UUID: run.UUID, ParentAgenticScanUUID: foreignParent.UUID, Status: "completed",
			CompletedAt: time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC),
		}
		if err := repo.UpdateAgenticScan(context.Background(), patch); !errors.Is(err, ErrScanProjectMismatch) {
			t.Fatalf("UpdateAgenticScan foreign parent error = %v, want ErrScanProjectMismatch", err)
		}
		assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, "update-project-a", run.ParentAgenticScanUUID, "running", time.Time{})
	})

	t.Run("valid-partial-status", func(t *testing.T) {
		repo, _, run, _ := updateOwnershipFixture(t)
		if err := repo.UpdateAgenticScan(context.Background(), &AgenticScan{UUID: run.UUID, Status: "paused"}); err != nil {
			t.Fatalf("UpdateAgenticScan partial status: %v", err)
		}
		assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, "update-project-a", run.ParentAgenticScanUUID, "paused", time.Time{})
	})
}

func TestPg_UpdateOwnershipGuards(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(openPGTestDB(t))
	parent := &AgenticScan{UUID: uuid.NewString(), ProjectUUID: "pg-update-a", Mode: "swarm", Status: "running"}
	foreignParent := &AgenticScan{UUID: uuid.NewString(), ProjectUUID: "pg-update-b", Mode: "swarm", Status: "running"}
	for _, run := range []*AgenticScan{parent, foreignParent} {
		if err := repo.CreateAgenticScan(ctx, run); err != nil {
			t.Fatalf("CreateAgenticScan(%s): %v", run.UUID, err)
		}
	}
	run := &AgenticScan{
		UUID: uuid.NewString(), ProjectUUID: "pg-update-a", ParentAgenticScanUUID: parent.UUID,
		Mode: "audit", Status: "running",
	}
	if err := repo.CreateAgenticScan(ctx, run); err != nil {
		t.Fatalf("CreateAgenticScan(child): %v", err)
	}
	scan := &Scan{
		UUID: uuid.NewString(), ProjectUUID: "pg-update-a", AgenticScanUUID: parent.UUID,
		Name: "pg update child", Status: "running",
	}
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan(child): %v", err)
	}

	if err := repo.UpdateAgenticScan(ctx, &AgenticScan{UUID: run.UUID, ProjectUUID: "pg-update-b", Status: "completed"}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("UpdateAgenticScan foreign project error = %v, want ErrScanProjectMismatch", err)
	}
	assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, "pg-update-a", parent.UUID, "running", time.Time{})
	if err := repo.UpdateAgenticScan(ctx, &AgenticScan{UUID: run.UUID, ParentAgenticScanUUID: foreignParent.UUID, Status: "completed"}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("UpdateAgenticScan foreign parent error = %v, want ErrScanProjectMismatch", err)
	}
	assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, "pg-update-a", parent.UUID, "running", time.Time{})

	full := &Scan{}
	if err := repo.DB().NewSelect().Model(full).Where("uuid = ?", scan.UUID).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	full.ProjectUUID = "pg-update-b"
	full.Status = "failed"
	if err := repo.UpdateScan(ctx, full); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("UpdateScan foreign project error = %v, want ErrScanProjectMismatch", err)
	}
	assertUpdatedScanUnchanged(t, repo, scan.UUID, "pg-update-a", parent.UUID, "running", time.Time{})
	if err := repo.UpdateScanPartial(ctx, &Scan{UUID: scan.UUID, AgenticScanUUID: foreignParent.UUID, Status: "failed"}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("UpdateScanPartial foreign parent error = %v, want ErrScanProjectMismatch", err)
	}
	assertUpdatedScanUnchanged(t, repo, scan.UUID, "pg-update-a", parent.UUID, "running", time.Time{})
}

func TestUpdateOwnershipAcceptsDefaultProjectAndSameProjectParents(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	parentUUID := uuid.NewString()
	parent := &AgenticScan{UUID: parentUUID, Mode: "swarm", Status: "running"}
	if err := repo.CreateAgenticScan(ctx, parent); err != nil {
		t.Fatalf("CreateAgenticScan(default parent): %v", err)
	}

	run := &AgenticScan{
		UUID: uuid.NewString(), ParentAgenticScanUUID: parentUUID, Mode: "audit", Status: "running",
	}
	if err := repo.CreateAgenticScan(ctx, run); err != nil {
		t.Fatalf("CreateAgenticScan(default child): %v", err)
	}
	scan := &Scan{UUID: uuid.NewString(), AgenticScanUUID: parentUUID, Name: "default scan", Status: "running"}
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan(default child): %v", err)
	}
	if run.ProjectUUID != DefaultProjectUUID || scan.ProjectUUID != DefaultProjectUUID {
		t.Fatalf("default child projects run=%q scan=%q", run.ProjectUUID, scan.ProjectUUID)
	}

	if err := repo.UpdateAgenticScan(ctx, &AgenticScan{UUID: run.UUID, Status: "completed"}); err != nil {
		t.Fatalf("UpdateAgenticScan(default-project status): %v", err)
	}
	if err := repo.UpdateScanPartial(ctx, &Scan{UUID: scan.UUID, Status: "paused"}); err != nil {
		t.Fatalf("UpdateScanPartial(default-project status): %v", err)
	}
	assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, DefaultProjectUUID, parentUUID, "completed", time.Time{})
	assertUpdatedScanUnchanged(t, repo, scan.UUID, DefaultProjectUUID, parentUUID, "paused", time.Time{})

	t.Run("historical-unknown-parent-preserved", func(t *testing.T) {
		repo := NewRepository(newTestDB(t))
		unknownParentUUID := uuid.NewString()
		run := &AgenticScan{
			UUID: uuid.NewString(), ProjectUUID: "legacy-project", ParentAgenticScanUUID: unknownParentUUID,
			Mode: "audit", Status: "running",
		}
		if err := repo.CreateAgenticScan(ctx, run); err != nil {
			t.Fatalf("CreateAgenticScan(historical unknown parent): %v", err)
		}
		scan := &Scan{
			UUID: uuid.NewString(), ProjectUUID: "legacy-project", AgenticScanUUID: unknownParentUUID,
			Name: "historical scan", Status: "running",
		}
		if err := repo.CreateScan(ctx, scan); err != nil {
			t.Fatalf("CreateScan(historical unknown parent): %v", err)
		}

		if err := repo.UpdateAgenticScan(ctx, &AgenticScan{UUID: run.UUID, Status: "paused"}); err != nil {
			t.Fatalf("UpdateAgenticScan with historical unknown parent: %v", err)
		}
		storedScan, err := repo.GetScanByUUID(ctx, scan.UUID)
		if err != nil {
			t.Fatal(err)
		}
		storedScan.Status = "paused"
		if err := repo.UpdateScan(ctx, storedScan); err != nil {
			t.Fatalf("UpdateScan with historical unknown parent: %v", err)
		}
		if err := repo.UpdateScanPartial(ctx, &Scan{UUID: scan.UUID, Status: "running"}); err != nil {
			t.Fatalf("UpdateScanPartial with historical unknown parent: %v", err)
		}
		assertUpdatedAgenticRunUnchanged(t, repo, run.UUID, "legacy-project", unknownParentUUID, "paused", time.Time{})
		assertUpdatedScanUnchanged(t, repo, scan.UUID, "legacy-project", unknownParentUUID, "running", time.Time{})
	})
}
