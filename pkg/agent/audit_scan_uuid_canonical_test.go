package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestAuditRunDoesNotAdoptNonUUIDSessionDirectoryName(t *testing.T) {
	ctx := context.Background()
	repo := newAuditTestRepo(t)
	const legacyDirName = "api-1234abcd"
	const originalSessionDir = "/original/session"
	if err := repo.CreateAgenticScan(ctx, &database.AgenticScan{
		UUID:        legacyDirName,
		ProjectUUID: database.DefaultProjectUUID,
		Mode:        "autopilot",
		AgentName:   "original-run",
		Status:      "completed",
		SessionDir:  originalSessionDir,
	}); err != nil {
		t.Fatalf("seed existing run: %v", err)
	}

	sessionDir := filepath.Join(t.TempDir(), legacyDirName)
	if err := os.MkdirAll(sessionDir, 0o700); err != nil {
		t.Fatalf("create colliding session dir: %v", err)
	}
	scanner := NewAuditAgenticScanner(AuditAgentConfig{
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
	}, repo)

	if _, err := uuid.Parse(scanner.agenticScanUUID); err != nil {
		t.Errorf("audit run UUID %q inherited a non-UUID session directory name: %v", scanner.agenticScanUUID, err)
	}
	scanner.createAgenticScan(ctx)

	stored, err := repo.GetAgenticScan(ctx, scanner.agenticScanUUID)
	if err != nil {
		t.Fatalf("load audit run %q: %v", scanner.agenticScanUUID, err)
	}
	if stored.SessionDir != sessionDir {
		t.Errorf("audit run was silently attached to existing row %q with session dir %q; want a distinct run for %q",
			stored.UUID, stored.SessionDir, sessionDir)
	}
}
