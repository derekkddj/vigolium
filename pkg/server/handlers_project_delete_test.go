package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func createDeleteTestProject(t *testing.T, repo *database.Repository, projectUUID string) {
	t.Helper()
	if err := repo.CreateProject(context.Background(), &database.Project{
		UUID: projectUUID, Name: "delete-test", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create project %s: %v", projectUUID, err)
	}
}

func projectRowCount(t *testing.T, db *database.DB, table, projectUUID string) int {
	t.Helper()
	var count int
	if err := db.NewRaw("SELECT COUNT(*) FROM "+table+" WHERE project_uuid = ?", projectUUID).Scan(context.Background(), &count); err != nil {
		t.Fatalf("count %s for %s: %v", table, projectUUID, err)
	}
	return count
}

func TestHandleDeleteProject_PurgeModeDoesNotReassignData(t *testing.T) {
	const purgeUUID = "11111111-1111-1111-1111-111111111111"
	const otherUUID = "22222222-2222-2222-2222-222222222222"
	t.Setenv("HOME", t.TempDir())
	db, repo := newPinnedTestDB(t)
	createDeleteTestProject(t, repo, purgeUUID)
	createDeleteTestProject(t, repo, otherUUID)

	insertRecord(t, db, purgeUUID)
	insertFindingReturning(t, db, purgeUUID)
	insertScan(t, db, repo, purgeUUID)
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{
		UUID: "33333333-3333-3333-3333-333333333333", ProjectUUID: purgeUUID,
		Mode: "query", AgentName: "olium", Status: "completed",
	}); err != nil {
		t.Fatalf("create agentic scan: %v", err)
	}
	insertRecord(t, db, otherUUID)
	insertFindingReturning(t, db, otherUUID)
	insertScan(t, db, repo, otherUUID)
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{
		UUID: "44444444-4444-4444-4444-444444444444", ProjectUUID: otherUUID,
		Mode: "query", AgentName: "olium", Status: "completed",
	}); err != nil {
		t.Fatalf("create other project's agentic scan: %v", err)
	}

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Delete("/api/projects/:uuid", h.HandleDeleteProject)
	status, body := doReq(t, app, http.MethodDelete, "/api/projects/"+purgeUUID+"?delete_data=true", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", status, body)
	}

	for _, table := range []string{"http_records", "findings", "scans", "agentic_scans"} {
		if got := projectRowCount(t, db, table, purgeUUID); got != 0 {
			t.Errorf("purge left %d rows in %s for deleted project", got, table)
		}
		if got := projectRowCount(t, db, table, database.DefaultProjectUUID); got != 0 {
			t.Errorf("purge reassigned %d rows from %s into the default project in %s", got, purgeUUID, table)
		}
		if got := projectRowCount(t, db, table, otherUUID); got != 1 {
			t.Errorf("purge changed other project's %s rows: got %d, want 1", table, got)
		}
	}

	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode response: %v; body %s", err, body)
	}
	if got := response["mode"]; got != "purge" {
		t.Errorf("response mode = %v, want purge", got)
	}
}

func TestHandleDeleteProject_DefaultModeReassignsToDefault(t *testing.T) {
	for _, query := range []string{"", "?delete_data=false"} {
		t.Run("query="+query, func(t *testing.T) {
			const projectUUID = "55555555-5555-5555-5555-555555555555"
			db, repo := newPinnedTestDB(t)
			createDeleteTestProject(t, repo, projectUUID)
			insertRecord(t, db, projectUUID)

			h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
			app := fiber.New()
			app.Delete("/api/projects/:uuid", h.HandleDeleteProject)
			status, body := doReq(t, app, http.MethodDelete, "/api/projects/"+projectUUID+query, "", nil)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", status, body)
			}
			if got := projectRowCount(t, db, "http_records", database.DefaultProjectUUID); got != 1 {
				t.Errorf("default project received %d records, want 1", got)
			}
			var response DeleteProjectResponse
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("decode response: %v; body %s", err, body)
			}
			if response.Mode != "reassign_to_default" {
				t.Errorf("mode = %q, want reassign_to_default", response.Mode)
			}
		})
	}
}

func TestHandleDeleteProject_PurgeRejectsDefaultAndInvalidMode(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Delete("/api/projects/:uuid", h.HandleDeleteProject)

	if status, _ := doReq(t, app, http.MethodDelete, "/api/projects/"+database.DefaultProjectUUID+"?delete_data=true", "", nil); status != http.StatusBadRequest {
		t.Errorf("default-project purge status = %d, want 400", status)
	}
	const projectUUID = "66666666-6666-6666-6666-666666666666"
	createDeleteTestProject(t, repo, projectUUID)
	if status, _ := doReq(t, app, http.MethodDelete, "/api/projects/"+projectUUID+"?delete_data=yes", "", nil); status != http.StatusBadRequest {
		t.Errorf("invalid delete_data status = %d, want 400", status)
	}
	if _, err := repo.GetProjectByUUID(context.Background(), projectUUID); err != nil {
		t.Fatalf("invalid mode deleted project: %v", err)
	}
}

func createProjectSessionTestDir(t *testing.T, root, uuid string) string {
	t.Helper()
	path := filepath.Join(root, uuid)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("create session directory %s: %v", path, err)
	}
	if err := os.WriteFile(filepath.Join(path, "artifact.txt"), []byte("test"), 0o600); err != nil {
		t.Fatalf("create session artifact: %v", err)
	}
	return path
}

func TestHandleDeleteProject_PurgeRemovesOnlyOwnedDiskDirectories(t *testing.T) {
	const projectUUID = "77777777-7777-7777-7777-777777777777"
	const otherUUID = "88888888-8888-8888-8888-888888888888"
	const scanUUID = "99999999-9999-9999-9999-999999999999"
	const runUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const otherScanUUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	home := t.TempDir()
	t.Setenv("HOME", home)
	nativeRoot := filepath.Join(home, ".vigolium", "native-sessions")
	agentRoot := filepath.Join(home, ".vigolium", "agent-sessions")
	projectConfigDir := filepath.Join(home, ".vigolium", "projects", projectUUID)
	nativeDir := createProjectSessionTestDir(t, nativeRoot, scanUUID)
	agentDir := createProjectSessionTestDir(t, agentRoot, runUUID)
	otherNativeDir := createProjectSessionTestDir(t, nativeRoot, otherScanUUID)
	if err := os.MkdirAll(projectConfigDir, 0o755); err != nil {
		t.Fatalf("create project config directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectConfigDir, "settings.yaml"), []byte("test"), 0o600); err != nil {
		t.Fatalf("create project config file: %v", err)
	}

	db, repo := newPinnedTestDB(t)
	createDeleteTestProject(t, repo, projectUUID)
	createDeleteTestProject(t, repo, otherUUID)
	for _, row := range []struct{ uuid, project string }{{scanUUID, projectUUID}, {otherScanUUID, otherUUID}} {
		if err := repo.CreateScan(context.Background(), &database.Scan{
			UUID: row.uuid, ProjectUUID: row.project, Name: "test", Status: "completed", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("create scan %s: %v", row.uuid, err)
		}
	}
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{
		UUID: runUUID, ProjectUUID: projectUUID, Mode: "query", AgentName: "olium", Status: "completed",
	}); err != nil {
		t.Fatalf("create agent run: %v", err)
	}

	settings := config.DefaultSettings()
	settings.ScanningStrategy.ScanLogs.SessionsDir = nativeRoot
	settings.Agent.SessionsDir = agentRoot
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, settings)
	app := fiber.New()
	app.Delete("/api/projects/:uuid", h.HandleDeleteProject)
	status, body := doReq(t, app, http.MethodDelete, "/api/projects/"+projectUUID+"?delete_data=true", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", status, body)
	}
	var response DeleteProjectResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode response: %v; body %s", err, body)
	}
	if !response.ConfigDirDeleted || response.SessionDirsDeleted != 2 || len(response.DiskDeletionFailures) != 0 {
		t.Errorf("unexpected deletion summary: %+v", response)
	}
	for _, path := range []string{projectConfigDir, nativeDir, agentDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("owned path %s still exists (stat error %v)", path, err)
		}
	}
	if _, err := os.Stat(otherNativeDir); err != nil {
		t.Errorf("other project's session directory was removed: %v", err)
	}
	if response.RowsDeleted["projects"] != 1 || response.RowsDeleted["scans"] != 1 || response.RowsDeleted["agentic_scans"] != 1 {
		t.Errorf("rows_deleted summary misses deleted rows: %+v", response.RowsDeleted)
	}
}

func TestHandleDeleteProject_PurgeReportsFilesystemFailures(t *testing.T) {
	const projectUUID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
	const scanUUID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
	home := t.TempDir()
	t.Setenv("HOME", home)
	nativeRoot := filepath.Join(home, ".vigolium", "native-sessions")
	scanDir := createProjectSessionTestDir(t, nativeRoot, scanUUID)
	projectConfigDir := filepath.Join(home, ".vigolium", "projects", projectUUID)
	if err := os.MkdirAll(projectConfigDir, 0o755); err != nil {
		t.Fatalf("create project config directory: %v", err)
	}

	db, repo := newPinnedTestDB(t)
	createDeleteTestProject(t, repo, projectUUID)
	if err := repo.CreateScan(context.Background(), &database.Scan{
		UUID: scanUUID, ProjectUUID: projectUUID, Name: "test", Status: "completed", StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	settings := config.DefaultSettings()
	settings.ScanningStrategy.ScanLogs.SessionsDir = nativeRoot
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, settings)
	h.removeAll = func(path string) error {
		if path == projectConfigDir {
			return errors.New("simulated remove failure")
		}
		return os.RemoveAll(path)
	}
	app := fiber.New()
	app.Delete("/api/projects/:uuid", h.HandleDeleteProject)
	status, body := doReq(t, app, http.MethodDelete, "/api/projects/"+projectUUID+"?delete_data=true", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", status, body)
	}
	var response DeleteProjectResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode response: %v; body %s", err, body)
	}
	if response.ConfigDirDeleted || response.SessionDirsDeleted != 1 || len(response.DiskDeletionFailures) != 1 || response.DiskDeletionFailures[0] != projectConfigDir {
		t.Errorf("filesystem failure not accurately reported: %+v", response)
	}
	if got := projectRowCount(t, db, "scans", projectUUID); got != 0 {
		t.Errorf("database purge rolled back after disk failure: scans left=%d", got)
	}
	if _, err := os.Stat(scanDir); !os.IsNotExist(err) {
		t.Errorf("successful session cleanup failed: %v", err)
	}
	if _, err := os.Stat(projectConfigDir); err != nil {
		t.Errorf("failed config directory unexpectedly disappeared: %v", err)
	}
}

func TestHandleDeleteProject_PurgeRejectsUnsafeSessionPaths(t *testing.T) {
	const projectUUID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	const traversalUUID = "../outside"
	const symlinkUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	home := t.TempDir()
	t.Setenv("HOME", home)
	nativeRoot := filepath.Join(home, ".vigolium", "native-sessions")
	traversalTarget := filepath.Join(home, ".vigolium", "outside")
	symlinkTarget := filepath.Join(home, "external-session")
	for _, path := range []string{traversalTarget, symlinkTarget} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create external target %s: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(path, "keep.txt"), []byte("keep"), 0o600); err != nil {
			t.Fatalf("create external marker: %v", err)
		}
	}
	if err := os.MkdirAll(nativeRoot, 0o755); err != nil {
		t.Fatalf("create native root: %v", err)
	}
	if err := os.Symlink(symlinkTarget, filepath.Join(nativeRoot, symlinkUUID)); err != nil {
		t.Fatalf("create session symlink: %v", err)
	}

	db, repo := newPinnedTestDB(t)
	createDeleteTestProject(t, repo, projectUUID)
	for _, scanUUID := range []string{traversalUUID, symlinkUUID} {
		if err := repo.CreateScan(context.Background(), &database.Scan{
			UUID: scanUUID, ProjectUUID: projectUUID, Name: "test", Status: "completed", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("create scan %s: %v", scanUUID, err)
		}
	}
	settings := config.DefaultSettings()
	settings.ScanningStrategy.ScanLogs.SessionsDir = nativeRoot
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, settings)
	app := fiber.New()
	app.Delete("/api/projects/:uuid", h.HandleDeleteProject)
	status, body := doReq(t, app, http.MethodDelete, "/api/projects/"+projectUUID+"?delete_data=true", "", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", status, body)
	}
	var response DeleteProjectResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode response: %v; body %s", err, body)
	}
	if len(response.DiskDeletionFailures) != 2 {
		t.Errorf("unsafe paths failures = %v, want both unsafe paths reported", response.DiskDeletionFailures)
	}
	for _, marker := range []string{filepath.Join(traversalTarget, "keep.txt"), filepath.Join(symlinkTarget, "keep.txt")} {
		if _, err := os.Stat(marker); err != nil {
			t.Errorf("unsafe target %s was removed: %v", marker, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(nativeRoot, symlinkUUID)); err != nil {
		t.Errorf("unsafe session symlink was removed: %v", err)
	}
	for _, failure := range response.DiskDeletionFailures {
		if strings.TrimSpace(failure) == "" {
			t.Error("disk deletion failure path must not be empty")
		}
	}
}
