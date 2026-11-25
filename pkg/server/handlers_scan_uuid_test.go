package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestHandleRunScanRejectsInvalidScanUUIDBeforeWriting(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	settings := config.DefaultSettings()
	root := t.TempDir()
	sessionsDir := filepath.Join(root, "sessions")
	settings.ScanningStrategy.ScanLogs.SessionsDir = sessionsDir

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, settings)
	app := fiber.New()
	app.Post("/api/scans/run", h.HandleRunScan)

	status, body := doReq(t, app, http.MethodPost, "/api/scans/run", `{"targets":["https://example.test"],"scan_uuid":"../outside"}`, nil)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "canonical lowercase UUID") {
		t.Fatalf("status = %d body = %s, want 400 explaining invalid scan_uuid", status, body)
	}
	if _, err := os.Stat(filepath.Join(root, "outside")); !os.IsNotExist(err) {
		t.Fatalf("invalid scan UUID created a path outside sessions root: stat err=%v", err)
	}
	if _, err := os.Stat(sessionsDir); !os.IsNotExist(err) {
		t.Fatalf("invalid scan UUID created the sessions root: stat err=%v", err)
	}
	if _, err := repo.GetScanByUUID(t.Context(), "../outside"); err == nil {
		t.Fatal("invalid scan UUID created a database row")
	}
}

func TestAgentRunHandlersRejectInvalidPinnedUUID(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	app := fiber.New()
	app.Post("/api/agent/run/query", h.HandleAgentQuery)
	app.Post("/api/agent/run/autopilot", h.HandleAgentAutopilot)
	app.Post("/api/agent/run/swarm", h.HandleAgentSwarm)
	app.Post("/api/agent/run/audit", h.HandleAgentAudit)

	for _, path := range []string{
		"/api/agent/run/query",
		"/api/agent/run/autopilot",
		"/api/agent/run/swarm",
		"/api/agent/run/audit",
	} {
		t.Run(path, func(t *testing.T) {
			status, body := doReq(t, app, http.MethodPost, path, `{"scan_uuid":"../outside"}`, nil)
			if status != http.StatusBadRequest || !strings.Contains(string(body), "canonical lowercase UUID") {
				t.Fatalf("status = %d body = %s, want 400 explaining invalid scan_uuid", status, body)
			}
		})
	}
}

func TestRegisterRunningAgenticScanRejectsInvalidPinnedUUID(t *testing.T) {
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, nil)
	if _, err := h.registerRunningAgenticScan("autopilot", "olium", "../outside", database.DefaultProjectUUID); err == nil {
		t.Fatal("registerRunningAgenticScan accepted an invalid pinned UUID")
	}
}
