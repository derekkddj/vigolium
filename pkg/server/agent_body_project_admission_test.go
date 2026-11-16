package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

const (
	admissionHeaderProject    = "11111111-1111-4111-8111-111111111111"
	admissionBodyProject      = "22222222-2222-4222-8222-222222222222"
	admissionUnknownProject   = "33333333-3333-4333-8333-333333333333"
	admissionMalformedProject = "not-a-project-uuid"
)

type agentAdmissionRoute struct {
	name string
	path string
	mode string
}

var agentAdmissionRoutes = []agentAdmissionRoute{
	{name: "query", path: "/api/agent/run/query", mode: "query"},
	{name: "autopilot", path: "/api/agent/run/autopilot", mode: "autopilot"},
	{name: "swarm", path: "/api/agent/run/swarm", mode: "swarm"},
}

// These tests keep the REST admission boundary distinct from repository
// compatibility: repositories intentionally accept arbitrary project IDs, but
// the REST-selected project should receive the same UUID/existence checks as
// X-Project-UUID. A minimal fix can select a non-empty body ProjectUUID first,
// otherwise use getProjectUUID(c), then apply validProjectUUID and
// GetProjectByUUID before admission. Preserve body-over-header precedence and
// run this check before swarm's optional base64 traffic ingestion; do not add a
// project lookup to general database write APIs.
func newAgentBodyProjectAdmissionApp(t *testing.T) (*Handlers, *database.Repository, *fiber.App) {
	t.Helper()
	h, repo, _ := newAgentTestHandlers(t)
	// Drain any admitted background run before the fixture closes its DB. The
	// configured test provider is invalid, so execution fails locally without
	// making an LLM or external-network request. h.Close also stops the cleanup
	// ticker; newAgentTestHandlers' cleanup safely tolerates that channel already
	// being closed.
	t.Cleanup(func() {
		if h.runCancel != nil {
			h.runCancel()
		}
		defer h.Close()
		awaitAgentAdmissionPersistence(t, h, repo, 10*time.Second)
	})
	for _, project := range []*database.Project{
		{UUID: admissionHeaderProject, Name: "admission-header"},
		{UUID: admissionBodyProject, Name: "admission-body"},
	} {
		if err := repo.CreateProject(context.Background(), project); err != nil {
			t.Fatalf("CreateProject(%s): %v", project.UUID, err)
		}
	}

	app := fiber.New(fiber.Config{ErrorHandler: apiErrorHandler})
	app.Use(apiVersionMiddleware(1))
	app.Use(ProjectUUIDMiddleware(repo))
	app.Post("/api/agent/run/query", h.HandleAgentQuery)
	app.Post("/api/agent/run/autopilot", h.HandleAgentAutopilot)
	app.Post("/api/agent/run/swarm", h.HandleAgentSwarm)
	return h, repo, app
}

// awaitAgentAdmissionPersistence waits for each admitted run to reach terminal
// in-memory state and for that terminal status plus CompletedAt to be durable in
// the repository. This keeps detached run finalizers from racing the fixture's
// DB cleanup, including when an assertion calls Fatal before test return.
func awaitAgentAdmissionPersistence(t *testing.T, h *Handlers, repo *database.Repository, timeout time.Duration) {
	t.Helper()
	h.agentMu.Lock()
	pending := make(map[string]struct{}, len(h.agenticScanStatus))
	for uuid := range h.agenticScanStatus {
		pending[uuid] = struct{}{}
	}
	h.agentMu.Unlock()
	if len(pending) == 0 {
		return
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for len(pending) > 0 {
		h.agentMu.Lock()
		memoryTerminal := make([]string, 0, len(pending))
		for uuid := range pending {
			if state := h.agenticScanStatus[uuid]; state != nil && isTerminalAgentStatus(state.Status) {
				memoryTerminal = append(memoryTerminal, uuid)
			}
		}
		h.agentMu.Unlock()
		for _, uuid := range memoryTerminal {
			run, err := repo.GetAgenticScan(context.Background(), uuid)
			if err != nil || !isTerminalAgentStatus(run.Status) || run.CompletedAt.IsZero() {
				continue
			}
			h.runCancelMu.Lock()
			_, active := h.runCancels[uuid]
			h.runCancelMu.Unlock()
			if active {
				continue
			}
			if (run.Mode == "query" && len(h.agentLightSem) != 0) || (run.Mode != "query" && len(h.agentHeavySem) != 0) {
				continue
			}
			delete(pending, uuid)
		}
		if len(pending) == 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Errorf("agent runs did not reach terminal persisted state before cleanup: %v", pending)
			return
		}
	}
}

func agentAdmissionBody(t *testing.T, route agentAdmissionRoute, sourcePath, projectUUID string, ingestSwarmRecord bool) map[string]any {
	t.Helper()
	body := map[string]any{"project_uuid": projectUUID}
	switch route.name {
	case "query":
		body["prompt"] = "admission test prompt"
	case "autopilot":
		body["source"] = sourcePath
		body["intensity"] = "quick"
		body["timeout"] = "50ms"
		body["no_audit"] = true
	case "swarm":
		if ingestSwarmRecord {
			body["http_request_base64"] = base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: admission.invalid\r\n\r\n"))
			body["http_response_base64"] = base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			body["url"] = "https://admission.invalid/"
		} else {
			body["source"] = sourcePath
			body["source_analysis_only"] = true
		}
		body["intensity"] = "quick"
		body["timeout"] = "50ms"
	default:
		t.Fatalf("unexpected agent admission route %q", route.name)
	}
	return body
}

func postAgentAdmissionJSON(t *testing.T, app *fiber.App, route agentAdmissionRoute, body map[string]any, projectHeader string) (int, []byte) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, route.path, strings.NewReader(string(encoded)))
	req.Header.Set("Content-Type", "application/json")
	if projectHeader != "" {
		req.Header.Set("X-Project-UUID", projectHeader)
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("POST %s: %v", route.path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s response: %v", route.path, err)
	}
	return resp.StatusCode, data
}

func agentAdmissionErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var response ErrorResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode error response %q: %v", body, err)
	}
	return response.ErrorCode
}

func assertAgentAdmissionSelectedProject(t *testing.T, h *Handlers, repo *database.Repository, app *fiber.App, route agentAdmissionRoute, expectedProject, bodyProject string) {
	t.Helper()
	code, responseBody := postAgentAdmissionJSON(t, app, route,
		agentAdmissionBody(t, route, t.TempDir(), bodyProject, false), admissionHeaderProject)
	if code != http.StatusAccepted {
		t.Fatalf("POST %s status = %d, want 202; body=%s", route.path, code, responseBody)
	}
	var response AgenticScanResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("decode accepted response %q: %v", responseBody, err)
	}
	if response.AgenticScanUUID == "" {
		t.Fatalf("accepted response has no agentic_scan_uuid: %s", responseBody)
	}
	run, err := repo.GetAgenticScan(context.Background(), response.AgenticScanUUID)
	if err != nil {
		t.Fatalf("GetAgenticScan(%s): %v", response.AgenticScanUUID, err)
	}
	if run.ProjectUUID != expectedProject {
		t.Errorf("persisted project_uuid = %q, want selected project %q", run.ProjectUUID, expectedProject)
	}
	_, headerCount, err := repo.ListAgenticScans(context.Background(), admissionHeaderProject, route.mode, 100, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans(header project): %v", err)
	}
	wantHeaderCount := int64(0)
	if expectedProject == admissionHeaderProject {
		wantHeaderCount = 1
	}
	if headerCount != wantHeaderCount {
		t.Errorf("header project has %d %s runs, want %d", headerCount, route.mode, wantHeaderCount)
	}
	h.agentMu.Lock()
	state := h.agenticScanStatus[response.AgenticScanUUID]
	var stateProject string
	if state != nil {
		stateProject = state.ProjectUUID
	}
	h.agentMu.Unlock()
	if stateProject != expectedProject {
		t.Errorf("in-memory project_uuid = %q, want selected project %q", stateProject, expectedProject)
	}
}

func TestAgentBodyProjectAdmission_ValidBodyOverridesHeaderAndEmptyFallsBack(t *testing.T) {
	for _, route := range agentAdmissionRoutes {
		t.Run(route.name+"/body-overrides-header", func(t *testing.T) {
			h, repo, app := newAgentBodyProjectAdmissionApp(t)
			assertAgentAdmissionSelectedProject(t, h, repo, app, route, admissionBodyProject, admissionBodyProject)
		})
		t.Run(route.name+"/empty-body-falls-back-to-header", func(t *testing.T) {
			h, repo, app := newAgentBodyProjectAdmissionApp(t)
			assertAgentAdmissionSelectedProject(t, h, repo, app, route, admissionHeaderProject, "")
		})
	}
}

func assertNoAgentAdmissionWrites(t *testing.T, h *Handlers, repo *database.Repository, route agentAdmissionRoute, rejectedProject string) {
	t.Helper()
	_, count, err := repo.ListAgenticScans(context.Background(), rejectedProject, route.mode, 100, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans(rejected project): %v", err)
	}
	if count != 0 {
		t.Errorf("rejected project %q has %d persisted %s runs", rejectedProject, count, route.mode)
	}

	h.agentMu.Lock()
	var rejectedStates int
	for _, state := range h.agenticScanStatus {
		if state.ProjectUUID == rejectedProject {
			rejectedStates++
		}
	}
	h.agentMu.Unlock()
	if rejectedStates != 0 {
		t.Errorf("rejected project %q has %d in-memory agent states", rejectedProject, rejectedStates)
	}

	records, err := repo.CountRecordsAfterCursor(context.Background(), rejectedProject, time.Time{}, "")
	if err != nil {
		t.Fatalf("CountRecordsAfterCursor(rejected project): %v", err)
	}
	if records != 0 {
		t.Errorf("rejected project %q has %d persisted HTTP records", rejectedProject, records)
	}
}

func TestAgentBodyProjectAdmission_RejectsMalformedBodyProjectBeforeWrites(t *testing.T) {
	for _, route := range agentAdmissionRoutes {
		t.Run(route.name, func(t *testing.T) {
			h, repo, app := newAgentBodyProjectAdmissionApp(t)
			sourcePath := t.TempDir()
			// Establish the exact header-admission response contract on this route.
			headerStatus, headerBody := postAgentAdmissionJSON(t, app, route,
				agentAdmissionBody(t, route, sourcePath, "", route.name == "swarm"), admissionMalformedProject)
			if headerStatus != http.StatusBadRequest || agentAdmissionErrorCode(t, headerBody) != string(apicontract.CodeInvalidProjectUUID) {
				t.Fatalf("malformed header contract = (%d, %s), want (400, %s)", headerStatus, headerBody, apicontract.CodeInvalidProjectUUID)
			}

			body := agentAdmissionBody(t, route, sourcePath, admissionMalformedProject, route.name == "swarm")
			bodyStatus, bodyResponse := postAgentAdmissionJSON(t, app, route, body, admissionHeaderProject)
			if bodyStatus != headerStatus || agentAdmissionErrorCode(t, bodyResponse) != agentAdmissionErrorCode(t, headerBody) {
				t.Errorf("malformed body project response = (%d, %s), want header admission's (%d, %s)", bodyStatus, bodyResponse, headerStatus, headerBody)
			}
			assertNoAgentAdmissionWrites(t, h, repo, route, admissionMalformedProject)
		})
	}
}

func TestAgentBodyProjectAdmission_RejectsUnknownBodyProjectBeforeWrites(t *testing.T) {
	for _, route := range agentAdmissionRoutes {
		t.Run(route.name, func(t *testing.T) {
			h, repo, app := newAgentBodyProjectAdmissionApp(t)
			sourcePath := t.TempDir()
			// A canonical but unregistered header is the established 404 contract.
			headerStatus, headerBody := postAgentAdmissionJSON(t, app, route,
				agentAdmissionBody(t, route, sourcePath, "", route.name == "swarm"), admissionUnknownProject)
			if headerStatus != http.StatusNotFound || agentAdmissionErrorCode(t, headerBody) != string(apicontract.CodeProjectNotFound) {
				t.Fatalf("unknown header contract = (%d, %s), want (404, %s)", headerStatus, headerBody, apicontract.CodeProjectNotFound)
			}

			body := agentAdmissionBody(t, route, sourcePath, admissionUnknownProject, route.name == "swarm")
			bodyStatus, bodyResponse := postAgentAdmissionJSON(t, app, route, body, admissionHeaderProject)
			if bodyStatus != headerStatus || agentAdmissionErrorCode(t, bodyResponse) != agentAdmissionErrorCode(t, headerBody) {
				t.Errorf("unknown body project response = (%d, %s), want header admission's (%d, %s)", bodyStatus, bodyResponse, headerStatus, headerBody)
			}
			assertNoAgentAdmissionWrites(t, h, repo, route, admissionUnknownProject)
		})
	}
}
