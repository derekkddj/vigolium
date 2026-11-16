package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

var auditBodyProjectAdmissionDrivers = []struct {
	name   string
	driver string
}{
	{name: "default-auto"},
	{name: "audit", driver: agent.AuditDriverAudit},
	{name: "piolium", driver: agent.AuditDriverPiolium},
	{name: "both", driver: agent.AuditDriverBoth},
}

func newAuditBodyProjectAdmissionApp(t *testing.T) (*Handlers, *database.Repository, *fiber.App) {
	t.Helper()
	h, repo, app := newAgentBodyProjectAdmissionApp(t)
	app.Post("/api/agent/run/audit", h.HandleAgentAudit)
	return h, repo, app
}

func auditBodyProjectAdmissionBody(t *testing.T, driver, projectUUID string) map[string]any {
	t.Helper()
	body := map[string]any{
		// A missing source terminates in source resolution before any driver
		// process can start, while still exercising the endpoint's admission path.
		"source":       filepath.Join(t.TempDir(), "missing-audit-source"),
		"project_uuid": projectUUID,
		"mode":         "lite",
	}
	if driver != "" {
		body["driver"] = driver
	}
	return body
}

func postAuditBodyProjectAdmission(t *testing.T, app *fiber.App, body map[string]any, projectHeader string) (int, []byte) {
	t.Helper()
	return postAgentAdmissionJSON(t, app, agentAdmissionRoute{
		name: "audit",
		path: "/api/agent/run/audit",
		mode: "audit",
	}, body, projectHeader)
}

func assertAuditAdmissionSelectedProject(t *testing.T, h *Handlers, repo *database.Repository, app *fiber.App, driver, expectedProject, bodyProject string) {
	t.Helper()
	status, responseBody := postAuditBodyProjectAdmission(t, app,
		auditBodyProjectAdmissionBody(t, driver, bodyProject), admissionHeaderProject)
	if status != http.StatusAccepted {
		t.Fatalf("POST /api/agent/run/audit status = %d, want 202; body=%s", status, responseBody)
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
	_, headerCount, err := repo.ListAgenticScans(context.Background(), admissionHeaderProject, "audit", 100, 0)
	if err != nil {
		t.Fatalf("ListAgenticScans(header project): %v", err)
	}
	wantHeaderCount := int64(0)
	if expectedProject == admissionHeaderProject {
		wantHeaderCount = 1
	}
	if headerCount != wantHeaderCount {
		t.Errorf("header project has %d audit runs, want %d", headerCount, wantHeaderCount)
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

func auditBodyProjectDriverAvailable(h *Handlers, driver string) bool {
	switch driver {
	case agent.AuditDriverAudit:
		available, _ := h.auditAvailable(&AgentAuditRequest{})
		return available
	case agent.AuditDriverPiolium:
		return h.pioliumAvailableCached()
	default:
		// auto/default and both accept requests even when one or both runtimes
		// are absent; the missing source prevents either runtime from starting.
		return true
	}
}

func TestAuditBodyProjectAdmission_ValidBodyOverridesHeaderAndEmptyFallsBack(t *testing.T) {
	for _, driverCase := range auditBodyProjectAdmissionDrivers {
		t.Run(driverCase.name+"/body-overrides-header", func(t *testing.T) {
			h, repo, app := newAuditBodyProjectAdmissionApp(t)
			if !auditBodyProjectDriverAvailable(h, driverCase.driver) {
				t.Skip("requested single-driver runtime is unavailable; body rejection is covered independently")
			}
			assertAuditAdmissionSelectedProject(t, h, repo, app, driverCase.driver,
				admissionBodyProject, admissionBodyProject)
		})
		t.Run(driverCase.name+"/empty-body-falls-back-to-header", func(t *testing.T) {
			h, repo, app := newAuditBodyProjectAdmissionApp(t)
			if !auditBodyProjectDriverAvailable(h, driverCase.driver) {
				t.Skip("requested single-driver runtime is unavailable; body rejection is covered independently")
			}
			assertAuditAdmissionSelectedProject(t, h, repo, app, driverCase.driver,
				admissionHeaderProject, "")
		})
	}
}

func TestAuditBodyProjectAdmission_RejectsMalformedBodyProjectBeforeWrites(t *testing.T) {
	for _, driverCase := range auditBodyProjectAdmissionDrivers {
		t.Run(driverCase.name, func(t *testing.T) {
			h, repo, app := newAuditBodyProjectAdmissionApp(t)
			headerStatus, headerBody := postAuditBodyProjectAdmission(t, app,
				auditBodyProjectAdmissionBody(t, driverCase.driver, ""), admissionMalformedProject)
			if headerStatus != http.StatusBadRequest || agentAdmissionErrorCode(t, headerBody) != string(apicontract.CodeInvalidProjectUUID) {
				t.Fatalf("malformed header contract = (%d, %s), want (400, %s)", headerStatus, headerBody, apicontract.CodeInvalidProjectUUID)
			}

			bodyStatus, bodyResponse := postAuditBodyProjectAdmission(t, app,
				auditBodyProjectAdmissionBody(t, driverCase.driver, admissionMalformedProject), admissionHeaderProject)
			if bodyStatus != headerStatus || agentAdmissionErrorCode(t, bodyResponse) != agentAdmissionErrorCode(t, headerBody) {
				t.Errorf("malformed body project response = (%d, %s), want header admission's (%d, %s)", bodyStatus, bodyResponse, headerStatus, headerBody)
			}
			assertNoAgentAdmissionWrites(t, h, repo,
				agentAdmissionRoute{name: "audit", path: "/api/agent/run/audit", mode: "audit"}, admissionMalformedProject)
		})
	}
}

func TestAuditBodyProjectAdmission_RejectsUnknownBodyProjectBeforeWrites(t *testing.T) {
	for _, driverCase := range auditBodyProjectAdmissionDrivers {
		t.Run(driverCase.name, func(t *testing.T) {
			h, repo, app := newAuditBodyProjectAdmissionApp(t)
			headerStatus, headerBody := postAuditBodyProjectAdmission(t, app,
				auditBodyProjectAdmissionBody(t, driverCase.driver, ""), admissionUnknownProject)
			if headerStatus != http.StatusNotFound || agentAdmissionErrorCode(t, headerBody) != string(apicontract.CodeProjectNotFound) {
				t.Fatalf("unknown header contract = (%d, %s), want (404, %s)", headerStatus, headerBody, apicontract.CodeProjectNotFound)
			}

			bodyStatus, bodyResponse := postAuditBodyProjectAdmission(t, app,
				auditBodyProjectAdmissionBody(t, driverCase.driver, admissionUnknownProject), admissionHeaderProject)
			if bodyStatus != headerStatus || agentAdmissionErrorCode(t, bodyResponse) != agentAdmissionErrorCode(t, headerBody) {
				t.Errorf("unknown body project response = (%d, %s), want header admission's (%d, %s)", bodyStatus, bodyResponse, headerStatus, headerBody)
			}
			assertNoAgentAdmissionWrites(t, h, repo,
				agentAdmissionRoute{name: "audit", path: "/api/agent/run/audit", mode: "audit"}, admissionUnknownProject)
		})
	}
}
