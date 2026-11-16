package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	protohttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	nativeLifecycleModuleID       = "uuid-integrity-lifecycle-test"
	nativeLifecycleBarrierWait    = 60 * time.Second
	nativeLifecycleAppTestTimeout = 75 * time.Second
	nativeLifecycleRequestTimeout = "60s"
)

var (
	nativeLifecycleGates    sync.Map // scan UUID -> *nativeLifecycleGate
	nativeLifecycleTargets  sync.Map // loopback host -> scan UUID
	nativeLifecycleEvidence sync.Map // scan UUID -> captured *evidence.Exchange
)

type nativeLifecycleGate struct {
	arrived     chan struct{}
	arrivedOnce sync.Once
	release     chan struct{}
	releaseOnce sync.Once
	cancelled   chan struct{}
}

func (g *nativeLifecycleGate) open() {
	g.releaseOnce.Do(func() { close(g.release) })
}

// The test-only selected module makes the full REST -> native runner path
// controllable without modifying runner/core. It captures the actual loopback
// exchange and emits duplicate result occurrences so grouped evidence persistence
// is exercised; cancellation flows through the contextual module API and request.
type nativeLifecycleModule struct{}

func (nativeLifecycleModule) ID() string                                   { return nativeLifecycleModuleID }
func (nativeLifecycleModule) Name() string                                 { return "Native lifecycle test module" }
func (nativeLifecycleModule) Description() string                          { return "test-only lifecycle fixture" }
func (nativeLifecycleModule) ShortDescription() string                     { return "lifecycle fixture" }
func (nativeLifecycleModule) ConfirmationCriteria() string                 { return "controlled loopback response" }
func (nativeLifecycleModule) Severity() severity.Severity                  { return severity.Low }
func (nativeLifecycleModule) Confidence() severity.Confidence              { return severity.Certain }
func (nativeLifecycleModule) ScanScopes() modules.ScanScope                { return modules.ScanScopeHost }
func (nativeLifecycleModule) Tags() []string                               { return []string{"test"} }
func (nativeLifecycleModule) CanProcess(*httpmsg.HttpRequestResponse) bool { return true }
func (nativeLifecycleModule) AllowedInsertionPointTypes() modules.InsertionPointTypeSet {
	return modules.AllInsertionPointTypes
}
func (nativeLifecycleModule) ScanPerInsertionPoint(*httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (nativeLifecycleModule) ScanPerRequest(*httpmsg.HttpRequestResponse, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (nativeLifecycleModule) ScanPerHost(*httpmsg.HttpRequestResponse, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (nativeLifecycleModule) ScanPerInsertionPointContext(context.Context, *httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (nativeLifecycleModule) ScanPerRequestContext(context.Context, *httpmsg.HttpRequestResponse, *protohttp.Requester, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (nativeLifecycleModule) ScanPerHostContext(ctx context.Context, item *httpmsg.HttpRequestResponse, client *protohttp.Requester, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	target, err := url.Parse(item.Target())
	if err != nil {
		return nil, err
	}
	var scanValue any
	if scanValue, _ = nativeLifecycleTargets.Load(target.Host); scanValue == nil {
		return nil, fmt.Errorf("no lifecycle scan registered for loopback host %q", target.Host)
	}
	scanID := scanValue.(string)
	if _, ok := nativeLifecycleGates.Load(scanID); !ok {
		return nil, fmt.Errorf("no lifecycle barrier registered for scan %q", scanID)
	}
	target.Path = "/barrier/" + scanID
	target.RawQuery = ""
	request, err := httpmsg.GetRawRequestFromURL(target.String())
	if err != nil {
		return nil, err
	}
	chain, _, err := client.ExecuteContext(ctx, request, protohttp.Options{})
	var receipt *evidence.Exchange
	if chain != nil {
		receipt = protohttp.CaptureEvidence(chain)
		chain.Close()
	}
	if err != nil {
		return nil, err
	}
	if receipt == nil {
		return nil, fmt.Errorf("lifecycle request for scan %q produced no evidence receipt", scanID)
	}
	nativeLifecycleEvidence.Store(scanID, receipt.Clone())
	results := make([]*output.ResultEvent, 0, 2)
	for _, label := range []string{"native lifecycle loopback exchange", "grouped lifecycle exchange"} {
		result := &output.ResultEvent{
			ModuleID: nativeLifecycleModuleID,
			Info: output.Info{
				Name:        "Native lifecycle fixture finding",
				Description: "loopback barrier released",
				Severity:    severity.Low,
				Confidence:  severity.Certain,
			},
			Type:    "http",
			URL:     target.String(),
			Matched: target.String(),
		}
		if !modkit.SetPrimaryEvidence(result, receipt, evidence.RoleObservation, label) {
			return nil, fmt.Errorf("lifecycle request for scan %q produced invalid evidence", scanID)
		}
		results = append(results, result)
	}
	return results, nil
}

func installNativeLifecycleModule() func() {
	previous := modules.DefaultRegistry
	temporary := modules.NewRegistry()
	for _, module := range previous.GetActiveModules() {
		temporary.RegisterActive(module)
	}
	for _, module := range previous.GetPassiveModules() {
		temporary.RegisterPassive(module)
	}
	temporary.RegisterActive(nativeLifecycleModule{})
	modules.DefaultRegistry = temporary
	return func() { modules.DefaultRegistry = previous }
}

// Do not add t.Parallel: this test temporarily swaps modules.DefaultRegistry.
// The server package currently has no parallel tests; keep registry consumers serial.
func TestRunScanRESTLifecycleOwnsProjectAcrossRequestReuse(t *testing.T) {
	restoreRegistry := installNativeLifecycleModule()
	t.Cleanup(restoreRegistry)
	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	const projectA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const projectB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	for id, name := range map[string]string{projectA: "lifecycle-a", projectB: "lifecycle-b"} {
		require.NoError(t, repo.CreateProject(ctx, &database.Project{
			UUID: id, Name: name, OwnerUUID: database.DefaultUserUUID,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}))
	}

	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = false
	settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()
	h := newBasicHandlers(t, ServerConfig{Concurrency: 2}, &fakeQueue{}, db, repo, settings)

	gates := map[string]*nativeLifecycleGate{}
	for _, scanID := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		gate := &nativeLifecycleGate{
			arrived: make(chan struct{}), release: make(chan struct{}),
			cancelled: make(chan struct{}, 1),
		}
		gates[scanID] = gate
		nativeLifecycleGates.Store(scanID, gate)
		t.Cleanup(func() {
			nativeLifecycleGates.Delete(scanID)
			nativeLifecycleEvidence.Delete(scanID)
		})
	}

	var targetRequests atomic.Int64
	targets := make(map[string]*httptest.Server, len(gates))
	for scanID, gate := range gates {
		id, scanGate := scanID, gate
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetRequests.Add(1)
			if !strings.HasPrefix(r.URL.Path, "/barrier/") {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("seed"))
				return
			}
			scanGate.arrivedOnce.Do(func() { close(scanGate.arrived) })
			select {
			case <-scanGate.release:
				_, _ = w.Write([]byte("released\x00\xff-native-lifecycle"))
			case <-r.Context().Done():
				scanGate.cancelled <- struct{}{}
			}
		}))
		targets[id] = target
		host := strings.TrimPrefix(target.URL, "http://")
		nativeLifecycleTargets.Store(host, id)
		t.Cleanup(func() {
			nativeLifecycleTargets.Delete(host)
			target.Close()
		})
	}
	// Cleanup is LIFO: open every barrier before any target server is closed,
	// including on Fatal/FailNow paths. Handler.Close was registered earlier by
	// newBasicHandlers; after these releases and server closes it cancels and joins
	// any remaining background scans before the database and registry are restored.
	t.Cleanup(func() {
		for _, gate := range gates {
			gate.open()
		}
	})

	app := fiber.New() // Mutable Fiber strings match production's default.
	// Simulate Fiber reusing request header storage after each REST handler has
	// handed its values to the background scan. The production project middleware
	// must have detached the header before this ordered mutation occurs.
	app.Use(func(c fiber.Ctx) error {
		err := c.Next()
		if c.Method() == http.MethodPost && c.Path() == "/api/scans/run" {
			var request struct {
				ScanUUID string `json:"scan_uuid"`
			}
			if json.Unmarshal(c.Body(), &request) == nil {
				if value, ok := nativeLifecycleGates.Load(request.ScanUUID); ok {
					select {
					case <-value.(*nativeLifecycleGate).arrived:
					case <-time.After(nativeLifecycleBarrierWait):
						return c.SendStatus(http.StatusGatewayTimeout)
					}
				}
			}
			if header := c.Request().Header.Peek("X-Project-UUID"); len(header) > 0 {
				header[0] = 'x'
			}
		}
		return err
	})
	app.Use(ProjectUUIDMiddleware(repo))
	app.Post("/api/scans/run", h.HandleRunScan)
	app.Post("/api/scans/:uuid/stop", h.HandleStopScan)
	app.Get("/api/scan/status", h.HandleScanStatus)
	app.Get("/api/scans/:uuid", h.HandleGetScan)
	app.Get("/api/scans/:uuid/logs", h.HandleGetScanLogs)
	app.Get("/api/http-records", h.HandleListRecords)
	app.Get("/api/findings", h.findingsHandler().HandleListFindings)

	startScan := func(projectUUID, scanID string) int {
		t.Helper()
		target := targets[scanID]
		if target == nil {
			target = targets["11111111-1111-4111-8111-111111111111"] // rejected same-project retry never reaches the target
		}
		body := fmt.Sprintf(`{"targets":[%q],"modules":[%q],"only":"discovery,dynamic-assessment","timeout":%q,"scan_uuid":%q}`,
			target.URL+"/seed/"+scanID, nativeLifecycleModuleID, nativeLifecycleRequestTimeout, scanID)
		req := httptest.NewRequest(http.MethodPost, "/api/scans/run", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Project-UUID", projectUUID)
		resp, err := app.Test(req, fiber.TestConfig{Timeout: nativeLifecycleAppTestTimeout})
		require.NoError(t, err, "POST /api/scans/run")
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	respA := startScan(projectA, "11111111-1111-4111-8111-111111111111")
	require.Equal(t, http.StatusAccepted, respA)
	respConflict := startScan(projectA, "33333333-3333-4333-8333-333333333333")
	require.Equal(t, http.StatusConflict, respConflict, "same-project concurrent admission must be rejected")
	if _, err := repo.GetScanByUUID(ctx, "33333333-3333-4333-8333-333333333333"); err == nil {
		t.Fatal("rejected same-project submission persisted a scan row")
	}

	respB := startScan(projectB, "22222222-2222-4222-8222-222222222222")
	require.Equal(t, http.StatusAccepted, respB, "a different project may scan concurrently")
	for _, id := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		select {
		case <-gates[id].arrived:
		case <-time.After(nativeLifecycleBarrierWait):
			t.Fatalf("native test module did not reach loopback barrier for %s", id)
		}
	}

	statusA, bodyA := doGet(t, app, "/api/scan/status", map[string]string{"X-Project-UUID": projectA})
	require.Equal(t, http.StatusOK, statusA)
	var scanStatusA ScanStatusResponse
	require.NoError(t, json.Unmarshal(bodyA, &scanStatusA))
	require.True(t, scanStatusA.Running)
	require.Equal(t, "11111111-1111-4111-8111-111111111111", scanStatusA.ScanUUID)
	statusB, bodyB := doGet(t, app, "/api/scan/status", map[string]string{"X-Project-UUID": projectB})
	require.Equal(t, http.StatusOK, statusB)
	var scanStatusB ScanStatusResponse
	require.NoError(t, json.Unmarshal(bodyB, &scanStatusB))
	require.True(t, scanStatusB.Running)
	require.Equal(t, "22222222-2222-4222-8222-222222222222", scanStatusB.ScanUUID)

	for id, project := range map[string]string{"11111111-1111-4111-8111-111111111111": projectA, "22222222-2222-4222-8222-222222222222": projectB} {
		scan, err := repo.GetScanByUUID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, project, scan.ProjectUUID, "scan row must retain the admitted project after header reuse")
		require.NotNil(t, scan.HeartbeatAt, "live native scan should publish its row heartbeat")
	}

	// Stop through the owner project only. The different-project request cannot
	// stop A, while B's own stop cancels its active runner and blocked HTTP call.
	wrongOwner, _ := doReq2(t, app, http.MethodPost, "/api/scans/11111111-1111-4111-8111-111111111111/stop", "", map[string]string{"X-Project-UUID": projectB})
	require.Equal(t, http.StatusConflict, wrongOwner.StatusCode)
	stopB, _ := doReq2(t, app, http.MethodPost, "/api/scans/22222222-2222-4222-8222-222222222222/stop", "", map[string]string{"X-Project-UUID": projectB})
	require.Equal(t, http.StatusOK, stopB.StatusCode)
	select {
	case <-gates["22222222-2222-4222-8222-222222222222"].cancelled:
	case <-time.After(nativeLifecycleBarrierWait):
		t.Fatal("stop did not cancel the loopback request held at the module barrier")
	}
	gates["11111111-1111-4111-8111-111111111111"].open()

	awaitScanTerminal := func(scanID, wantStatus string) *database.Scan {
		t.Helper()
		deadline := time.Now().Add(nativeLifecycleBarrierWait)
		for time.Now().Before(deadline) {
			scan, err := repo.GetScanByUUID(ctx, scanID)
			if err == nil && scan.Status == wantStatus {
				return scan
			}
			time.Sleep(10 * time.Millisecond)
		}
		scan, err := repo.GetScanByUUID(ctx, scanID)
		t.Fatalf("scan %s did not finalize as %s: row=%+v err=%v", scanID, wantStatus, scan, err)
		return nil
	}
	scanA := awaitScanTerminal("11111111-1111-4111-8111-111111111111", "completed")
	// A stopped native REST scan finalizes its row as cancelled, like status.json.
	scanB := awaitScanTerminal("22222222-2222-4222-8222-222222222222", "cancelled")
	require.False(t, scanB.FinishedAt.IsZero(), "cancelled scan row must be finalized")
	require.Equal(t, projectA, scanA.ProjectUUID)
	require.Equal(t, projectB, scanB.ProjectUUID)
	require.NotNil(t, scanA.HeartbeatAt)
	require.NotNil(t, scanB.HeartbeatAt)

	logCounts := map[string]int{}
	for id, project := range map[string]string{"11111111-1111-4111-8111-111111111111": projectA, "22222222-2222-4222-8222-222222222222": projectB} {
		var logs []*database.ScanLog
		require.NoError(t, db.NewSelect().Model(&logs).Where("scan_uuid = ?", id).Scan(ctx))
		require.NotEmpty(t, logs, "native runtime should persist scan logs")
		logCounts[id] = len(logs)
		for _, log := range logs {
			require.Equal(t, id, log.ScanUUID)
			require.Equal(t, project, log.ProjectUUID)
		}
		statusPath := runner.SessionStatusPath(settings.ScanningStrategy.ScanLogs.SessionsDir, id)
		statusBytes, err := os.ReadFile(statusPath)
		require.NoError(t, err, "heartbeat status file must remain available after finalization")
		var sessionStatus struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal(statusBytes, &sessionStatus))
		// The row finalizer commits before the deferred heartbeat Finish writes
		// status.json. A terminal row is not a barrier for that later file write.
		// Wait for the same terminal value without relaxing the final assertion.
		wantStatus := wantSessionStatus(scanA, scanB, id)
		require.Eventually(t, func() bool {
			statusBytes, err = os.ReadFile(statusPath)
			return err == nil && json.Unmarshal(statusBytes, &sessionStatus) == nil && sessionStatus.Status == wantStatus
		}, nativeLifecycleBarrierWait, 10*time.Millisecond, "session status must finalize after its scan row")
		require.Equal(t, wantStatus, sessionStatus.Status)
	}
	require.Positive(t, logCounts["11111111-1111-4111-8111-111111111111"])
	require.Positive(t, logCounts["22222222-2222-4222-8222-222222222222"])

	var records []*database.HTTPRecord
	require.NoError(t, db.NewSelect().Model(&records).Where("scan_uuid IN (?, ?)", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222").Scan(ctx))
	require.NotEmpty(t, records, "native loopback scans should exercise record persistence")
	recordCounts := map[string]int{}
	cancelledTargetURL, err := url.Parse(targets["22222222-2222-4222-8222-222222222222"].URL)
	require.NoError(t, err)
	cancelledTargetRecord := false
	for _, record := range records {
		want := projectA
		switch record.ScanUUID {
		case "11111111-1111-4111-8111-111111111111":
			recordCounts[record.ScanUUID]++
		case "22222222-2222-4222-8222-222222222222":
			want = projectB
			recordCounts[record.ScanUUID]++
			cancelledTargetRecord = cancelledTargetRecord || record.Hostname == cancelledTargetURL.Hostname()
		default:
			t.Fatalf("unexpected scan on native lifecycle traffic record: %+v", record)
		}
		require.Equal(t, want, record.ProjectUUID, "record ownership must follow its scan")
	}
	require.Positive(t, recordCounts["11111111-1111-4111-8111-111111111111"])
	require.Positive(t, recordCounts["22222222-2222-4222-8222-222222222222"], "cancelled scan traffic must still persist in its project")
	require.True(t, cancelledTargetRecord, "cancelled scan's target HTTP traffic must persist under project B")

	var findings []*database.Finding
	require.NoError(t, db.NewSelect().Model(&findings).Where("scan_uuid IN (?, ?)", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222").Scan(ctx))
	require.Len(t, findings, 1, "duplicate result occurrences should group into one finding")
	var successFinding *database.Finding
	for _, finding := range findings {
		require.Equal(t, "11111111-1111-4111-8111-111111111111", finding.ScanUUID, "cancelled scan must not persist a finding")
		require.Equal(t, projectA, finding.ProjectUUID, "finding ownership must follow its scan")
		if successFinding == nil {
			successFinding = finding
		}
	}
	require.NotNil(t, successFinding)
	require.Equal(t, "selected", successFinding.EvidenceStatus)
	require.NoError(t, repo.HydrateFindingEvidenceManifest(ctx, []*database.Finding{successFinding}))
	require.NotEmpty(t, successFinding.Evidence, "persisted finding must retain its evidence associations")

	expectedEvidenceValue, ok := nativeLifecycleEvidence.Load("11111111-1111-4111-8111-111111111111")
	require.True(t, ok, "successful loopback module must retain its actual captured exchange receipt")
	expectedEvidence := expectedEvidenceValue.(*evidence.Exchange)
	require.NoError(t, expectedEvidence.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, expectedEvidence.Provenance)
	require.Equal(t, evidence.StateComplete, expectedEvidence.RequestState)
	require.Equal(t, evidence.StateComplete, expectedEvidence.ResponseState)
	require.Equal(t, targets["11111111-1111-4111-8111-111111111111"].URL+"/barrier/11111111-1111-4111-8111-111111111111", expectedEvidence.URL)
	require.True(t, bytes.Contains(expectedEvidence.Request, []byte("/barrier/11111111-1111-4111-8111-111111111111")))
	require.True(t, bytes.Contains(expectedEvidence.Response, []byte("released\x00\xff-native-lifecycle")))
	var selectedEvidence []*evidence.Entry
	for i := range successFinding.Evidence {
		entry := &successFinding.Evidence[i]
		if entry.ExchangeID == expectedEvidence.ID {
			selectedEvidence = append(selectedEvidence, entry)
		}
	}
	require.Len(t, selectedEvidence, 2, "grouped finding must retain both result-occurrence associations")
	occurrences := make(map[string]struct{}, len(selectedEvidence))
	labels := make(map[string]struct{}, len(selectedEvidence))
	for _, entry := range selectedEvidence {
		require.Equal(t, evidence.RoleObservation, entry.Role)
		require.True(t, entry.Primary)
		require.NotEmpty(t, entry.OccurrenceID, "finding evidence must retain its occurrence identity")
		require.Equal(t, targets["11111111-1111-4111-8111-111111111111"].URL+"/barrier/11111111-1111-4111-8111-111111111111", entry.FindingURL)
		require.Equal(t, "11111111-1111-4111-8111-111111111111", entry.ScanUUID)
		occurrences[entry.OccurrenceID] = struct{}{}
		labels[entry.Label] = struct{}{}
	}
	require.Len(t, occurrences, 2, "grouped result occurrences must not collapse to one occurrence ID")
	require.Equal(t, map[string]struct{}{
		"native lifecycle loopback exchange": {},
		"grouped lifecycle exchange":         {},
	}, labels)

	storedEvidence, err := repo.GetEvidenceExchange(ctx, expectedEvidence.ID, projectA)
	require.NoError(t, err, "exchange lookup must succeed in its owner project")
	require.NoError(t, storedEvidence.Validate())
	require.Equal(t, expectedEvidence.ID, storedEvidence.ID)
	require.Equal(t, expectedEvidence.URL, storedEvidence.URL)
	require.Equal(t, expectedEvidence.Service, storedEvidence.Service)
	require.Equal(t, expectedEvidence.Provenance, storedEvidence.Provenance)
	require.Equal(t, expectedEvidence.RequestState, storedEvidence.RequestState)
	require.Equal(t, expectedEvidence.ResponseState, storedEvidence.ResponseState)
	require.Equal(t, expectedEvidence.ContentHash, storedEvidence.ContentHash)
	require.Equal(t, expectedEvidence.Hash(), storedEvidence.ContentHash, "stored bytes must validate against the content hash")
	require.True(t, bytes.Equal(expectedEvidence.Request, storedEvidence.Request), "stored request bytes must match the actual captured exchange")
	require.True(t, bytes.Equal(expectedEvidence.Response, storedEvidence.Response), "stored response bytes must match the actual captured exchange")
	_, err = repo.GetEvidenceExchange(ctx, expectedEvidence.ID, projectB)
	require.ErrorIs(t, err, sql.ErrNoRows, "exchange lookup must not cross project scope")
	var evidenceRows []*database.EvidenceExchange
	require.NoError(t, db.NewSelect().Model(&evidenceRows).Where("id = ?", expectedEvidence.ID).Scan(ctx))
	require.Len(t, evidenceRows, 1)
	require.Equal(t, projectA, evidenceRows[0].ProjectUUID, "exchange row must retain its owning project")

	observations, err := repo.ListFindingObservations(ctx, projectA, successFinding.ID)
	require.NoError(t, err)
	require.NotEmpty(t, observations, "finding observation history must be persisted")
	observedInSuccessScan := false
	for _, observation := range observations {
		require.Equal(t, projectA, observation.ProjectUUID)
		require.Equal(t, successFinding.FindingHash, observation.FindingHash)
		if observation.ScanUUID == "11111111-1111-4111-8111-111111111111" {
			observedInSuccessScan = true
		}
		require.NotEqual(t, "22222222-2222-4222-8222-222222222222", observation.ScanUUID, "cancelled scan must not own a finding observation")
	}
	require.True(t, observedInSuccessScan, "finding observation must be associated with the successful scan")
	foreignObservations, err := repo.ListFindingObservations(ctx, projectB, successFinding.ID)
	require.NoError(t, err)
	require.Empty(t, foreignObservations, "finding observation history must not cross project scope")

	// Exercise the project-scoped API readers as well as the underlying rows.
	for _, project := range []string{projectA, projectB} {
		status, body := doGet(t, app, "/api/http-records?limit=500", map[string]string{"X-Project-UUID": project})
		require.Equal(t, http.StatusOK, status)
		var listed struct {
			Data  []*database.HTTPRecord `json:"data"`
			Total int64                  `json:"total"`
		}
		require.NoError(t, json.Unmarshal(body, &listed))
		require.NotEmpty(t, listed.Data, "project API should return its native scan records")
		for _, record := range listed.Data {
			require.Equal(t, project, record.ProjectUUID, "record API leaked another project's traffic")
		}
	}
	for _, tc := range []struct {
		project, scanID string
		wantFindings    int64
	}{
		{projectA, "11111111-1111-4111-8111-111111111111", 1},
		{projectA, "22222222-2222-4222-8222-222222222222", 0},
		{projectB, "11111111-1111-4111-8111-111111111111", 0},
		{projectB, "22222222-2222-4222-8222-222222222222", 0},
	} {
		status, body := doGet(t, app, "/api/findings?scan_uuid="+tc.scanID, map[string]string{"X-Project-UUID": tc.project})
		require.Equal(t, http.StatusOK, status)
		var listed PaginatedResponse
		require.NoError(t, json.Unmarshal(body, &listed))
		if tc.project == projectA && tc.scanID == "11111111-1111-4111-8111-111111111111" {
			require.GreaterOrEqual(t, listed.Total, tc.wantFindings)
		} else {
			require.Zero(t, listed.Total, "foreign or cancelled findings must not appear")
		}
	}
	logsResp, logsBody := doGet(t, app, "/api/scans/11111111-1111-4111-8111-111111111111/logs", map[string]string{"X-Project-UUID": projectA})
	require.Equal(t, http.StatusOK, logsResp)
	require.NotEmpty(t, logsBody)
	foreignLogs, _ := doGet(t, app, "/api/scans/11111111-1111-4111-8111-111111111111/logs", map[string]string{"X-Project-UUID": projectB})
	require.Equal(t, http.StatusNotFound, foreignLogs)

	scanStatusA = awaitProjectScanIdle(t, app, projectA)
	scanStatusB = awaitProjectScanIdle(t, app, projectB)
	require.False(t, scanStatusA.Running)
	require.False(t, scanStatusB.Running)
	require.Greater(t, targetRequests.Load(), int64(0))
}

func awaitProjectScanIdle(t *testing.T, app *fiber.App, projectUUID string) ScanStatusResponse {
	t.Helper()
	deadline := time.Now().Add(nativeLifecycleBarrierWait)
	for time.Now().Before(deadline) {
		status, body := doGet(t, app, "/api/scan/status", map[string]string{"X-Project-UUID": projectUUID})
		if status != http.StatusOK {
			t.Fatalf("project %s status endpoint returned %d: %s", projectUUID, status, body)
		}
		var scanStatus ScanStatusResponse
		if err := json.Unmarshal(body, &scanStatus); err != nil {
			t.Fatalf("decode project %s scan status: %v", projectUUID, err)
		}
		if !scanStatus.Running {
			return scanStatus
		}
		time.Sleep(10 * time.Millisecond)
	}
	status, body := doGet(t, app, "/api/scan/status", map[string]string{"X-Project-UUID": projectUUID})
	t.Fatalf("project %s scan did not leave running state before timeout (status=%d): %s", projectUUID, status, body)
	return ScanStatusResponse{}
}

func wantSessionStatus(completed, cancelled *database.Scan, scanID string) string {
	if scanID == "11111111-1111-4111-8111-111111111111" && completed != nil && completed.Status == "completed" {
		return runner.SessionCompleted
	}
	if scanID == "22222222-2222-4222-8222-222222222222" && cancelled != nil && cancelled.Status == "cancelled" {
		return runner.SessionCancelled
	}
	return ""
}
