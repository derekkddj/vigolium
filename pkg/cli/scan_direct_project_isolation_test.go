package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/portsweep"
	"github.com/vigolium/vigolium/pkg/types"
)

func directForeignUUIDFixture(t *testing.T) (*database.Repository, *database.Scan) {
	t.Helper()
	directRowFixture(t)
	swapGlobal(t, &globalProjectUUID, "project-b")
	swapGlobal(t, &globalProjectName, "")
	swapGlobal(t, &globalScanUUID, "foreign-pinned-scan")
	clicommon.ResetProjectResolutionForTest()
	t.Cleanup(clicommon.ResetProjectResolutionForTest)
	db, err := getDB()
	if err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)
	// The selected project must exist; the pinned row belongs to another one.
	for _, id := range []string{"project-a", "project-b"} {
		if err := repo.CreateProject(context.Background(), &database.Project{UUID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.CreateScan(context.Background(), &database.Scan{
		UUID: globalScanUUID, ProjectUUID: "project-a", Name: "original", Status: "pending",
		Target: "https://original.invalid", AgenticScanUUID: "original-parent", TotalFindings: 7,
	}); err != nil {
		t.Fatal(err)
	}
	original, err := repo.GetScanByUUID(context.Background(), globalScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	return repo, original
}

func assertDirectForeignRowUntouched(t *testing.T, repo *database.Repository, original *database.Scan, session *directScanSession) {
	t.Helper()
	ctx := context.Background()
	stored, err := repo.GetScanByUUID(ctx, original.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, stored) {
		t.Fatalf("foreign row changed: original=%+v stored=%+v", original, stored)
	}
	for _, table := range []string{"scan_logs", "http_records", "findings"} {
		if n, err := repo.DB().NewSelect().TableExpr(table).Count(ctx); err != nil || n != 0 {
			t.Fatalf("failed direct input wrote %s: count=%d err=%v", table, n, err)
		}
	}
	if session != nil && (len(session.heartbeats) != 0 || len(session.finished) != 0 || len(session.finishedOut) != 0 || session.finishedRepo != nil) {
		t.Fatalf("failed input initialized heartbeat or queued webhook: %+v", session)
	}
}

func TestDirectScanProjectIsolationRejectInputDoesNotFinalize(t *testing.T) {
	repo, original := directForeignUUIDFixture(t)
	session := &directScanSession{name: database.ScanNameScanURL, pinned: original.UUID}
	result, err := session.rejectInput(context.Background(), original.UUID, "https://replacement.invalid", "GET", types.TargetVerdict{Target: "https://replacement.invalid"})
	if result != nil || !errors.Is(err, database.ErrScanProjectMismatch) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertDirectForeignRowUntouched(t, repo, original, session)
	// No finished entry means close cannot emit even an enabled webhook.
	session.fireWebhooks()
	assertDirectForeignRowUntouched(t, repo, original, session)
}

func TestDirectScanProjectIsolationExecuteStopsBeforeRequests(t *testing.T) {
	repo, original := directForeignUUIDFixture(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	input := directInput(t, server.URL)
	session := newDirectScanSession(database.ScanNameScanURL, []scanInput{input})
	result, err := executeDirectScan(context.Background(), session, input.rr, input.target, input.method)
	if result != nil || !errors.Is(err, database.ErrScanProjectMismatch) || requests.Load() != 0 {
		t.Fatalf("result=%+v err=%v requests=%d", result, err, requests.Load())
	}
	assertDirectForeignRowUntouched(t, repo, original, session)
}

func TestDirectScanProjectIsolationScanRequestStopsBeforeSchemeProbe(t *testing.T) {
	_, original := directForeignUUIDFixture(t)
	swapGlobal(t, &scanIgnoreScope, true)
	swapGlobal(t, &globalStateless, false)
	swapGlobal(t, &scanReqTarget, "")
	swapGlobal(t, &scanReqNoSchemeProbe, false)
	oldScopeHint := scopeEscapeHint
	t.Cleanup(func() { scopeEscapeHint = oldScopeHint })
	if needsRunnerScan() {
		t.Fatal("fixture unexpectedly selected the runner path")
	}
	var probes atomic.Int64
	origResolver := requestSchemeResolver
	t.Cleanup(func() { requestSchemeResolver = origResolver })
	requestSchemeResolver = func(context.Context, string, string, string, portsweep.SchemeOptions) portsweep.SchemeResolution {
		probes.Add(1)
		return portsweep.SchemeResolution{} // Never contacts a target, even on regression.
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	// Even if both guards regress, the only possible target is loopback.
	inputPath := filepath.Join(t.TempDir(), "request.txt")
	raw := "GET / HTTP/1.1\r\nHost: " + strings.TrimPrefix(server.URL, "http://") + "\r\n\r\n"
	if err := os.WriteFile(inputPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	swapGlobal(t, &scanReqInput, inputPath)
	err := runScanRequestCmd(&cobra.Command{}, nil)
	if !errors.Is(err, database.ErrScanProjectMismatch) || probes.Load() != 0 || requests.Load() != 0 {
		t.Fatalf("scan-request err=%v scheme probes=%d requests=%d", err, probes.Load(), requests.Load())
	}
	// runScanRequestCmd closes its selected store on exit; clear the closed
	// process cache and reopen the same pin, never substitute another store.
	resetDBCacheForTest()
	db, openErr := getDB()
	if openErr != nil {
		t.Fatal(openErr)
	}
	assertDirectForeignRowUntouched(t, database.NewRepository(db), original, nil)
}

func TestDirectScanProjectIsolationCompletionRequiresCapturedScope(t *testing.T) {
	for _, scenario := range []string{"no-capture", "foreign-capture", "different-store"} {
		t.Run(scenario, func(t *testing.T) {
			repo, original := directForeignUUIDFixture(t)
			session := &directScanSession{name: database.ScanNameScanURL, pinned: original.UUID}
			if scenario != "no-capture" {
				scope := directScanScope{db: repo.DB(), project: "project-b"}
				if scenario == "different-store" {
					scope.db = newDBAtPath(t, filepath.Join(t.TempDir(), "other.sqlite"))
				}
				session.scanScopes = map[string]directScanScope{original.UUID: scope}
			}
			err := session.complete(context.Background(), repo, original.UUID, "https://replacement.invalid", core.ExecutionReport{}, nil, false, nil, database.TargetTally{}, 0)
			if err == nil {
				t.Fatal("unvalidated completion succeeded")
			}
			if scenario == "foreign-capture" && !errors.Is(err, database.ErrScanProjectMismatch) {
				t.Fatalf("foreign completion error=%v", err)
			}
			assertDirectForeignRowUntouched(t, repo, original, session)
		})
	}
}

func TestDirectScanProjectIsolationCapturedCompletionSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name, project string
		cancelled     bool
	}{
		{name: "selected-project", project: "project-b"},
		{name: "default-project"},
		{name: "cancelled", project: "project-b", cancelled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directRowFixture(t)
			repo := database.NewRepository(newDBAtPath(t, filepath.Join(t.TempDir(), "scope.sqlite")))
			session := &directScanSession{name: database.ScanNameScanURL, pinned: "owned-scan"}
			t.Cleanup(session.close)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			if err := session.begin(ctx, repo, tc.project, session.pinned, "https://owned.invalid", "GET", 0, 0); err != nil {
				t.Fatal(err)
			}
			// A new repository wrapper over the same handle is allowed, and the
			// current CLI selection cannot replace the captured expected project.
			swapGlobal(t, &globalProjectUUID, "unrelated-current-selection")
			if err := session.complete(ctx, database.NewRepository(repo.DB()), session.pinned, "https://owned.invalid", core.ExecutionReport{Responded: 1}, nil, tc.cancelled, nil, database.TargetTally{Admitted: 1}, 0); err != nil {
				t.Fatal(err)
			}
			stored, err := repo.GetScanByUUID(context.Background(), session.pinned)
			if err != nil {
				t.Fatal(err)
			}
			project := tc.project
			if project == "" {
				project = database.DefaultProjectUUID
			}
			if stored.ProjectUUID != project || stored.FinishedAt.IsZero() {
				t.Fatalf("completion lost captured project: %+v", stored)
			}
			if tc.cancelled {
				if stored.Status != "cancelled" || stored.StopReason != database.ReasonCancelled {
					t.Fatalf("cancelled completion=%+v", stored)
				}
			} else if stored.Status != "completed" || stored.Completeness != database.CompletenessComplete {
				t.Fatalf("successful completion=%+v", stored)
			}
			logs, total, err := repo.ListScanLogs(context.Background(), session.pinned, "", "", 10, 0)
			if err != nil || total != 2 || len(logs) != 2 || logs[0].ProjectUUID != project || logs[1].ProjectUUID != project {
				t.Fatalf("completion logs=%+v total=%d err=%v", logs, total, err)
			}
			if len(session.finished) != 1 || session.finished[0] != session.pinned {
				t.Fatalf("successful completion was not tracked: %v", session.finished)
			}
		})
	}
}

func TestDirectScanProjectIsolationReassignedRowCannotComplete(t *testing.T) {
	directRowFixture(t)
	repo := database.NewRepository(newDBAtPath(t, filepath.Join(t.TempDir(), "scope.sqlite")))
	session := &directScanSession{name: database.ScanNameScanURL, pinned: "owned-scan"}
	t.Cleanup(session.close)
	ctx := context.Background()
	if err := session.begin(ctx, repo, "project-a", session.pinned, "https://owned.invalid", "GET", 0, 0); err != nil {
		t.Fatal(err)
	}
	// Freeze liveness before simulating an external reassignment. Only the
	// finalizer is under test, not another worker's heartbeat implementation.
	session.heartbeats[session.pinned].Stop(ctx)
	if _, err := repo.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "project-b").Where("uuid = ?", session.pinned).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := repo.GetScanByUUID(ctx, session.pinned)
	if err != nil {
		t.Fatal(err)
	}
	var logsBefore []*database.ScanLog
	if err := repo.DB().NewSelect().Model(&logsBefore).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	err = session.complete(ctx, repo, session.pinned, "https://replacement.invalid", core.ExecutionReport{Responded: 1}, nil, false, nil, database.TargetTally{Admitted: 1}, 0)
	if !errors.Is(err, database.ErrScanProjectMismatch) {
		t.Fatalf("reassigned completion error=%v", err)
	}
	after, err := repo.GetScanByUUID(ctx, session.pinned)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("reassigned row mutated: after=%+v err=%v", after, err)
	}
	var logsAfter []*database.ScanLog
	if err := repo.DB().NewSelect().Model(&logsAfter).Scan(ctx); err != nil || !reflect.DeepEqual(logsBefore, logsAfter) {
		t.Fatalf("reassigned completion added logs: after=%+v err=%v", logsAfter, err)
	}
	if len(session.finished) != 0 || len(session.finishedOut) != 0 || session.finishedRepo != nil {
		t.Fatal("reassigned completion queued a webhook")
	}
}

func TestDirectScanProjectIsolationSelectedStoreInsertFailureStopsRequests(t *testing.T) {
	repo, original := directForeignUUIDFixture(t)
	swapGlobal(t, &globalScanUUID, "")
	if _, err := repo.DB().ExecContext(context.Background(), `CREATE TRIGGER deny_scan_insert BEFORE INSERT ON scans BEGIN SELECT RAISE(FAIL, 'injected create failure'); END`); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	input := directInput(t, server.URL)
	session := newDirectScanSession(database.ScanNameScanURL, []scanInput{input})
	result, err := executeDirectScan(context.Background(), session, input.rr, input.target, input.method)
	if result != nil || err == nil || requests.Load() != 0 {
		t.Fatalf("selected store failure result=%+v err=%v requests=%d", result, err, requests.Load())
	}
	assertDirectForeignRowUntouched(t, repo, original, session)
}

func TestDirectScanProjectIsolationMemoryOnlyPolicy(t *testing.T) {
	if err := (&directScanSession{}).begin(context.Background(), nil, "", "new-uuid", "", "GET", 0, 0); err != nil {
		t.Fatalf("unpinned memory-only input must remain supported: %v", err)
	}
	if err := (&directScanSession{pinned: "existing-uuid"}).begin(context.Background(), nil, "", "existing-uuid", "", "GET", 0, 0); err == nil || !strings.Contains(err.Error(), "validate ownership") {
		t.Fatalf("pinned UUID without a store must fail closed: %v", err)
	}
}
