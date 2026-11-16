package runner

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// Every possible producer points to loopback, including auth/OAST/notifications.
// The phase stubs fail if reached; identity rejection must precede all of them.
func nativeIsolationRunner(t *testing.T, repo *database.Repository) (*Runner, *atomic.Int64, *callbackEvents) {
	t.Helper()
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Set-Cookie", "sid=local; Path=/")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	r := newCallbackScanRunner(t)
	r.SetRepository(repo)
	r.options.ProjectUUID = "project-b"
	r.options.ScanUUID = "pinned-native"
	r.options.Targets = []string{server.URL}
	r.options.SkipPreflight = true
	r.settings.OAST.Enabled = true
	r.settings.OAST.ServerURL = server.URL
	authPath := filepath.Join(t.TempDir(), "auth.yaml")
	auth := fmt.Sprintf("name: local\nrole: primary\nlogin:\n  url: %s/login\n  method: POST\n  type: cookie\n", server.URL)
	if err := os.WriteFile(authPath, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	r.options.AuthFiles = []string{authPath}
	var received callbackEvents
	r.SetEventCallback(received.record)
	r.phaseRunners = map[NativePhase]phaseRunner{}
	for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
		r.phaseRunners[phase] = phaseRunner{tag: string(phase), label: string(phase), run: func(*Runner, context.Context, *phaseInfra) error {
			t.Fatal("phase ran after identity rejection")
			return nil
		}}
	}
	return r, &requests, &received
}

type nativeIsolationRows struct {
	scans    []*database.Scan
	logs     []*database.ScanLog
	findings []*database.Finding
	records  []*database.HTTPRecord
}

func nativeIsolationSnapshot(t *testing.T, repo *database.Repository) nativeIsolationRows {
	t.Helper()
	var rows nativeIsolationRows
	for _, model := range []any{&rows.scans, &rows.logs, &rows.findings, &rows.records} {
		if err := repo.DB().NewSelect().Model(model).Scan(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

func assertNativeIdentityRejected(t *testing.T, r *Runner, requests *atomic.Int64, received *callbackEvents) {
	t.Helper()
	if requests.Load() != 0 || len(received.snapshot()) != 0 || r.ScanLogger() != nil || r.liveness.Load() != nil || r.Finalized() {
		t.Fatalf("rejected scan initialized producers: requests=%d callbacks=%+v logger=%v heartbeat=%v finalized=%v", requests.Load(), received.snapshot(), r.ScanLogger(), r.liveness.Load(), r.Finalized())
	}
	// Even a late finding/terminal delivery cannot let a caller reconcile or
	// emit a webhook for the rejected identity.
	r.emitFindingEvent(&output.ResultEvent{ModuleID: "late-finding"})
	r.emitEvent(scanevents.Event{Type: scanevents.TypeScanFinished})
	if len(received.snapshot()) != 0 {
		t.Fatal("rejected scan delivered a late callback")
	}
	entries, err := os.ReadDir(r.settings.ScanningStrategy.ScanLogs.SessionsDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected scan created session/heartbeat/log files: entries=%v err=%v", entries, err)
	}
}

func TestNativeProjectIsolationForeignPinnedAndManaged(t *testing.T) {
	for _, scenario := range []string{"pinned", "managed", "scan-on-receive", "empty-project", "scope-refused"} {
		t.Run(scenario, func(t *testing.T) {
			repo := newBannerRepo(t)
			ctx := context.Background()
			if err := repo.CreateScan(ctx, &database.Scan{
				UUID: "pinned-native", ProjectUUID: "project-a", Name: "original", Status: "running", Target: "https://original.invalid",
				AgenticScanUUID: "original-parent", TotalFindings: 7, ScopeOriginMode: "strict", PID: 123,
			}); err != nil {
				t.Fatal(err)
			}
			if err := repo.CreateScanLog(ctx, &database.ScanLog{ScanUUID: "pinned-native", ProjectUUID: "project-a", Level: "info", Message: "original log"}); err != nil {
				t.Fatal(err)
			}
			if err := repo.SaveFindingDirect(ctx, &database.Finding{ProjectUUID: "project-a", ScanUUID: "pinned-native", ModuleID: "original", ModuleName: "original", Severity: "high", FindingHash: "original-hash"}); err != nil {
				t.Fatal(err)
			}
			before := nativeIsolationSnapshot(t, repo)
			r, requests, received := nativeIsolationRunner(t, repo)
			switch scenario {
			case "managed":
				r.options.ManagedScanRecord = true
			case "scan-on-receive":
				r.options.ScanOnReceive = true
			case "empty-project":
				r.options.ProjectUUID = ""
			case "scope-refused":
				r.targetsAreInput = true
				r.settings.Scope.Host.Exclude = []string{"*"}
			}
			err := r.RunNativeScan()
			var identity *NativeScanIdentityError
			if !errors.Is(err, database.ErrScanProjectMismatch) || !errors.As(err, &identity) || identity.ScanUUID != "pinned-native" {
				t.Fatalf("foreign identity error=%v typed=%+v", err, identity)
			}
			assertNativeIdentityRejected(t, r, requests, received)
			if after := nativeIsolationSnapshot(t, repo); !reflect.DeepEqual(before, after) {
				t.Fatalf("foreign row/evidence changed: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestNativeProjectIsolationMissingManagedAndUnavailableStore(t *testing.T) {
	for _, scenario := range []string{"missing-managed", "missing-on-receive", "managed-no-repo", "managed-no-uuid", "read-error", "insert-error"} {
		t.Run(scenario, func(t *testing.T) {
			repo := newBannerRepo(t)
			r, requests, received := nativeIsolationRunner(t, repo)
			missing := true
			switch scenario {
			case "missing-managed":
				r.options.ManagedScanRecord = true
			case "missing-on-receive":
				r.options.ScanOnReceive = true
			case "managed-no-repo":
				r.options.ManagedScanRecord = true
				r.SetRepository(nil)
			case "managed-no-uuid":
				r.options.ManagedScanRecord = true
				r.options.ScanUUID = ""
			case "read-error":
				missing = false
				if _, err := repo.DB().ExecContext(context.Background(), "ALTER TABLE scans RENAME TO unavailable_scans"); err != nil {
					t.Fatal(err)
				}
			case "insert-error":
				missing = false
				if _, err := repo.DB().ExecContext(context.Background(), `CREATE TRIGGER deny_scan_insert BEFORE INSERT ON scans BEGIN SELECT RAISE(FAIL, 'injected create failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			err := r.RunNativeScan()
			var identity *NativeScanIdentityError
			if !errors.As(err, &identity) || (missing && !errors.Is(err, sql.ErrNoRows)) {
				t.Fatalf("unavailable identity error=%v typed=%+v", err, identity)
			}
			assertNativeIdentityRejected(t, r, requests, received)
			for _, table := range []string{"scan_logs", "findings", "http_records"} {
				if n, err := repo.DB().NewSelect().TableExpr(table).Count(context.Background()); err != nil || n != 0 {
					t.Fatalf("rejected scan wrote %s: n=%d err=%v", table, n, err)
				}
			}
		})
	}
}

func TestNativeProjectIsolationSameProjectCompletionAndCounts(t *testing.T) {
	for _, scenario := range []string{"new", "existing-agent", "managed", "on-receive", "default", "memory-only"} {
		t.Run(scenario, func(t *testing.T) {
			withoutGlobalEvents(t)
			r := newCallbackScanRunner(t)
			r.options.ScanUUID = "owned-native"
			r.options.ProjectUUID = "project-a"
			r.options.SkipPreflight = true
			project := "project-a"
			if scenario == "default" {
				r.options.ProjectUUID = ""
				project = database.DefaultProjectUUID
			}
			repo := newBannerRepo(t)
			if scenario != "memory-only" {
				r.SetRepository(repo)
			}
			if scenario == "existing-agent" || scenario == "managed" || scenario == "on-receive" {
				if err := repo.CreateScan(context.Background(), &database.Scan{UUID: r.options.ScanUUID, ProjectUUID: project, Status: "running", AgenticScanUUID: "same-project-parent", Name: "original-agent-scan"}); err != nil {
					t.Fatal(err)
				}
			}
			r.options.ManagedScanRecord = scenario == "managed"
			r.options.ScanOnReceive = scenario == "on-receive"
			if scenario == "memory-only" {
				r.options.ScanUUID = "" // A legitimate unpinned memory-only scan.
			}
			var received callbackEvents
			r.SetEventCallback(received.record)
			var phases int
			r.phaseRunners = map[NativePhase]phaseRunner{}
			for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
				r.phaseRunners[phase] = phaseRunner{tag: string(phase), label: string(phase), run: func(r *Runner, ctx context.Context, _ *phaseInfra) error {
					phases++
					tracker := r.currentPhase.Load()
					tracker.recordFinding()
					var sent atomic.Int64
					tracker.addCounter(sent.Load)
					sent.Store(3)
					if phases == 1 && r.repository != nil {
						for _, p := range []string{project, "legacy-foreign"} {
							f := &database.Finding{ProjectUUID: p, ScanUUID: r.options.ScanUUID, ModuleID: "local", ModuleName: "local", Severity: "high", FindingHash: p, HTTPRecordUUIDs: []string{}}
							if _, err := repo.DB().NewInsert().Model(f).Exec(ctx); err != nil {
								return err
							}
						}
					}
					return nil
				}}
			}
			if err := r.RunNativeScan(); err != nil || phases != 2 {
				t.Fatalf("same-project run err=%v phases=%d", err, phases)
			}
			events := received.snapshot()
			assertCallbackEnvelope(t, events, r.options.ScanUUID)
			var finishedPhases int
			for _, ev := range events {
				if ev.Type == scanevents.TypePhaseFinished {
					finishedPhases++
					if ev.Findings == nil || *ev.Findings != 1 || ev.RequestsSent == nil || *ev.RequestsSent != 3 {
						t.Fatalf("phase counts changed: %+v", ev)
					}
				}
			}
			if finishedPhases != 2 || events[0].Project != project || events[len(events)-1].Type != scanevents.TypeScanFinished || events[len(events)-1].Status != scanevents.StatusCompleted {
				t.Fatalf("same-project lifecycle=%+v", events)
			}
			if scenario != "memory-only" {
				row, err := repo.GetScanByUUID(context.Background(), r.options.ScanUUID)
				if err != nil || row.ProjectUUID != project || row.Status != "completed" || row.TotalFindings != 1 || row.HighCount != 1 || row.HeartbeatAt == nil || !r.Finalized() {
					t.Fatalf("same-project terminal row=%+v err=%v finalized=%v", row, err, r.Finalized())
				}
				var banner bytes.Buffer
				r.printFinishedBanner(context.Background(), &banner, r.options.ScanUUID, time.Second, project)
				if !strings.Contains(banner.String(), "findings: 1") {
					t.Fatalf("banner included legacy foreign findings: %q", banner.String())
				}
				if (scenario == "existing-agent" || scenario == "managed" || scenario == "on-receive") && (row.AgenticScanUUID != "same-project-parent" || row.Name != "original-agent-scan") {
					t.Fatalf("same-project rescan replaced identity: %+v", row)
				}
			}
		})
	}
}

func TestNativeProjectIsolationPlanCallbackCannotAdoptForeignProject(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.ScanUUID, r.options.ProjectUUID = "owned-native", "project-a"
	var reassigned *database.Scan
	r.SetEventCallback(func(ev scanevents.Event) {
		if ev.Type != scanevents.TypeScanPlan {
			return
		}
		ctx := context.Background()
		if _, err := repo.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "project-b").Where("uuid = ?", r.options.ScanUUID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		r.options.ProjectUUID = "project-b"
		var err error
		reassigned, err = repo.GetScanByUUID(ctx, r.options.ScanUUID)
		if err != nil {
			t.Fatal(err)
		}
	})
	err := r.RunNativeScan()
	var identity *NativeScanIdentityError
	if !errors.As(err, &identity) || identity.ProjectUUID != "project-a" || r.Finalized() || r.liveness.Load() != nil {
		t.Fatalf("plan callback adopted changed identity: err=%v identity=%+v finalized=%v heartbeat=%v", err, identity, r.Finalized(), r.liveness.Load())
	}
	after, readErr := repo.GetScanByUUID(context.Background(), r.options.ScanUUID)
	if readErr != nil || reassigned == nil || !reflect.DeepEqual(reassigned, after) {
		t.Fatalf("plan callback's foreign row restamped: before=%+v after=%+v err=%v", reassigned, after, readErr)
	}
	if n, err := repo.DB().NewSelect().Model((*database.ScanLog)(nil)).Where("project_uuid = ?", "project-b").Count(context.Background()); err != nil || n != 0 {
		t.Fatalf("runner adopted foreign logger: n=%d err=%v", n, err)
	}
	if entries, err := os.ReadDir(r.settings.ScanningStrategy.ScanLogs.SessionsDir); err != nil || len(entries) != 0 {
		t.Fatalf("runner initialized reassigned heartbeat: entries=%v err=%v", entries, err)
	}
}

func TestNativeProjectIsolationCLIEventPhaseCounts(t *testing.T) {
	buf := withEventStream(t)
	r := newCallbackScanRunner(t)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.ScanUUID, r.options.ProjectUUID = "scan-test", "project-a"
	r.options.SkipPreflight = true
	r.phaseRunners = map[NativePhase]phaseRunner{}
	for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
		r.phaseRunners[phase] = phaseRunner{tag: string(phase), label: string(phase), run: func(r *Runner, _ context.Context, _ *phaseInfra) error {
			tr := r.currentPhase.Load()
			var requests atomic.Int64
			tr.addCounter(requests.Load)
			requests.Store(4)
			tr.recordFinding()
			tr.recordFinding()
			return nil
		}}
	}
	if err := r.RunNativeScan(); err != nil || !r.Finalized() {
		t.Fatalf("native CLI stream run err=%v finalized=%v", err, r.Finalized())
	}
	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	if len(finished) != 2 {
		t.Fatalf("native CLI stream phase events=%s", buf.String())
	}
	for _, ev := range finished {
		if ev["requests_sent"] != float64(4) || ev["findings"] != float64(2) || ev["status"] != scanevents.StatusCompleted || ev["scan_uuid"] != "scan-test" {
			t.Fatalf("native CLI stdout phase counts changed: %v", ev)
		}
	}
}

// Reassign between the final identity read and the scoped timing read. The
// completion's sql.ErrNoRows must still be a typed identity failure so callers
// cannot run an unscoped completion safety net against the reassigned row.
func TestNativeProjectIsolationFinalizerReadFailureIsTyped(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.ScanUUID, r.options.ProjectUUID = "owned-native", "project-a"
	r.SetEventCallback(func(scanevents.Event) {})
	r.phaseRunners = map[NativePhase]phaseRunner{}
	var reassigned *database.Scan
	repo.DB().AddQueryHook(nativeIsolationQueryHook{before: func(ctx context.Context, ev *bun.QueryEvent) {
		if !strings.HasPrefix(ev.Query, `SELECT "sc"."started_at" FROM`) {
			return
		}
		if _, err := repo.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "project-b").Where("uuid = ?", r.options.ScanUUID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var err error
		reassigned, err = repo.GetScanByUUID(ctx, r.options.ScanUUID)
		if err != nil {
			t.Fatal(err)
		}
	}})
	err := r.RunNativeScan()
	var identity *NativeScanIdentityError
	if !errors.As(err, &identity) || !errors.Is(err, sql.ErrNoRows) || r.Finalized() || reassigned == nil {
		t.Fatalf("scoped finalizer read failure err=%v identity=%+v finalized=%v hook_ran=%v", err, identity, r.Finalized(), reassigned != nil)
	}
	after, readErr := repo.GetScanByUUID(context.Background(), r.options.ScanUUID)
	if readErr != nil || !reflect.DeepEqual(reassigned, after) {
		t.Fatalf("finalizer changed reassigned row: before=%+v after=%+v err=%v", reassigned, after, readErr)
	}
}

func TestNativeProjectIsolationReassignmentCannotFinalize(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.ScanUUID, r.options.ProjectUUID = "owned-native", "project-a"
	var received callbackEvents
	r.SetEventCallback(received.record)
	var reassigned *database.Scan
	r.phaseRunners = map[NativePhase]phaseRunner{
		PhaseDiscovery: {tag: "discovery", label: "discovery", run: func(r *Runner, ctx context.Context, _ *phaseInfra) error {
			r.noteModuleError("original-module", "failure")
			if _, err := repo.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "project-b").Where("uuid = ?", r.options.ScanUUID).Exec(ctx); err != nil {
				return fatal(err)
			}
			var err error
			reassigned, err = repo.GetScanByUUID(ctx, r.options.ScanUUID)
			if err != nil {
				return fatal(err)
			}
			return fatal(errors.New("stop after external reassignment"))
		}},
	}
	err := r.RunNativeScan()
	if !errors.Is(err, database.ErrScanProjectMismatch) || r.Finalized() {
		t.Fatalf("reassigned completion err=%v finalized=%v", err, r.Finalized())
	}
	after, readErr := repo.GetScanByUUID(context.Background(), r.options.ScanUUID)
	if readErr != nil || !reflect.DeepEqual(reassigned, after) {
		t.Fatalf("reassigned row changed by finalizer/heartbeat: before=%+v after=%+v err=%v", reassigned, after, readErr)
	}
	for _, ev := range received.snapshot() {
		if ev.Type == scanevents.TypeScanFinished && (ev.Status != scanevents.StatusFailed || !strings.Contains(ev.Message, "identity")) {
			t.Fatalf("reassigned completion callback=%+v", ev)
		}
	}
}
