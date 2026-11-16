package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

type nativeIsolationInput struct {
	source.InputSource
	closed atomic.Int64
}

func (s *nativeIsolationInput) Close() error {
	s.closed.Add(1)
	return s.InputSource.Close()
}

// Background reconciliation must not turn a rejected correlation UUID into a
// foreign completion/report/webhook. Drain joins any incorrectly queued webhook
// deterministically; no sleeps or external targets/providers are used.
func TestBackgroundScanScopedFallbackRefusesReassignedRow(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)
	const scanID = "late-reassignment"
	if err := repo.CreateScan(ctx, &database.Scan{UUID: scanID, ProjectUUID: "project-a", Status: "running", TotalFindings: 9}); err != nil {
		t.Fatal(err)
	}
	var webhookCalls, reportCalls atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.ScanUUID, opts.ProjectUUID = scanID, "project-a"
	opts.ManagedScanRecord = true
	opts.Modules = []string{"ext-missing"} // Setup fails before target traffic.
	opts.OnlyPhase = "discovery,dynamic-assessment"
	if err := runner.ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatal(err)
	}
	r, err := runner.NewWithInputSource(opts, source.NewSliceSource(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Discard)
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = false
	settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()
	settings.Notify = config.NotifyConfig{Enabled: true, Provider: config.NotifyProviderWebhook, Webhook: config.WebhookConfig{URL: receiver.URL, TimeoutSec: 1}}
	r.SetSettings(settings)
	r.SetRepository(repo)
	var reassigned *database.Scan
	r.SetEventCallback(func(ev scanevents.Event) {
		if ev.Type != scanevents.TypeScanFinished {
			return
		}
		// Runner's final validation is over, but the server safety net has not
		// started. Even this late change must not be completed across projects.
		if _, err := repo.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "project-b").Where("uuid = ?", scanID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var err error
		reassigned, err = repo.GetScanByUUID(ctx, scanID)
		if err != nil {
			t.Fatal(err)
		}
	})
	h := &Handlers{db: repo.DB(), repo: repo, settings: settings,
		config: ServerConfig{RenderReport: func(context.Context, *database.DB, string, string, string, string) error {
			reportCalls.Add(1)
			return nil
		}}, scanStates: map[string]*scanState{"project-a": {running: true, runner: r, scanID: scanID}},
	}
	h.runBackgroundScan(scanID, r, "project-a", true, scanOutputs{base: filepath.Join(t.TempDir(), "output"), formats: []string{"html"}})
	if n := webhook.Drain(5 * time.Second); n != 0 {
		t.Fatalf("webhook deliveries pending: %d", n)
	}
	after, err := repo.GetScanByUUID(ctx, scanID)
	if err != nil || reassigned == nil || !reflect.DeepEqual(reassigned, after) || reportCalls.Load() != 0 || webhookCalls.Load() != 0 || h.scanStates["project-a"].running {
		t.Fatalf("safety net reconciled foreign row: before=%+v after=%+v err=%v reports=%d webhooks=%d", reassigned, after, err, reportCalls.Load(), webhookCalls.Load())
	}
}

func TestBackgroundScanRejectsNativeIdentityBeforeReconciliation(t *testing.T) {
	for _, scenario := range []string{"foreign-pinned", "foreign-managed", "foreign-default", "missing-managed"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			repo := newTestRepo(t)
			const scanID = "rejected-native"
			if scenario != "missing-managed" {
				if err := repo.CreateScan(ctx, &database.Scan{UUID: scanID, ProjectUUID: "project-a", Status: "running", PID: 123, TotalRequests: 7, TotalFindings: 9}); err != nil {
					t.Fatal(err)
				}
				if err := repo.CreateScanLog(ctx, &database.ScanLog{ScanUUID: scanID, ProjectUUID: "project-a", Level: "info", Message: "original"}); err != nil {
					t.Fatal(err)
				}
				if err := repo.SaveFindingDirect(ctx, &database.Finding{ProjectUUID: "project-a", ScanUUID: scanID, ModuleID: "original", ModuleName: "original", Severity: "high", FindingHash: "original"}); err != nil {
					t.Fatal(err)
				}
			}
			var beforeScans []*database.Scan
			var beforeLogs []*database.ScanLog
			var beforeFindings []*database.Finding
			for _, model := range []any{&beforeScans, &beforeLogs, &beforeFindings} {
				if err := repo.DB().NewSelect().Model(model).Scan(ctx); err != nil {
					t.Fatal(err)
				}
			}

			var targetCalls, webhookCalls, reportCalls, callbacks atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				targetCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				webhookCalls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer receiver.Close()

			opts := types.DefaultOptions()
			opts.Silent = true
			opts.ScanUUID, opts.ProjectUUID = scanID, "project-b"
			opts.Targets = []string{target.URL}
			opts.ManagedScanRecord = scenario == "foreign-managed" || scenario == "missing-managed"
			project := opts.ProjectUUID
			if scenario == "foreign-default" {
				opts.ProjectUUID = ""
				project = database.DefaultProjectUUID
			}
			opts.OnlyPhase = "discovery,dynamic-assessment"
			if err := runner.ApplyNativePhaseSelection(opts, nil); err != nil {
				t.Fatal(err)
			}
			authPath := filepath.Join(t.TempDir(), "auth.yaml")
			auth := fmt.Sprintf("name: local\nrole: primary\nlogin:\n  url: %s/login\n  method: POST\n  type: cookie\n", target.URL)
			if err := os.WriteFile(authPath, []byte(auth), 0o600); err != nil {
				t.Fatal(err)
			}
			opts.AuthFiles = []string{authPath}
			input := &nativeIsolationInput{InputSource: source.NewSliceSource(nil, nil)}
			r, err := runner.NewWithInputSource(opts, input)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Discard)
			settings := config.DefaultSettings()
			settings.OAST.Enabled, settings.OAST.ServerURL = true, target.URL
			settings.DynamicAssessment.Extensions.Enabled = false
			settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()
			settings.Notify = config.NotifyConfig{Enabled: true, Provider: config.NotifyProviderWebhook, Webhook: config.WebhookConfig{URL: receiver.URL, TimeoutSec: 1}}
			r.SetSettings(settings)
			r.SetRepository(repo)
			r.SetEventCallback(func(scanevents.Event) { callbacks.Add(1) })
			h := &Handlers{
				db: repo.DB(), repo: repo, settings: settings,
				config: ServerConfig{RenderReport: func(context.Context, *database.DB, string, string, string, string) error {
					reportCalls.Add(1)
					return nil
				}},
				scanStates: map[string]*scanState{project: {running: true, runner: r, scanID: scanID}},
			}
			h.runBackgroundScan(scanID, r, project, true, scanOutputs{base: filepath.Join(t.TempDir(), "output"), formats: []string{"html"}})
			if n := webhook.Drain(5 * time.Second); n != 0 {
				t.Fatalf("webhook deliveries still pending: %d", n)
			}
			if targetCalls.Load() != 0 || webhookCalls.Load() != 0 || reportCalls.Load() != 0 || callbacks.Load() != 0 || r.Finalized() || r.ScanLogger() != nil {
				t.Fatalf("rejected scan reconciled: target=%d webhook=%d report=%d callbacks=%d finalized=%v logger=%v", targetCalls.Load(), webhookCalls.Load(), reportCalls.Load(), callbacks.Load(), r.Finalized(), r.ScanLogger())
			}
			state := h.scanStates[project]
			if state.running || state.runner != nil || state.scanID != "" || input.closed.Load() != 1 {
				t.Fatalf("rejected scan resources/state not cleared: state=%+v source_closed=%d", state, input.closed.Load())
			}
			r.Close() // The normal cleanup remains idempotent on this early exit.
			if input.closed.Load() != 1 {
				t.Fatal("runner closed its input more than once")
			}
			var afterScans []*database.Scan
			var afterLogs []*database.ScanLog
			var afterFindings []*database.Finding
			for _, model := range []any{&afterScans, &afterLogs, &afterFindings} {
				if err := repo.DB().NewSelect().Model(model).Scan(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(beforeScans, afterScans) || !reflect.DeepEqual(beforeLogs, afterLogs) || !reflect.DeepEqual(beforeFindings, afterFindings) {
				t.Fatal("background reconciliation changed rejected scan rows/logs/findings")
			}
			if n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx); err != nil || n != 0 {
				t.Fatalf("rejected scan persisted traffic: n=%d err=%v", n, err)
			}
			if entries, err := os.ReadDir(settings.ScanningStrategy.ScanLogs.SessionsDir); err != nil || len(entries) != 0 {
				t.Fatalf("rejected scan created session/log/heartbeat files: entries=%v err=%v", entries, err)
			}
		})
	}
}
