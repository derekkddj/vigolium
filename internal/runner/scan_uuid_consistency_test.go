package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

func TestScanUUIDIsConsistentAcrossCallbackAndCLILaunchPaths(t *testing.T) {
	for _, mode := range []string{"callback", "cli"} {
		t.Run(mode, func(t *testing.T) {
			withoutGlobalEvents(t)
			r := newCallbackScanRunner(t)
			r.SetRepository(newBannerRepo(t))
			if mode == "cli" {
				// CLI/launch paths pin the UUID before installing their event
				// emitter; mirror that ordering while entering the runner with it.
				r.options.ScanUUID = buildLaunchOptions(LaunchParams{Targets: r.options.Targets}).ScanUUID
			}

			var events []scanevents.Event
			var eventJSON bytes.Buffer
			if mode == "callback" {
				r.SetEventCallback(func(ev scanevents.Event) { events = append(events, ev) })
			} else {
				emitter := scanevents.New(&eventJSON, r.options.ScanUUID)
				scanevents.Install(emitter)
				t.Cleanup(func() { scanevents.Install(nil) })
			}

			var executorScanUUID string
			r.phaseRunners = map[NativePhase]phaseRunner{
				PhaseDiscovery: {
					tag: "discovery", label: "discovery",
					run: func(r *Runner, _ context.Context, _ *phaseInfra) error {
						r.scanLogger.Info("discovery", "UUID consistency probe")
						return nil
					},
				},
				PhaseDynamicAssessment: {
					tag: "dynamic-assessment", label: "dynamic-assessment",
					run: func(_ *Runner, _ context.Context, infra *phaseInfra) error {
						// Production executor configs use infra.scanUUID directly.
						executorScanUUID = infra.scanUUID
						return nil
					},
				},
			}

			if mode == "callback" {
				r.options.ScanUUID = ""
			}
			if err := r.RunNativeScan(); err != nil {
				t.Fatalf("RunNativeScan: %v", err)
			}
			scanUUID := r.options.ScanUUID
			if scanUUID == "" {
				t.Fatal("runner did not assign a scan UUID")
			}
			if executorScanUUID != scanUUID {
				t.Errorf("executor identity = %q, runner identity = %q", executorScanUUID, scanUUID)
			}

			statusPath := SessionStatusPath(r.settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(), scanUUID)
			status, err := ReadSessionStatus(statusPath)
			if err != nil || status == nil {
				t.Fatalf("read status.json at %q: status=%+v err=%v", statusPath, status, err)
			}
			if status.ScanUUID != scanUUID {
				t.Errorf("status.json scan_uuid = %q, want %q", status.ScanUUID, scanUUID)
			}

			row, err := r.repository.GetScanByUUID(context.Background(), scanUUID)
			if err != nil || row.Status != "completed" || row.HeartbeatAt == nil {
				t.Fatalf("scan row = %+v, err=%v", row, err)
			}
			var logs []*database.ScanLog
			if err := r.repository.DB().NewSelect().Model(&logs).Where("scan_uuid = ?", scanUUID).Scan(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(logs) == 0 {
				t.Fatal("scan logger wrote no rows for the generated UUID")
			}
			for _, log := range logs {
				if log.ScanUUID != scanUUID {
					t.Errorf("scan log UUID = %q, want %q", log.ScanUUID, scanUUID)
				}
			}

			if mode == "callback" {
				if len(events) < 2 {
					t.Fatalf("callback events = %+v, want lifecycle events", events)
				}
				for _, ev := range events {
					if ev.ScanUUID != scanUUID {
						t.Errorf("callback %s scan UUID = %q, want %q", ev.Type, ev.ScanUUID, scanUUID)
					}
				}
			} else {
				lines := bytes.Split(bytes.TrimSpace(eventJSON.Bytes()), []byte("\n"))
				if eventJSON.Len() == 0 {
					t.Fatal("CLI event stream received no events")
				}
				for _, line := range lines {
					var ev scanevents.Event
					if err := json.Unmarshal(line, &ev); err != nil {
						t.Fatalf("decode CLI event %q: %v", line, err)
					}
					if ev.ScanUUID != scanUUID {
						t.Errorf("CLI %s scan UUID = %q, want %q", ev.Type, ev.ScanUUID, scanUUID)
					}
				}
			}

			if filepath.Base(filepath.Dir(statusPath)) != scanUUID {
				t.Errorf("status path %q does not use scan UUID %q", statusPath, scanUUID)
			}
		})
	}
}
