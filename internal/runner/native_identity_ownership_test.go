package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
)

// A request header can be converted to a string without copying by an HTTP
// adapter. Reusing its backing bytes after Runner construction must not change
// the identities this invocation sends to its callback, logger or finalizer.
func TestRunnerOwnsInvocationIdentityAcrossCallbackBufferReuse(t *testing.T) {
	withoutGlobalEvents(t)

	const (
		projectID = "3af56732-9c75-4fc2-8ace-a2e5655b725c"
		scanID    = "11bbf7b3-84f4-4336-80c6-04cfd93947b4"
	)
	projectBytes := []byte(projectID)
	scanBytes := []byte(scanID)
	borrow := func(b []byte) string { return unsafe.String(unsafe.SliceData(b), len(b)) }

	opts := types.DefaultOptions()
	opts.Silent = true
	opts.OnlyPhase = "discovery,dynamic-assessment"
	opts.ProjectUUID = borrow(projectBytes)
	opts.ScanUUID = borrow(scanBytes)
	if err := ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatal(err)
	}
	r, err := NewWithInputSource(opts, source.NewSliceSource(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Discard)
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = false
	settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()
	r.SetSettings(settings)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.SkipPreflight = true

	type eventIdentity struct{ kind, scan, project string }
	var received []eventIdentity
	r.SetEventCallback(func(ev scanevents.Event) {
		// Copy at callback receipt so the test distinguishes a later byte-buffer
		// mutation from the callback retaining borrowed string storage itself.
		received = append(received, eventIdentity{
			kind: ev.Type, scan: strings.Clone(ev.ScanUUID), project: strings.Clone(ev.Project),
		})
		if ev.Type == scanevents.TypeScanStarted {
			projectBytes[0] = '1'
			scanBytes[0] = '9'
		}
	})

	var phases int
	r.phaseRunners = map[NativePhase]phaseRunner{}
	for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
		r.phaseRunners[phase] = phaseRunner{
			tag: string(phase), label: string(phase),
			run: func(r *Runner, ctx context.Context, infra *phaseInfra) error {
				phases++
				if r.options.ProjectUUID != projectID || r.options.ScanUUID != scanID || infra.scanUUID != scanID {
					t.Errorf("phase identity changed: options=(%q,%q) infra.scan=%q", r.options.ProjectUUID, r.options.ScanUUID, infra.scanUUID)
				}
				r.scanLogger.Info(string(phase), "phase identity remains owned")
				return nil
			},
		}
	}

	if err := r.RunNativeScan(); err != nil {
		t.Fatalf("RunNativeScan with caller-buffer reuse: %v", err)
	}
	if phases != 2 {
		t.Fatalf("ran %d phases, want both phases", phases)
	}
	if !r.Finalized() {
		t.Fatal("scan did not finalize")
	}
	if r.options.ProjectUUID != projectID || r.options.ScanUUID != scanID {
		t.Fatalf("runner options changed: project=%q scan=%q", r.options.ProjectUUID, r.options.ScanUUID)
	}
	if len(received) == 0 || received[0].kind != scanevents.TypeScanStarted || received[len(received)-1].kind != scanevents.TypeScanFinished {
		t.Fatalf("callback lifecycle is incomplete: %+v", received)
	}
	for _, ev := range received {
		if ev.scan != scanID {
			t.Errorf("callback %s scan identity=%q, want %q", ev.kind, ev.scan, scanID)
		}
		if ev.project != "" && ev.project != projectID {
			t.Errorf("callback %s project identity=%q, want %q", ev.kind, ev.project, projectID)
		}
	}

	row, err := repo.GetScanByUUID(context.Background(), scanID)
	if err != nil || row.ProjectUUID != projectID || row.Status != "completed" || row.HeartbeatAt == nil {
		t.Fatalf("scan row did not retain admitted identity/completion: row=%+v err=%v", row, err)
	}
	var logs []*database.ScanLog
	if err := repo.DB().NewSelect().Model(&logs).Where("scan_uuid = ?", scanID).Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatal("phase logger did not write logs")
	}
	for _, log := range logs {
		if log.ProjectUUID != projectID {
			t.Errorf("scan log project=%q, want %q", log.ProjectUUID, projectID)
		}
	}
}

// Replacing the caller's Options fields after construction is separate from
// reusing a borrowed string's backing bytes: the Runner must also own the
// Options struct itself. This does not mutate r.options, which remains subject
// to the native scan's deliberate reassignment rejection.
func TestRunnerRejectsInternalInvocationOptionsReassignment(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.ScanUUID, r.options.ProjectUUID = "owned-native", "project-a"
	r.SetEventCallback(func(ev scanevents.Event) {
		if ev.Type == scanevents.TypeScanPlan {
			// This is a deliberate mutation of Runner-owned invocation state,
			// unlike a caller reusing the Options passed to New.
			r.options.ProjectUUID = "project-b"
		}
	})

	err := r.RunNativeScan()
	var identity *NativeScanIdentityError
	if !errors.As(err, &identity) || identity.ProjectUUID != "project-a" || r.Finalized() || r.liveness.Load() != nil {
		t.Fatalf("runner accepted internal identity reassignment: err=%v identity=%+v finalized=%v heartbeat=%v",
			err, identity, r.Finalized(), r.liveness.Load())
	}
	row, readErr := repo.GetScanByUUID(context.Background(), "owned-native")
	if readErr != nil || row.ProjectUUID != "project-a" || row.Status != "running" {
		t.Fatalf("rejected reassignment changed the owned row: row=%+v err=%v", row, readErr)
	}
}

func TestRunnerOwnsOptionsStructAtConstruction(t *testing.T) {
	withoutGlobalEvents(t)
	const (
		projectID = "3af56732-9c75-4fc2-8ace-a2e5655b725c"
		foreignID = "1af56732-9c75-4fc2-8ace-a2e5655b725c"
		scanID    = "11bbf7b3-84f4-4336-80c6-04cfd93947b4"
		otherScan = "91bbf7b3-84f4-4336-80c6-04cfd93947b4"
	)
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.OnlyPhase = "discovery,dynamic-assessment"
	opts.ProjectUUID, opts.ScanUUID = projectID, scanID
	if err := ApplyNativePhaseSelection(opts, nil); err != nil {
		t.Fatal(err)
	}
	r, err := NewWithInputSource(opts, source.NewSliceSource(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Discard)
	settings := config.DefaultSettings()
	settings.OAST.Enabled = false
	settings.DynamicAssessment.Extensions.Enabled = false
	settings.ScanningStrategy.ScanLogs.SessionsDir = t.TempDir()
	r.SetSettings(settings)
	repo := newBannerRepo(t)
	r.SetRepository(repo)
	r.options.SkipPreflight = true
	r.phaseRunners = map[NativePhase]phaseRunner{}
	for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
		r.phaseRunners[phase] = phaseRunner{tag: string(phase), label: string(phase), run: func(*Runner, context.Context, *phaseInfra) error { return nil }}
	}

	// A caller may reuse the struct for the next request/run as soon as the
	// constructor returns. This is not a reassignment of the Runner's invocation.
	opts.ProjectUUID, opts.ScanUUID = foreignID, otherScan
	if err := r.RunNativeScan(); err != nil {
		t.Fatalf("RunNativeScan after caller Options replacement: %v", err)
	}
	row, err := repo.GetScanByUUID(context.Background(), scanID)
	if err != nil || row.ProjectUUID != projectID || row.Status != "completed" {
		t.Fatalf("runner did not retain its constructor identity: row=%+v err=%v", row, err)
	}
	if n, err := repo.DB().NewSelect().Model((*database.Scan)(nil)).Where("uuid = ?", otherScan).Count(context.Background()); err != nil || n != 0 {
		t.Fatalf("caller replacement created a second scan row: count=%d err=%v", n, err)
	}
}
