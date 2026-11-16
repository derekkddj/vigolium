package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func withoutGlobalEvents(t *testing.T) {
	t.Helper()
	prior := scanevents.Default()
	scanevents.Install(nil)
	t.Cleanup(func() { scanevents.Install(prior) })
}

type callbackEvents struct {
	mu     sync.Mutex
	events []scanevents.Event
}

func (c *callbackEvents) record(ev scanevents.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *callbackEvents) snapshot() []scanevents.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]scanevents.Event(nil), c.events...)
}

func assertCallbackEnvelope(t *testing.T, events []scanevents.Event, uuid string) {
	t.Helper()
	for i, ev := range events {
		if ev.ScanUUID != uuid || ev.V != scanevents.SchemaVersion || ev.Seq != uint64(i+1) {
			t.Errorf("event %d has wrong runner envelope: %+v", i, ev)
		}
		if _, err := time.Parse(scanevents.TimestampLayout, ev.TS); err != nil {
			t.Errorf("event %d timestamp %q: %v", i, ev.TS, err)
		}
	}
}

func TestRunnerEventCallbackPhaseWithGlobalDisabled(t *testing.T) {
	withoutGlobalEvents(t)
	var received callbackEvents
	r := &Runner{options: &types.Options{ScanUUID: "callback-phase"}}
	r.SetEventCallback(received.record)
	tr := r.beginPhase(context.Background(), string(PhaseDiscovery), nil)
	tr.noteError(errors.New("source refused"))
	tr.markPartial(database.ReasonPhaseDeadline)
	tr.noteLimit(database.LimitTargetBudget)
	tr.recordFinding()
	progress := tr.trackTargets(3)
	progress.Add(2)
	out := tr.finish(context.Background(), nil)

	events := received.snapshot()
	var kinds []string
	for _, ev := range events {
		kinds = append(kinds, ev.Type)
		if ev.Phase != string(PhaseDiscovery) {
			t.Errorf("wrong phase: %+v", ev)
		}
	}
	if !slices.Equal(kinds, []string{scanevents.TypePhaseStarted, scanevents.TypeError, scanevents.TypePhaseFinished}) {
		t.Fatalf("callback types = %v", kinds)
	}
	assertCallbackEnvelope(t, events, "callback-phase")
	finished := events[len(events)-1]
	if finished.Status != scanevents.StatusFailed || finished.Message != "source refused" || out.Errors != 1 {
		t.Errorf("error outcome not preserved: event=%+v outcome=%+v", finished, out)
	}
	if finished.RequestsSent == nil || *finished.RequestsSent != 0 || finished.Findings == nil || *finished.Findings != 1 {
		t.Errorf("nil requester/finding counts: %+v", finished)
	}
	if finished.Done == nil || *finished.Done != 2 || finished.Total == nil || *finished.Total != 3 || finished.Unit != progressUnitTargets {
		t.Errorf("work progress not preserved: %+v", finished)
	}
	if !slices.Equal(finished.Reasons, out.Reasons) || !slices.Equal(finished.Limits, out.Limits) {
		t.Errorf("outcome codes differ: event=%+v outcome=%+v", finished, out)
	}
	if scanevents.On() || scanevents.Default() != nil {
		t.Fatal("callback enabled the process emitter")
	}
}

func TestRunnerEventCallbackHeartbeatStopsAtPhaseFinish(t *testing.T) {
	withoutGlobalEvents(t)
	if progressInterval != 5*time.Second {
		t.Fatalf("heartbeat interval = %s, want 5s", progressInterval)
	}
	var received callbackEvents
	progressEvent := make(chan scanevents.Event, 2)
	r := &Runner{options: &types.Options{ScanUUID: "callback-heartbeat"}}
	r.SetEventCallback(func(ev scanevents.Event) {
		received.record(ev)
		if ev.Type == scanevents.TypePhaseProgress {
			progressEvent <- ev
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := r.beginPhase(ctx, string(PhaseProbe), nil)
	defer func() {
		if tr != nil {
			tr.finish(ctx, nil)
		}
	}()
	var requests atomic.Int64
	tr.addCounter(requests.Load)
	requests.Store(7)
	tr.recordFinding()
	tr.trackTargets(2).Add(1)
	select {
	case ev := <-progressEvent:
		if ev.RequestsSent == nil || *ev.RequestsSent != 7 || ev.Findings == nil || *ev.Findings != 1 || ev.Done == nil || *ev.Done != 1 {
			t.Errorf("heartbeat counters: %+v", ev)
		}
	case <-time.After(progressInterval + 3*time.Second):
		t.Fatal("no callback heartbeat with global events disabled")
	}
	stopped := tr.stopped
	tr.finish(ctx, nil)
	tr = nil
	select {
	case <-stopped:
	default:
		t.Fatal("phase finish returned without joining heartbeat")
	}
	events := received.snapshot()
	assertCallbackEnvelope(t, events, "callback-heartbeat")
	if len(events) != 3 || events[len(events)-1].Type != scanevents.TypePhaseFinished {
		t.Fatalf("unexpected phase sequence: %+v", events)
	}
	select {
	case ev := <-progressEvent:
		t.Fatalf("heartbeat emitted after phase finished: %+v", ev)
	default:
	}
}

func TestRunnerEventCallbackHeartbeatStopsOnContextCancellation(t *testing.T) {
	withoutGlobalEvents(t)
	r := &Runner{}
	r.SetEventCallback(func(scanevents.Event) {})
	ctx, cancel := context.WithCancel(context.Background())
	tr := r.beginPhase(ctx, string(PhaseProbe), nil)
	defer tr.finish(ctx, nil)
	cancel()
	select {
	case <-tr.stopped:
	case <-time.After(time.Second):
		t.Fatal("heartbeat outlived cancelled phase context")
	}
}

func TestRunnerEventCallbackDoesNotSubscribeToOrWriteGlobalEmitter(t *testing.T) {
	buf := withEventStream(t)
	global := scanevents.Default()
	var received callbackEvents
	r := &Runner{options: &types.Options{ScanUUID: "local"}}
	r.SetEventCallback(received.record)
	scanevents.Emit(scanevents.Event{Type: scanevents.TypeError, Message: "foreign scan"})
	tr := r.beginPhase(context.Background(), string(PhaseProbe), nil)
	tr.finish(context.Background(), nil)
	if scanevents.Default() != global {
		t.Fatal("callback replaced the global emitter")
	}
	assertCallbackEnvelope(t, received.snapshot(), "local")
	if got := received.snapshot(); len(got) != 2 {
		t.Fatalf("callback received foreign global events: %+v", got)
	}
	if got := eventsOfType(t, buf, scanevents.TypePhaseStarted); len(got) != 0 {
		t.Fatalf("callback scan wrote into the CLI stream: %s", buf.String())
	}
	if got := eventsOfType(t, buf, scanevents.TypeError); len(got) != 1 || got[0]["message"] != "foreign scan" {
		t.Fatalf("CLI stream was modified: %s", buf.String())
	}
}

func TestRunnerEventCallbackNilPreservesCLI(t *testing.T) {
	buf := withEventStream(t)
	r := &Runner{}
	r.SetEventCallback(func(scanevents.Event) { t.Error("removed callback invoked") })
	r.SetEventCallback(nil)
	tr := r.beginPhase(context.Background(), string(PhaseProbe), nil)
	tr.noteError(errors.New("phase error"))
	tr.finish(context.Background(), nil)
	for _, kind := range []string{scanevents.TypePhaseStarted, scanevents.TypeError, scanevents.TypePhaseFinished} {
		if got := eventsOfType(t, buf, kind); len(got) != 1 {
			t.Errorf("CLI %s count = %d, want 1", kind, len(got))
		}
	}
	if r.beginCallbackScan(NativeScanPlan{}) {
		t.Fatal("nil callback enabled runner-owned scan lifecycle")
	}
}

func TestRunnerEventCallbackNilWithoutGlobalDoesNotStartHeartbeat(t *testing.T) {
	withoutGlobalEvents(t)
	r := &Runner{}
	r.SetEventCallback(nil)
	tr := r.beginPhase(context.Background(), string(PhaseProbe), nil)
	if tr.stop != nil || tr.stopped != nil {
		t.Error("nil callback started an event-only heartbeat with global events off")
	}
	tr.noteError(errors.New("still recorded without events"))
	if out := tr.finish(context.Background(), nil); out.Errors != 1 || out.State != database.PhaseFailed {
		t.Errorf("nil callback lost outcome ledger: %+v", out)
	}
}

func TestRunnerEventCallbackFindingsAreIsolatedAndSerialized(t *testing.T) {
	withoutGlobalEvents(t)
	const runners, workers, findingsPerWorker = 3, 8, 20
	type instance struct {
		r     *Runner
		phase *phaseTracker
		// No mutex: the runner must serialize callbacks, even concurrent writes.
		events []scanevents.Event
		prior  atomic.Int64
	}
	instances := make([]*instance, runners)
	for i := range instances {
		in := &instance{}
		sw := &output.StandardWriter{DisableStdout: true, OnEvent: func(*output.ResultEvent) { in.prior.Add(1) }}
		in.r = &Runner{options: &types.Options{ScanUUID: fmt.Sprintf("findings-%d", i)}, output: sw}
		in.r.SetEventCallback(func(ev scanevents.Event) { in.events = append(in.events, ev) })
		in.phase = in.r.beginPhase(context.Background(), string(PhaseDynamicAssessment), nil)
		in.r.currentPhase.Store(in.phase)
		in.r.attachEventObserver()
		in.r.attachEventObserver() // must not double-wrap or double-count
		instances[i] = in
	}
	var wg sync.WaitGroup
	for i, in := range instances {
		for worker := 0; worker < workers; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := 0; n < findingsPerWorker; n++ {
					ev := &output.ResultEvent{
						ModuleID: fmt.Sprintf("module-%d", i),
						Host:     fmt.Sprintf("host-%d.test", i),
						URL:      fmt.Sprintf("https://host-%d.test/path", i),
						Info:     output.Info{Severity: severity.High},
						Request:  "PRIVATE-HTTP-REQUEST",
						Response: "PRIVATE-HTTP-RESPONSE",
						Payload:  "PRIVATE-PAYLOAD",
						Matched:  "PRIVATE-MATCHED-PAYLOAD",
					}
					if err := in.r.output.Write(ev); err != nil {
						t.Errorf("finding write: %v", err)
					}
				}
			}()
		}
	}
	wg.Wait()
	for i, in := range instances {
		in.r.currentPhase.Store(nil)
		in.phase.finish(context.Background(), nil)
		assertCallbackEnvelope(t, in.events, in.r.options.ScanUUID)
		want := int64(workers * findingsPerWorker)
		if in.prior.Load() != want || len(in.events) != int(want)+2 {
			t.Errorf("runner %d callback/wrapper counts: prior=%d events=%d", i, in.prior.Load(), len(in.events))
		}
		for _, ev := range in.events {
			if ev.Type == scanevents.TypeFindingNew && (ev.ModuleID != fmt.Sprintf("module-%d", i) || ev.Host != fmt.Sprintf("host-%d.test", i) || ev.Severity != "high") {
				t.Errorf("runner %d received another runner's finding: %+v", i, ev)
			}
			data, err := json.Marshal(ev)
			if err != nil || strings.Contains(string(data), "PRIVATE-") {
				t.Errorf("event exposed HTTP/payload evidence: %s (%v)", data, err)
			}
		}
		finished := in.events[len(in.events)-1]
		if finished.Findings == nil || *finished.Findings != want {
			t.Errorf("runner %d phase findings = %v, want %d", i, finished.Findings, want)
		}
	}
}

func newCallbackScanRunner(t *testing.T) *Runner {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.OnlyPhase = "discovery,dynamic-assessment"
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
	return r
}

func TestRunnerEventCallbackScanLifecycle(t *testing.T) {
	withoutGlobalEvents(t)
	for _, tc := range []struct {
		name   string
		run    func(*Runner, context.Context, *phaseInfra) error
		status string
		failed bool
	}{
		{"completed", func(*Runner, context.Context, *phaseInfra) error { return nil }, scanevents.StatusCompleted, false},
		{"phase-error", func(*Runner, context.Context, *phaseInfra) error { return errors.New("phase failed") }, scanevents.StatusCurtailed, false},
		{"fatal", func(*Runner, context.Context, *phaseInfra) error { return fatal(errors.New("writer gone")) }, scanevents.StatusFailed, true},
		{"panic", func(*Runner, context.Context, *phaseInfra) error { panic("phase panic") }, scanevents.StatusFailed, true},
		{"cancelled", func(r *Runner, _ context.Context, _ *phaseInfra) error { r.cancel(); return context.Canceled }, scanevents.StatusInterrupted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newCallbackScanRunner(t)
			var received callbackEvents
			r.SetEventCallback(received.record)
			r.phaseRunners = map[NativePhase]phaseRunner{
				PhaseDiscovery:         {tag: "discovery", label: "discovery", run: tc.run},
				PhaseDynamicAssessment: {tag: "dynamic-assessment", label: "dynamic-assessment", run: func(*Runner, context.Context, *phaseInfra) error { return nil }},
			}
			err := r.RunNativeScan()
			if (err != nil) != tc.failed {
				t.Errorf("run error = %v, want failure=%v", err, tc.failed)
			}
			events := received.snapshot()
			if len(events) < 2 || events[0].Type != scanevents.TypeScanStarted || events[len(events)-1].Type != scanevents.TypeScanFinished {
				t.Fatalf("missing scan lifecycle: %+v", events)
			}
			if r.options.ScanUUID == "" {
				t.Fatal("callback scan did not generate its own UUID")
			}
			assertCallbackEnvelope(t, events, r.options.ScanUUID)
			finished := events[len(events)-1]
			if finished.Status != tc.status {
				t.Errorf("scan status = %s, want %s: %+v", finished.Status, tc.status, finished)
			}
			if tc.failed && finished.Message == "" {
				t.Error("failed scan callback missing error message")
			}
			var terminal int
			for _, ev := range events {
				if ev.Type == scanevents.TypeScanFinished {
					terminal++
				}
			}
			if terminal != 1 || scanevents.On() {
				t.Errorf("terminal events=%d global enabled=%v", terminal, scanevents.On())
			}
		})
	}
}

func TestRunnerEventCallbackScanSetupFailureStillFinishes(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	r.options.Modules = []string{"ext-missing"}
	var received callbackEvents
	r.SetEventCallback(received.record)
	if err := r.RunNativeScan(); !errors.Is(err, ErrUnknownExtensionModule) {
		t.Fatalf("expected infrastructure selection failure, got %v", err)
	}
	events := received.snapshot()
	if len(events) != 2 || events[0].Type != scanevents.TypeScanStarted || events[1].Type != scanevents.TypeScanFinished || events[1].Status != scanevents.StatusFailed || events[1].Message == "" {
		t.Fatalf("infrastructure failure lifecycle = %+v", events)
	}
	assertCallbackEnvelope(t, events, r.options.ScanUUID)
	r.emitFindingEvent(&output.ResultEvent{ModuleID: "late-after-setup-failure"})
	r.emitEvent(scanevents.Event{Type: scanevents.TypeScanFinished})
	if got := received.snapshot(); len(got) != len(events) {
		t.Fatalf("setup failure did not close callback delivery: %+v", got)
	}
}

func TestRunnerEventCallbackConcurrentScans(t *testing.T) {
	withoutGlobalEvents(t)
	const count = 3
	runners := make([]*Runner, count)
	collectors := make([]callbackEvents, count)
	entered := make(chan struct{}, count)
	release := make(chan struct{})
	results := make(chan error, count)
	for i := range runners {
		r := newCallbackScanRunner(t)
		r.options.ScanUUID = fmt.Sprintf("concurrent-%d", i)
		r.SetEventCallback(collectors[i].record)
		r.phaseRunners = map[NativePhase]phaseRunner{
			PhaseDiscovery: {tag: "discovery", label: "discovery", run: func(r *Runner, _ context.Context, _ *phaseInfra) error {
				entered <- struct{}{}
				<-release
				return r.output.Write(&output.ResultEvent{ModuleID: fmt.Sprintf("module-%d", i), Info: output.Info{Severity: severity.High}})
			}},
			PhaseDynamicAssessment: {tag: "dynamic-assessment", label: "dynamic-assessment", run: func(*Runner, context.Context, *phaseInfra) error { return nil }},
		}
		runners[i] = r
	}
	for _, r := range runners {
		go func() { results <- r.RunNativeScan() }()
	}
	for range count {
		<-entered
	}
	close(release)
	for range count {
		if err := <-results; err != nil {
			t.Errorf("concurrent scan: %v", err)
		}
	}
	for i, r := range runners {
		events := collectors[i].snapshot()
		assertCallbackEnvelope(t, events, r.options.ScanUUID)
		if len(events) == 0 || events[0].Type != scanevents.TypeScanStarted || events[len(events)-1].Type != scanevents.TypeScanFinished {
			t.Fatalf("runner %d incomplete callback lifecycle: %+v", i, events)
		}
		var findings int
		for _, ev := range events {
			if ev.Type == scanevents.TypeFindingNew {
				findings++
				if ev.ModuleID != fmt.Sprintf("module-%d", i) {
					t.Errorf("runner %d got another runner's finding: %+v", i, ev)
				}
			}
		}
		if findings != 1 {
			t.Errorf("runner %d findings = %d, want 1", i, findings)
		}
	}
	if scanevents.On() {
		t.Fatal("concurrent callbacks enabled global events")
	}
}

func TestRunnerEventCallbackImmutableDuringRun(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var received callbackEvents
	var replacementCalls atomic.Int64
	r.SetEventCallback(received.record)
	r.phaseRunners = map[NativePhase]phaseRunner{
		PhaseDiscovery: {tag: "discovery", label: "discovery", run: func(*Runner, context.Context, *phaseInfra) error {
			close(entered)
			<-release
			return nil
		}},
		PhaseDynamicAssessment: {tag: "dynamic-assessment", label: "dynamic-assessment", run: func(*Runner, context.Context, *phaseInfra) error { return nil }},
	}
	result := make(chan error, 1)
	go func() { result <- r.RunNativeScan() }()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.SetEventCallback(func(scanevents.Event) { replacementCalls.Add(1) })
			r.SetEventCallback(nil)
			r.emitEvent(scanevents.Event{Type: scanevents.TypeError, Message: "still original callback"})
		}()
	}
	wg.Wait()
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if replacementCalls.Load() != 0 {
		t.Fatalf("callback changed after RunNativeScan began: %d calls", replacementCalls.Load())
	}
	assertCallbackEnvelope(t, received.snapshot(), r.options.ScanUUID)
	if received.snapshot()[len(received.snapshot())-1].Type != scanevents.TypeScanFinished {
		t.Fatal("nil setter removed original callback during run")
	}
}

func TestRunnerEventCallbackNilIsAlsoImmutableAfterRun(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	r.phaseRunners = map[NativePhase]phaseRunner{}
	if err := r.RunNativeScan(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	r.SetEventCallback(func(scanevents.Event) { calls.Add(1) })
	r.emitEvent(scanevents.Event{Type: scanevents.TypeError})
	if calls.Load() != 0 {
		t.Error("callback was enabled after a nil-callback run")
	}
}

// Model an executor that returned without joining its passive worker. Its
// retained StandardWriter observer is released only after Native has returned.
func TestRunnerEventCallbackLateObserverAfterScanReturnIsDropped(t *testing.T) {
	buf := withEventStream(t)
	global := scanevents.Default()
	r := newCallbackScanRunner(t)
	r.options.ScanUUID = "terminal-late-observer"
	var received callbackEvents
	var priorCalls atomic.Int64
	sw := r.output.(*output.StandardWriter)
	sw.OnEvent = func(*output.ResultEvent) { priorCalls.Add(1) }
	r.SetEventCallback(received.record)
	lateRelease := make(chan struct{})
	lateResult := make(chan error, 1)
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(lateRelease) })
	r.phaseRunners = map[NativePhase]phaseRunner{
		PhaseDiscovery: {tag: "discovery", label: "discovery", run: func(r *Runner, _ context.Context, _ *phaseInfra) error {
			go func() {
				<-lateRelease
				lateResult <- r.output.Write(&output.ResultEvent{ModuleID: "abandoned-worker", Info: output.Info{Severity: severity.High}})
			}()
			return nil
		}},
		PhaseDynamicAssessment: {tag: "dynamic-assessment", label: "dynamic-assessment", run: func(*Runner, context.Context, *phaseInfra) error { return nil }},
	}
	if err := r.RunNativeScan(); err != nil {
		t.Fatal(err)
	}
	before := received.snapshot()
	if len(before) == 0 || before[len(before)-1].Type != scanevents.TypeScanFinished {
		t.Fatalf("missing terminal callback before Native return: %+v", before)
	}
	observer := sw.OnEvent
	if observer == nil {
		t.Fatal("test requires a retained finding observer")
	}
	releaseOnce.Do(func() { close(lateRelease) })
	if err := <-lateResult; err != nil {
		t.Fatal(err)
	}
	observer(&output.ResultEvent{ModuleID: "retained-observer"})
	r.SetEventCallback(nil) // frozen; closing must not remove the callback
	r.emitEvent(scanevents.Event{Type: scanevents.TypeError, Message: "late error"})
	r.finishCallbackScan(r.ctx, time.Now(), nil) // duplicate completion attempt
	if got := received.snapshot(); len(got) != len(before) {
		t.Fatalf("callback delivered events after Native returned: %+v", got[len(before):])
	}
	if priorCalls.Load() != 2 {
		t.Fatalf("late worker/observer did not actually run: %d calls", priorCalls.Load())
	}
	if buf.Len() != 0 || scanevents.Default() != global {
		t.Fatalf("late local events leaked to or replaced the CLI emitter: %s", buf.String())
	}
	assertCallbackEnvelope(t, before, r.options.ScanUUID)
}

func TestRunnerEventCallbackTerminalJoinsInFlightAndClosesDelivery(t *testing.T) {
	buf := withEventStream(t)
	global := scanevents.Default()
	sw := &output.StandardWriter{DisableStdout: true}
	r := &Runner{options: &types.Options{ScanUUID: "terminal-in-flight"}, ctx: context.Background(), output: sw}
	var received callbackEvents
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	terminalEntered, releaseTerminal := make(chan struct{}), make(chan struct{})
	var firstReturned atomic.Bool
	var terminalNotice sync.Once
	var firstReleaseOnce, terminalReleaseOnce sync.Once
	defer firstReleaseOnce.Do(func() { close(releaseFirst) })
	defer terminalReleaseOnce.Do(func() { close(releaseTerminal) })
	r.SetEventCallback(func(ev scanevents.Event) {
		received.record(ev)
		switch {
		case ev.Type == scanevents.TypeFindingNew && ev.ModuleID == "in-flight":
			close(firstEntered)
			<-releaseFirst
			firstReturned.Store(true)
		case ev.Type == scanevents.TypeScanFinished:
			if !firstReturned.Load() {
				t.Error("terminal callback overtook an in-flight finding callback")
			}
			terminalNotice.Do(func() { close(terminalEntered) })
			<-releaseTerminal
		}
	})
	r.freezeEventCallback()
	r.attachEventObserver()
	firstDone := make(chan struct{})
	go func() {
		sw.OnEvent(&output.ResultEvent{ModuleID: "in-flight"})
		close(firstDone)
	}()
	<-firstEntered
	// Structural assertion, not a sleep: an in-flight callback must own the
	// very mutex the terminal barrier uses to wait and close delivery.
	if r.eventEmitMu.TryLock() {
		r.eventEmitMu.Unlock()
		t.Error("in-flight callback does not hold the terminal barrier lock")
	}
	terminalAttempted, terminalDone := make(chan struct{}), make(chan struct{})
	go func() {
		close(terminalAttempted)
		r.finishCallbackScan(r.ctx, time.Now(), nil)
		close(terminalDone)
	}()
	<-terminalAttempted
	select {
	case <-terminalDone:
		t.Error("terminal delivery returned while the first callback was blocked")
	default:
	}
	firstReleaseOnce.Do(func() { close(releaseFirst) })
	<-firstDone
	<-terminalEntered // terminal user code now holds eventEmitMu, delivery closed
	if r.eventEmitMu.TryLock() {
		r.eventEmitMu.Unlock()
		t.Error("terminal callback does not hold the delivery barrier lock")
	}
	const contenders = 16
	attempts := make(chan struct{}, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempts <- struct{}{}
			sw.OnEvent(&output.ResultEvent{ModuleID: "late-contender"})
			r.finishCallbackScan(r.ctx, time.Now(), nil)
		}()
	}
	for range contenders {
		<-attempts
	}
	terminalReleaseOnce.Do(func() { close(releaseTerminal) })
	<-terminalDone
	wg.Wait()
	events := received.snapshot()
	if len(events) != 2 || events[0].Type != scanevents.TypeFindingNew || events[1].Type != scanevents.TypeScanFinished {
		t.Fatalf("terminal barrier did not close exactly once: %+v", events)
	}
	if buf.Len() != 0 || scanevents.Default() != global {
		t.Fatalf("terminal/late delivery touched the CLI emitter: %s", buf.String())
	}
	assertCallbackEnvelope(t, events, r.options.ScanUUID)
}

func TestRunnerEventCallbackPanicFailsClosedWithoutGlobalFallback(t *testing.T) {
	for _, kind := range []string{scanevents.TypeFindingNew, scanevents.TypeScanFinished} {
		t.Run(kind, func(t *testing.T) {
			buf := withEventStream(t)
			global := scanevents.Default()
			r := &Runner{options: &types.Options{ScanUUID: "callback-panic"}}
			var calls atomic.Int64
			r.SetEventCallback(func(scanevents.Event) {
				calls.Add(1)
				panic("callback contract violation")
			})
			r.freezeEventCallback()
			func() {
				defer func() {
					if got := recover(); got != "callback contract violation" {
						t.Errorf("callback panic was swallowed or changed: %v", got)
					}
				}()
				r.emitEvent(scanevents.Event{Type: kind})
			}()
			r.SetEventCallback(nil)
			r.emitFindingEvent(&output.ResultEvent{ModuleID: "late-after-panic"})
			r.emitEvent(scanevents.Event{Type: scanevents.TypeScanFinished})
			if calls.Load() != 1 || buf.Len() != 0 || scanevents.Default() != global {
				t.Fatalf("callback panic did not fail closed: calls=%d global=%s", calls.Load(), buf.String())
			}
		})
	}
}

func TestRunnerEventCallbackSkipsGlobalStderrCapture(t *testing.T) {
	withoutGlobalEvents(t)
	r := newCallbackScanRunner(t)
	dbCfg := r.settings.Database
	dbCfg.Driver = "sqlite"
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "callback.sqlite")
	db, err := database.NewDB(&dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.SetRepository(database.NewRepository(db))
	r.SetEventCallback(func(scanevents.Event) {})
	stderr := os.Stderr
	r.phaseRunners = map[NativePhase]phaseRunner{}
	for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
		r.phaseRunners[phase] = phaseRunner{tag: string(phase), label: string(phase), run: func(r *Runner, _ context.Context, _ *phaseInfra) error {
			if os.Stderr != stderr || r.teeWriter != nil || stderrCaptureActive.Load() {
				t.Error("callback scan claimed process-global stderr capture")
			}
			return nil
		}}
	}
	if err := r.RunNativeScan(); err != nil {
		t.Fatal(err)
	}
}
