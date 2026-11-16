package core

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/goleak"
)

// All blocked scans have a controlled release, including failure cleanup. These
// tests intentionally do not leave genuinely wedged goroutines in the process.
func realWorkRelease(t *testing.T) (chan struct{}, func()) {
	t.Helper()
	ch := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return ch, release
}

func realWorkCheckLeaks(t *testing.T) {
	t.Helper()
	// Capture existing goroutines before starting test work, not in cleanup.
	ignoreExisting := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, ignoreExisting) })
}

func realWorkWaitGroup(t *testing.T, wg *sync.WaitGroup, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	waitClosed(t, done, what)
}

func TestRealWorkLeaseRetainsTrackerAndReleasesExactlyOnce(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	var acks atomic.Int64
	tr := e.newItemTracker(context.Background(), ackedItem("/lease", &acks), false)
	ctx := withItemTracker(tr.ctx, tr)
	release := acquireRealWork(ctx)
	if tr.pending.Load() != 2 {
		t.Fatalf("pending = %d, want dispatcher + real work", tr.pending.Load())
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); release() }()
	}
	wg.Wait()
	if tr.pending.Load() != 1 || acks.Load() != 0 {
		t.Fatalf("release dropped dispatcher: pending=%d acks=%d", tr.pending.Load(), acks.Load())
	}
	tr.done()
	waitClosed(t, tr.finished, "tracker completion")
	if acks.Load() != 1 {
		t.Fatalf("acks = %d, want 1", acks.Load())
	}
	// Preserve direct wrapper callers and tolerate an explicitly nil tracker.
	acquireRealWork(context.Background())()
	acquireRealWork(withItemTracker(context.Background(), nil))()
}

func TestRealWorkPassiveTimeoutStormCapsActualCalls(t *testing.T) {
	realWorkCheckLeaks(t)
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	const limit = 2
	e.pool.realPassiveSem = make(chan struct{}, limit)
	mod := hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "real-storm"}, hint: 15 * time.Millisecond}
	_, item := makeTestItem("example.invalid", "/storm", "retained body")
	blocked, release := realWorkRelease(t)
	ctx, cancel := context.WithCancel(context.Background())
	var wrappers sync.WaitGroup
	// Registered after realWorkRelease so even a failing assertion cancels
	// semaphore waiters, releases actual scans, and joins before leak checking.
	t.Cleanup(func() {
		cancel()
		release()
		realWorkWaitGroup(t, &wrappers, "storm wrappers to exit")
		realWorkWaitGroup(t, &e.pool.realTaskWG, "storm real scans to exit")
	})
	var live, peak, calls atomic.Int32
	started := make(chan struct{}, 16)
	scan := func(context.Context) ([]*output.ResultEvent, error) {
		calls.Add(1)
		n := live.Add(1)
		defer live.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-blocked // deliberately ignore watchdog/parent cancellation
		return []*output.ResultEvent{{URL: item.Target()}}, nil
	}
	// First fill the real-work budget; both wrappers time out while their real
	// scans remain blocked. A wrapper-only cap would allow replacement scans.
	for i := 0; i < limit; i++ {
		if got := e.runPassiveWithTimeout(ctx, scan, mod, item); got != nil {
			t.Fatal("timed-out scan returned findings")
		}
		// Even if a heavily loaded scheduler let the watchdog fire before its
		// goroutine ran, establish actual entry before asserting concurrency.
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("initial storm scan never entered")
		}
	}
	if calls.Load() != limit || live.Load() != limit {
		t.Fatalf("initial calls=%d live=%d, want %d", calls.Load(), live.Load(), limit)
	}
	var acks atomic.Int64
	tr := e.newItemTracker(ctx, ackedItem("/waiting", &acks), false)
	waitingCtx := withItemTracker(tr.ctx, tr)
	attempted := make(chan struct{}, 12)
	for i := 0; i < cap(attempted); i++ {
		wrappers.Add(1)
		go func() {
			defer wrappers.Done()
			attempted <- struct{}{}
			e.runPassiveWithTimeout(waitingCtx, scan, mod, item)
		}()
	}
	for i := 0; i < cap(attempted); i++ {
		<-attempted
	}
	// Also cover the inline cross-path bypass: no hint and no context support.
	wrappers.Add(1)
	go func() {
		defer wrappers.Done()
		e.runPassiveWithTimeout(waitingCtx, scan, &trackingPassiveModule{id: "real-inline-waiter"}, item)
	}()
	select {
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal("storm context unexpectedly cancelled")
	}
	if calls.Load() != limit || peak.Load() != limit || tr.pending.Load() != 1 {
		t.Errorf("replacement work escaped cap: calls=%d peak=%d waiting refs=%d", calls.Load(), peak.Load(), tr.pending.Load())
	}
	cancel()
	realWorkWaitGroup(t, &wrappers, "cancelled semaphore waiters")
	if tr.pending.Load() != 1 || acks.Load() != 0 {
		t.Fatalf("cancelled waiters acquired/leaked an item lease: pending=%d acks=%d", tr.pending.Load(), acks.Load())
	}
	tr.done()
	release()
	realWorkWaitGroup(t, &e.pool.realTaskWG, "abandoned storm scans")
	if live.Load() != 0 || len(e.pool.realPassiveSem) != 0 || calls.Load() != limit {
		t.Fatalf("storm cleanup: live=%d slots=%d calls=%d", live.Load(), len(e.pool.realPassiveSem), calls.Load())
	}
}

func TestRealWorkWatchdogsRetainItemUntilActualExit(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, cancelled := range []bool{false, true} {
			name := "passive/timeout"
			if active {
				name = "active/timeout"
			}
			if cancelled {
				name += "/parent-cancel"
			}
			t.Run(name, func(t *testing.T) {
				realWorkCheckLeaks(t)
				e, _ := newTestExecutor(ExecutorConfig{ActiveModuleTimeout: 20 * time.Millisecond}, nil)
				e.statsTracker = stats.New(1, false)
				e.pool.itemSlots = make(chan struct{}, 1)
				e.pool.itemSlots <- struct{}{}
				e.pool.realPassiveSem = make(chan struct{}, 1)
				activeTaskSem := make(chan struct{}, 1)
				if active {
					activeTaskSem <- struct{}{}
				}
				ctx, cancel := context.WithCancel(context.Background())
				var acks, slotReleases atomic.Int64
				item := ackedItem("/real-lifetime", &acks)
				tr := e.newItemTracker(ctx, item, true)
				var admitted atomic.Int64
				admitted.Store(1)
				tr.runPending = &admitted
				// Drive wrappers directly, explicitly testing the helper contract.
				// Execute tests below exercise the parent's production attachment.
				callCtx := withResponseBufferGuard(withItemTracker(ctx, tr), &tr.guard)
				blocked, release := realWorkRelease(t)
				entered, wrapperDone := make(chan struct{}), make(chan struct{})
				var dispatcherDone sync.Once
				dropDispatcher := func() { dispatcherDone.Do(tr.done) }
				t.Cleanup(func() {
					cancel()
					release()
					waitClosed(t, wrapperDone, "lifetime wrapper cleanup")
					dropDispatcher()
					realWorkWaitGroup(t, &e.pool.realTaskWG, "lifetime real-work cleanup")
				})
				go func() {
					defer close(wrapperDone)
					scan := func(context.Context) ([]*output.ResultEvent, error) {
						close(entered)
						<-blocked
						return []*output.ResultEvent{{}}, nil
					}
					if active {
						o := e.runActiveWithTimeout(callCtx,
							func(c context.Context, _ *http.Requester) ([]*output.ResultEvent, error) { return scan(c) },
							&activeStub{id: "real-active", canProc: true}, item.Request, nil,
							func() { slotReleases.Add(1); <-activeTaskSem }, 0)
						if o.completed || o.events != nil {
							t.Error("abandoned active call returned results/completed")
						}
					} else {
						mod := hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "real-passive"}, hint: 20 * time.Millisecond}
						if got := e.runPassiveWithTimeout(callCtx, scan, mod, item.Request); got != nil {
							t.Error("abandoned passive call returned results")
						}
					}
				}()
				waitClosed(t, entered, "real scan to enter")
				if cancelled {
					cancel()
				}
				waitClosed(t, wrapperDone, "watchdog to abandon real scan")
				dropDispatcher()
				select {
				case <-tr.finished:
					t.Fatal("item completed before the real scan exited")
				default:
				}
				if acks.Load() != 0 || e.Processed() != 0 || e.InFlight() != 1 || admitted.Load() != 1 || len(e.pool.itemSlots) != 1 {
					t.Fatalf("early item retirement: acks=%d processed=%d inFlight=%d admitted=%d slots=%d", acks.Load(), e.Processed(), e.InFlight(), admitted.Load(), len(e.pool.itemSlots))
				}
				if active && (slotReleases.Load() != 0 || len(activeTaskSem) != 1) {
					t.Fatal("active slot released before actual exit")
				}
				if !active && len(e.pool.realPassiveSem) != 1 {
					t.Fatal("real passive slot released before actual exit")
				}
				release()
				realWorkWaitGroup(t, &e.pool.realTaskWG, "actual scan exit and tracker cleanup")
				waitClosed(t, tr.finished, "real-work item completion")
				wantACK := int64(1)
				if cancelled {
					wantACK = 0
				}
				if acks.Load() != wantACK || e.Processed() != 1 || e.InFlight() != 0 || admitted.Load() != 0 || len(e.pool.itemSlots) != 0 {
					t.Fatalf("actual completion: acks=%d processed=%d inFlight=%d admitted=%d slots=%d", acks.Load(), e.Processed(), e.InFlight(), admitted.Load(), len(e.pool.itemSlots))
				}
				if len(e.pool.realPassiveSem) != 0 || len(activeTaskSem) != 0 || (active && slotReleases.Load() != 1) {
					t.Fatal("actual exit did not release concurrency slots exactly once")
				}
			})
		}
	}
}

func TestRealWorkBufferedCompletionDoesNotJoinExitDefers(t *testing.T) {
	realWorkCheckLeaks(t)
	e, _ := newTestExecutor(ExecutorConfig{ActiveModuleTimeout: time.Second}, nil)
	var acks, releases atomic.Int64
	item := ackedItem("/buffered-completion", &acks)
	tr := e.newItemTracker(context.Background(), item, false)
	ctx := withItemTracker(tr.ctx, tr)
	blockedExit, release := realWorkRelease(t)
	exitEntered := make(chan struct{})
	t.Cleanup(func() {
		release()
		realWorkWaitGroup(t, &e.pool.realTaskWG, "buffered-completion cleanup")
	})
	want := []*output.ResultEvent{{URL: item.Request.Target()}}
	o := e.runActiveWithTimeout(ctx,
		func(context.Context, *http.Requester) ([]*output.ResultEvent, error) { return want, nil },
		&activeStub{id: "real-buffered", canProc: true}, item.Request, nil,
		func() { close(exitEntered); <-blockedExit; releases.Add(1) }, 0)
	waitClosed(t, exitEntered, "scan goroutine's blocked exit defer")
	tr.done()
	got, completed := o.events, o.completed
	if !completed || len(got) != 1 || got[0] != want[0] {
		t.Fatal("normal buffered completion lost findings")
	}
	if acks.Load() != 0 || tr.pending.Load() != 1 || releases.Load() != 0 {
		t.Fatal("receiving the result retired real work before its exit defers")
	}
	joined := make(chan struct{})
	go func() { defer close(joined); e.pool.realTaskWG.Wait() }()
	select {
	case <-joined:
		t.Fatal("realTaskWG completed while an exit defer was still blocked")
	case <-time.After(20 * time.Millisecond):
	}
	// The drained channel may safely be reused while the first sender's exit
	// defers still run. It is never pooled from an abandoned select arm.
	mod := hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "real-reuse"}, hint: time.Second}
	if next := e.runPassiveWithTimeout(context.Background(),
		func(context.Context) ([]*output.ResultEvent, error) { return want, nil }, mod, item.Request); len(next) != 1 || next[0] != want[0] {
		t.Fatal("subsequent completion received stale/missing pooled-channel results")
	}
	release()
	waitClosed(t, joined, "all real-work exit defers")
	if acks.Load() != 1 || releases.Load() != 1 || e.InFlight() != 0 {
		t.Fatalf("exit cleanup: acks=%d releases=%d inFlight=%d", acks.Load(), releases.Load(), e.InFlight())
	}
}

func TestRealWorkNormalResultsErrorsAndPanicsReleaseLeases(t *testing.T) {
	for _, mode := range []string{"inline", "passive-watchdog", "active-watchdog"} {
		for _, outcome := range []string{"results", "error", "panic"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				e, _ := newTestExecutor(ExecutorConfig{ActiveModuleTimeout: time.Second}, nil)
				e.pool.realPassiveSem = make(chan struct{}, 1)
				var acks, releases atomic.Int64
				item := ackedItem("/normal-real-work", &acks)
				tr := e.newItemTracker(context.Background(), item, false)
				ctx := withItemTracker(tr.ctx, tr)
				want := []*output.ResultEvent{{URL: item.Request.Target()}}
				scan := func(context.Context) ([]*output.ResultEvent, error) {
					switch outcome {
					case "panic":
						panic("controlled real-work panic")
					case "error":
						return want, errors.New("controlled real-work error")
					default:
						return want, nil
					}
				}
				var got []*output.ResultEvent
				if mode == "active-watchdog" {
					o := e.runActiveWithTimeout(ctx,
						func(c context.Context, _ *http.Requester) ([]*output.ResultEvent, error) { return scan(c) },
						&activeStub{id: "real-normal", canProc: true}, item.Request, nil, func() { releases.Add(1) }, 0)
					got = o.events
					if !o.completed {
						t.Fatal("normal results/error/panic was reported as a watchdog timeout")
					}
				} else {
					var mod modules.PassiveModule = &trackingPassiveModule{id: "real-normal"}
					if mode == "passive-watchdog" {
						mod = hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "real-normal"}, hint: time.Second}
					}
					got = e.runPassiveWithTimeout(ctx, scan, mod, item.Request)
				}
				tr.done()
				realWorkWaitGroup(t, &e.pool.realTaskWG, "normal real-work cleanup")
				waitClosed(t, tr.finished, "normal tracker cleanup")
				if outcome == "results" {
					if len(got) != 1 || got[0] != want[0] {
						t.Fatal("normal module findings changed")
					}
				} else if mode == "active-watchdog" && outcome == "error" {
					// An active call keeps what it confirmed before failing.
					if len(got) != 1 || got[0] != want[0] || e.ModuleErrors()["real-normal"] != 1 {
						t.Fatalf("active error semantics changed: results=%d errors=%v", len(got), e.ModuleErrors())
					}
				} else if got != nil || e.ModuleErrors()["real-normal"] != 1 {
					t.Fatalf("error/panic semantics changed: results=%d errors=%v", len(got), e.ModuleErrors())
				}
				if acks.Load() != 1 || e.InFlight() != 0 || tr.pending.Load() != 0 || len(e.pool.realPassiveSem) != 0 || (mode == "active-watchdog" && releases.Load() != 1) {
					t.Fatal("normal/error/panic path leaked or double-released a lifecycle lease")
				}
			})
		}
	}
}

// realWorkFlushPassive exercises production dispatch and deferred flush without
// duplicating module boilerplate. The timeout hint forces the watchdog path.
type realWorkFlushPassive struct {
	hintedPassive
	entered, release chan struct{}
	flushed          chan struct{}
	scanReturned     atomic.Bool
	flushRaced       atomic.Bool
}

func (m *realWorkFlushPassive) ScanPerRequest(item *httpmsg.HttpRequestResponse, _ *modules.ScanContext) ([]*output.ResultEvent, error) {
	close(m.entered)
	<-m.release
	_ = item.Response().Body() // touch retained data after watchdog abandonment
	m.scanReturned.Store(true)
	return nil, nil
}

func (m *realWorkFlushPassive) Flush(*modules.ScanContext) {
	m.flushRaced.Store(!m.scanReturned.Load())
	close(m.flushed)
}

func TestRealWorkExecuteFlushAndBoundedShutdown(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		name := "release-before-shutdown"
		if abandon {
			name = "bounded-abandonment"
		}
		t.Run(name, func(t *testing.T) {
			realWorkCheckLeaks(t)
			blocked, release := realWorkRelease(t)
			mod := &realWorkFlushPassive{
				hintedPassive: hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "real-flusher"}, hint: 20 * time.Millisecond},
				entered:       make(chan struct{}), release: blocked, flushed: make(chan struct{}),
			}
			var acks atomic.Int64
			timeoutNoted := make(chan struct{})
			var timeoutOnce sync.Once
			e := NewExecutor(ExecutorConfig{
				Workers: 1, SkipBaseline: true,
				FeedbackDrainMaxStall: 2 * time.Second,
				WorkerExitGrace:       100 * time.Millisecond,
				OnModuleError: func(_ string, kind string) int64 {
					if kind == ModuleErrorTimeout {
						timeoutOnce.Do(func() { close(timeoutNoted) })
					}
					return 1
				},
			}, &sliceSource{items: []*work.WorkItem{ackedItem("/flush-real-work", &acks)}}, nil, []modules.PassiveModule{mod})
			ctx, cancel := context.WithCancel(context.Background())
			done := runExecute(t, e, ctx)
			t.Cleanup(func() {
				cancel()
				release()
				waitClosed(t, done, "Execute cleanup")
				realWorkWaitGroup(t, &e.pool.taskWG, "Execute task cleanup")
				realWorkWaitGroup(t, &e.pool.realTaskWG, "Execute real-work cleanup")
			})
			waitClosed(t, mod.entered, "production passive scan")
			waitClosed(t, timeoutNoted, "production passive watchdog timeout")
			if abandon {
				cancel()
				waitClosed(t, done, "bounded shutdown with stuck real scan")
				rep := e.Report()
				if rep.Clean() || !rep.WorkersAbandoned || !rep.DeferredFlushSkipped {
					t.Fatalf("stuck real scan reported clean/flushable: %+v", rep)
				}
			} else {
				select {
				case <-mod.flushed:
					t.Fatal("passive flush ran while abandoned scan still held its body")
				case <-done:
					t.Fatal("Execute returned before real scan exit")
				case <-time.After(50 * time.Millisecond):
				}
			}
			if acks.Load() != 0 || e.Processed() != 0 || e.InFlight() != 1 {
				t.Fatalf("production item retired early: acks=%d processed=%d inFlight=%d", acks.Load(), e.Processed(), e.InFlight())
			}
			select {
			case <-mod.flushed:
				t.Fatal("flush was not withheld/skipped for real work")
			default:
			}
			release()
			waitClosed(t, done, "Execute after controlled scan release")
			realWorkWaitGroup(t, &e.pool.realTaskWG, "late real scan cleanup")
			if abandon {
				if acks.Load() != 0 || e.InFlight() != 0 {
					t.Fatal("late cancelled scan advanced ACK or retained item")
				}
				select {
				case <-mod.flushed:
					t.Fatal("skipped flush ran later after Execute returned")
				default:
				}
			} else {
				waitClosed(t, mod.flushed, "safe passive flush")
				if mod.flushRaced.Load() || !e.Report().Clean() || acks.Load() != 1 || e.Processed() != 1 || e.InFlight() != 0 {
					t.Fatalf("healthy real-work join/flush failed: race=%t report=%+v acks=%d processed=%d inFlight=%d", mod.flushRaced.Load(), e.Report(), acks.Load(), e.Processed(), e.InFlight())
				}
			}
		})
	}
}
