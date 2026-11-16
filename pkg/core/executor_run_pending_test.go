package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

func TestExecutorDrainCountsQueuedAndDequeuedItems(t *testing.T) {
	for _, feedback := range []bool{false, true} {
		name := "source"
		if feedback {
			name = "feedback"
		}
		t.Run(name, func(t *testing.T) {
			e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
			e.scanCtx = &modules.ScanContext{}
			e.statsTracker = stats.New(1, false)
			e.pool.feedbackCh = make(chan *work.WorkItem, 1)
			ctx, pending := withRunPending(context.Background())
			items := make(chan *work.WorkItem, 1)
			var acks atomic.Int64
			_, rr := makeTestItem("example.invalid", "/baseline", "<html>fixture</html>")
			item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })
			if feedback {
				e.pool.feedbackCh <- item
				e.drainFeedback(ctx, items)
			} else if !e.sendItem(ctx, item, items) {
				t.Fatal("sendItem failed")
			}

			// No worker has started: this exact queued state previously looked
			// idle at EOF. Removing it from the channel must not open a gap.
			assertBusy := func(stage string) {
				t.Helper()
				if pending.Load() != 1 || !e.drainBusy(pending) || acks.Load() != 0 {
					t.Fatalf("%s: pending=%d busy=%t acks=%d", stage, pending.Load(), e.drainBusy(pending), acks.Load())
				}
			}
			if e.InFlight() != 0 || len(e.pool.feedbackCh) != 0 {
				t.Fatal("fixture must have no in-flight item or queued feedback")
			}
			assertBusy("queued before worker starts")
			dequeued := <-items
			assertBusy("dequeued before tracker creation")

			// Follow the worker's tracker path, retaining a detached task's
			// reference. Admission must survive the dispatcher's return.
			e.pool.itemSlots <- struct{}{}
			tracker := e.newItemTracker(ctx, dequeued, true)
			tracker.runPending = runPendingFromContext(ctx)
			tracker.acquire()
			e.dispatchItem(tracker)
			tracker.done()
			assertBusy("detached task retains item")
			if e.InFlight() != 1 || e.Processed() != 0 {
				t.Fatalf("early completion: inFlight=%d processed=%d", e.InFlight(), e.Processed())
			}
			tracker.done()
			if tracker.panicked.Load() {
				t.Fatal("fixture dispatch panicked")
			}
			if pending.Load() != 0 || e.drainBusy(pending) || e.InFlight() != 0 || len(e.pool.itemSlots) != 0 {
				t.Fatalf("completed: pending=%d busy=%t inFlight=%d slots=%d", pending.Load(), e.drainBusy(pending), e.InFlight(), len(e.pool.itemSlots))
			}
			if acks.Load() != 1 || e.Processed() != 1 || e.Responded() != 1 {
				t.Fatalf("completion: acks=%d processed=%d responded=%d", acks.Load(), e.Processed(), e.Responded())
			}
		})
	}
}

func TestExecutorRunPendingRealWorker(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	e.scanCtx = &modules.ScanContext{}
	e.statsTracker = stats.New(1, false)
	ctx, pending := withRunPending(context.Background())
	items := make(chan *work.WorkItem, 1)
	var acks atomic.Int64
	_, rr := makeTestItem("example.invalid", "/baseline", "<html>fixture</html>")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })
	if !e.sendItem(ctx, item, items) {
		t.Fatal("sendItem failed")
	}
	close(items)
	// Exercise production attachment and release without a scheduling race.
	e.worker(ctx, 0, items, nil)
	if pending.Load() != 0 || e.drainBusy(pending) || e.InFlight() != 0 || len(e.pool.itemSlots) != 0 {
		t.Fatalf("worker completion: pending=%d busy=%t inFlight=%d slots=%d", pending.Load(), e.drainBusy(pending), e.InFlight(), len(e.pool.itemSlots))
	}
	if acks.Load() != 1 || e.Processed() != 1 || e.Responded() != 1 {
		t.Fatalf("worker completion: acks=%d processed=%d responded=%d", acks.Load(), e.Processed(), e.Responded())
	}
}

func TestExecutorRunPendingStatusContext(t *testing.T) {
	statusSeen := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e, _ := newTestExecutor(ExecutorConfig{
		Workers: 1,
		OnStatus: func(int64, int64, int64, int64, int64, int64, int64, time.Duration) {
			select {
			case statusSeen <- struct{}{}:
			default:
			}
		},
		StatusInterval: time.Millisecond,
		OnResponse: func(*work.WorkItem, *httpmsg.HttpRequestResponse) {
			select {
			case <-statusSeen:
			case <-ctx.Done():
				t.Error("status callback did not run")
			}
		},
	}, nil)
	e.scanCtx = &modules.ScanContext{}
	item, _ := makeTestItem("example.invalid", "/baseline", "<html>fixture</html>")
	e.source = &sliceSource{items: []*work.WorkItem{item}}
	e.statsTracker = stats.New(1, false)
	e.moduleMetrics = &stats.ModuleMetrics{}
	if _, err := e.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.Report().Clean() || e.Responded() != 1 || e.Processed() != 1 {
		t.Fatalf("status-enabled run: report=%+v processed=%d", e.Report(), e.Processed())
	}
}

func TestExecutorRunPendingCancelledSendAndRunIsolation(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1}, nil)
	base, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, pending := withRunPending(base)
	var acks atomic.Int64
	_, rr := makeTestItem("example.invalid", "/baseline", "fixture")
	item := work.NewWithCallback(rr, nil, func() { acks.Add(1) })
	// No receiver on an unbuffered channel: cancellation is the only ready arm.
	if e.sendItem(ctx, item, make(chan *work.WorkItem)) || pending.Load() != 0 || acks.Load() != 0 {
		t.Fatalf("cancelled admission: pending=%d acks=%d", pending.Load(), acks.Load())
	}

	oldCtx, oldPending := withRunPending(context.Background())
	items := make(chan *work.WorkItem, 1)
	if !e.sendItem(oldCtx, item, items) {
		t.Fatal("old run admission failed")
	}
	tracker := e.newItemTracker(oldCtx, <-items, false)
	tracker.runPending = runPendingFromContext(oldCtx)
	_, newPending := withRunPending(context.Background())
	newPending.Add(1)
	tracker.done()
	if oldPending.Load() != 0 || newPending.Load() != 1 || acks.Load() != 1 {
		t.Fatalf("late old completion changed new run: old=%d new=%d acks=%d", oldPending.Load(), newPending.Load(), acks.Load())
	}
}
