package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// A watchdog timeout does not stop the underlying module. A second Execute on
// the same executor must not reset that run's report, add to its WaitGroups, or
// reuse its mutable module state, even if the abandoned call exits later.
func TestRealWorkAbandonedExecutorCannotBeReused(t *testing.T) {
	realWorkCheckLeaks(t)
	blocked, release := realWorkRelease(t)
	mod := &realWorkFlushPassive{
		hintedPassive: hintedPassive{trackingPassiveModule: &trackingPassiveModule{id: "reuse-flusher"}, hint: 20 * time.Millisecond},
		entered:       make(chan struct{}), release: blocked, flushed: make(chan struct{}),
	}
	var acks atomic.Int64
	e := NewExecutor(ExecutorConfig{
		Workers: 1, SkipBaseline: true,
		FeedbackDrainMaxStall: time.Second, WorkerExitGrace: 20 * time.Millisecond,
	}, &sliceSource{items: []*work.WorkItem{ackedItem("/reuse-abandoned", &acks)}}, nil, []modules.PassiveModule{mod})
	ctx, cancel := context.WithCancel(context.Background())
	done := runExecute(t, e, ctx)
	t.Cleanup(func() {
		cancel()
		release()
		waitClosed(t, done, "first Execute cleanup")
		realWorkWaitGroup(t, &e.pool.taskWG, "task cleanup")
		realWorkWaitGroup(t, &e.pool.realTaskWG, "real-work cleanup")
	})
	waitClosed(t, mod.entered, "first actual module call")
	cancel()
	waitClosed(t, done, "first bounded shutdown")
	if !e.Report().WorkersAbandoned {
		t.Fatal("setup: first run did not abandon the actual call")
	}

	src := &terminalTestSource{err: &declaredSourceError{fatal: true}}
	e.source = src
	for _, lateExit := range []bool{false, true} {
		if lateExit {
			release()
			realWorkWaitGroup(t, &e.pool.realTaskWG, "late actual exit")
		}
		attemptCtx, attemptCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, err := e.Execute(attemptCtx)
		attemptCancel()
		if err == nil {
			t.Errorf("lateExit=%t: abandoned executor admitted another Execute", lateExit)
		}
		if src.calls.Load() != 0 {
			t.Errorf("lateExit=%t: rejected reuse pulled %d inputs", lateExit, src.calls.Load())
		}
		if rep := e.Report(); !rep.WorkersAbandoned || !rep.DeferredFlushSkipped || rep.Clean() {
			t.Errorf("lateExit=%t: reuse erased abandonment evidence: %+v", lateExit, rep)
		}
	}
	if acks.Load() != 0 {
		t.Fatal("an abandoned cancelled item was falsely acknowledged")
	}
}
