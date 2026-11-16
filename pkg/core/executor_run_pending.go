package core

import (
	"context"
	"sync/atomic"
)

type executorRunPendingKey struct{}

// withRunPending counts admitted items from before enqueue until tracker
// completion. inFlight starts only after dequeue, so it cannot alone establish
// that the post-EOF drain is idle. Each Execute owns a fresh counter: cancelled
// queues and late task completions must never change a subsequent run's count.
func withRunPending(ctx context.Context) (context.Context, *atomic.Int64) {
	pending := &atomic.Int64{}
	return context.WithValue(ctx, executorRunPendingKey{}, pending), pending
}

func runPendingFromContext(ctx context.Context) *atomic.Int64 {
	pending, _ := ctx.Value(executorRunPendingKey{}).(*atomic.Int64)
	return pending
}

func (e *Executor) drainBusy(pending *atomic.Int64) bool {
	return pending.Load() != 0 || e.pool.inFlight.Load() != 0 || len(e.pool.feedbackCh) != 0
}
