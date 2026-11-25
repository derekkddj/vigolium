package core

import (
	"context"
	"sync"
)

// itemTrackerContextKey connects watchdog calls to the item whose data they may
// retain. It is distinct from the response-buffer guard: preventing buffer reuse
// alone does not keep outstanding-item backpressure or acknowledgement intact.
type itemTrackerContextKey struct{}

// withItemTracker attaches the tracker before its response-buffer guard is added.
// Child module contexts inherit both values. Callers must still own a tracker
// reference while starting work under this context.
func withItemTracker(ctx context.Context, t *itemTracker) context.Context {
	return context.WithValue(ctx, itemTrackerContextKey{}, t)
}

// acquireRealWork retains the item before a watchdog goroutine can escape its
// wrapper. The returned release belongs to the actual scan call, not the timeout
// select, and must run only when that call exits. A wrapper/task reference keeps
// normal result processing alive independently of this real-work reference.
// Direct wrapper callers without a tracker retain their existing behavior.
func acquireRealWork(ctx context.Context) func() {
	t, _ := ctx.Value(itemTrackerContextKey{}).(*itemTracker)
	if t == nil {
		return func() {}
	}
	t.acquire()
	var once sync.Once
	return func() { once.Do(t.done) }
}
