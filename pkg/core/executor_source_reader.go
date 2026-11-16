package core

import (
	"context"

	"github.com/vigolium/vigolium/pkg/work"
)

type sourceReadResult struct {
	item  *work.WorkItem
	err   error
	panic any
}

// sourceReader keeps one outstanding pull while the feeder delivers feedback.
// Next may wait for an ACK from a module that itself produces feedback. Calling
// Next synchronously would starve those discoveries until that module returns.
// A demand handshake prevents prefetching another item or retaining a raw corpus;
// there is only one reader goroutine per feed, never one goroutine per record.
func (e *Executor) sourceReader(ctx context.Context, itemCh chan<- *work.WorkItem) (pull func() (*work.WorkItem, error), stop func()) {
	demand := make(chan struct{})
	results := make(chan sourceReadResult)
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-demand:
			}
			result := func() (result sourceReadResult) {
				// Preserve source panic propagation on the Execute caller rather
				// than turning a recoverable caller panic into a detached panic.
				defer func() { result.panic = recover() }()
				// Use the original context. EOF must not cancel contexts captured
				// by a WorkItem's ACK while workers are still draining that item.
				result.item, result.err = e.source.Next(ctx)
				return result
			}()
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case results <- result:
			}
			if result.panic != nil {
				return
			}
		}
	}()
	pull = func() (*work.WorkItem, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case demand <- struct{}{}:
		}
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case feedback := <-e.pool.feedbackCh:
				if !e.sendItem(ctx, feedback, itemCh) {
					return nil, ctx.Err()
				}
			case result := <-results:
				if result.panic != nil {
					panic(result.panic)
				}
				return result.item, result.err
			}
		}
	}
	stop = func() {
		close(stopCh)
		// InputSource.Next observes the executor context on cancellation;
		// at clean EOF it has already delivered its result. Join the reader.
		<-done
	}
	return pull, stop
}
