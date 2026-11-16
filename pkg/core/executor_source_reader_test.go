package core

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/goleak"
)

type contextReaderSource struct {
	calls   atomic.Int64
	ackErr  error
	entered chan struct{}
	block   bool
	panic   bool
}

func (s *contextReaderSource) Next(ctx context.Context) (*work.WorkItem, error) {
	n := s.calls.Add(1)
	if s.panic {
		panic("source panic")
	}
	if s.block {
		close(s.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if n > 1 {
		return nil, io.EOF
	}
	return work.NewWithCallback(nil, nil, func() { s.ackErr = ctx.Err() }), nil
}

func (*contextReaderSource) Close() error { return nil }

func TestSourceReaderDoesNotPrefetchOrCancelACKContext(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	src := &contextReaderSource{}
	e := NewExecutor(ExecutorConfig{Workers: 1}, src, nil, nil)
	pull, stop := e.sourceReader(context.Background(), make(chan *work.WorkItem))
	require.Zero(t, src.calls.Load())
	item, err := pull()
	require.NoError(t, err)
	require.Equal(t, int64(1), src.calls.Load())
	_, err = pull()
	require.ErrorIs(t, err, io.EOF)
	stop()
	require.Equal(t, int64(2), src.calls.Load())
	item.Complete()
	require.NoError(t, src.ackErr, "clean source EOF must not cancel a pending item's captured context")
}

func TestSourceReaderCancellationJoinsBlockedNext(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	src := &contextReaderSource{block: true, entered: make(chan struct{})}
	e := NewExecutor(ExecutorConfig{Workers: 1}, src, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pull, stop := e.sourceReader(ctx, make(chan *work.WorkItem))
	done := make(chan error, 1)
	go func() { _, err := pull(); done <- err }()
	select {
	case <-src.entered:
	case <-time.After(time.Second):
		t.Fatal("reader did not call Next")
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	stop()
	require.Equal(t, int64(1), src.calls.Load())
}

func TestSourceReaderPropagatesPanicOnPullCaller(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	e := NewExecutor(ExecutorConfig{Workers: 1}, &contextReaderSource{panic: true}, nil, nil)
	pull, stop := e.sourceReader(context.Background(), make(chan *work.WorkItem))
	defer stop()
	require.PanicsWithValue(t, "source panic", func() { _, _ = pull() })
}
