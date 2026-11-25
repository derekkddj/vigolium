package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/goleak"
)

type declaredSourceError struct {
	fatal bool
}

func (e *declaredSourceError) Error() string          { return "stored exchange exceeds memory admission limit" }
func (e *declaredSourceError) FatalSourceError() bool { return e.fatal }

type terminalTestSource struct {
	initial *work.WorkItem
	err     error
	calls   atomic.Int64
	failed  chan struct{}
}

func (s *terminalTestSource) Next(context.Context) (*work.WorkItem, error) {
	n := s.calls.Add(1)
	if n == 1 && s.initial != nil {
		return s.initial, nil
	}
	if s.failed != nil {
		close(s.failed)
		s.failed = nil
	}
	return nil, s.err
}
func (*terminalTestSource) Close() error { return nil }

func TestFatalSourceErrorStopsPullsAndRemainsPartial(t *testing.T) {
	for _, disableFeedback := range []bool{true, false} {
		t.Run(fmt.Sprintf("disableFeedback=%v", disableFeedback), func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			cause := &declaredSourceError{fatal: true}
			wrapped := fmt.Errorf("hydrate page: %w", cause)
			src := &terminalTestSource{err: wrapped}
			e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true, DisableFeedback: disableFeedback}, src, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			found, err := e.Execute(ctx)
			require.Same(t, wrapped, err, "preserve the exact error, not just its message")
			require.ErrorIs(t, err, cause)
			require.False(t, found)
			require.Equal(t, int64(1), src.calls.Load(), "never retry the unread oversized record")
			require.True(t, e.Report().StoppedEarly)
			require.False(t, e.Report().Clean())
			require.Zero(t, e.Processed(), "a failed pull is not completed work")
			require.NoError(t, ctx.Err(), "failure must not need the caller deadline")
		})
	}
}

func TestFatalSourceErrorDrainsAcceptedWorkWithoutCancellingACK(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	cause := &declaredSourceError{fatal: true}
	_, rr := makeTestItem("hol.example.test", "/probe", "<html>ready</html>")
	var acked atomic.Int64
	src := &terminalTestSource{
		initial: work.NewWithCallback(rr, nil, func() { acked.Add(1) }),
		err:     cause,
		failed:  make(chan struct{}),
	}
	failed := src.failed
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var moduleCtxErr error
	mod := newHookedModule(func(ctx context.Context, _ *httpmsg.HttpRequestResponse, _ *modules.ScanContext) {
		close(started)
		<-release
		moduleCtxErr = ctx.Err()
	})
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, src, []modules.ActiveModule{mod}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.Execute(ctx); done <- err }()
	select {
	case <-failed:
	case <-ctx.Done():
		t.Fatal("source error was not observed")
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("accepted work was not dispatched")
	}
	require.Zero(t, acked.Load(), "accepted work cannot ACK before its module finishes")
	select {
	case err := <-done:
		t.Fatalf("returned before draining accepted work: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-done:
		require.Same(t, cause, err)
	case <-ctx.Done():
		t.Fatal("did not finish after accepted work exited")
	}
	require.NoError(t, moduleCtxErr, "fatal pull must not cancel valid accepted work")
	require.Equal(t, int64(1), acked.Load())
	require.Equal(t, int64(1), e.Processed())
	require.Equal(t, int64(2), src.calls.Load())
	require.True(t, e.Report().StoppedEarly)
	require.False(t, e.Report().DrainStalled)
	require.False(t, e.Report().WorkersAbandoned)
	require.False(t, e.Report().DeferredFlushSkipped)
}

type advancingErrorSource struct {
	err   error
	item  *work.WorkItem
	calls atomic.Int64
}

func (s *advancingErrorSource) Next(context.Context) (*work.WorkItem, error) {
	switch s.calls.Add(1) {
	case 1:
		return nil, s.err
	case 2:
		return s.item, nil
	default:
		return nil, io.EOF
	}
}
func (*advancingErrorSource) Close() error { return nil }

func TestNonFatalSourceErrorStillReadsNextItem(t *testing.T) {
	for _, err := range []error{errors.New("malformed target already advanced"), &declaredSourceError{fatal: false}} {
		t.Run(err.Error(), func(t *testing.T) {
			defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
			_, rr := makeTestItem("hol.example.test", "/probe", "<html>ready</html>")
			src := &advancingErrorSource{err: err, item: work.NewWithModules(rr, nil)}
			e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, src, nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, gotErr := e.Execute(ctx)
			require.NoError(t, gotErr)
			require.Equal(t, int64(3), src.calls.Load())
			require.Equal(t, int64(1), e.Processed())
			require.True(t, e.Report().Clean())
		})
	}
}
