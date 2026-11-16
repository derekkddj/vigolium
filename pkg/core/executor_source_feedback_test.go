package core

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/goleak"
)

// A receive handoff cannot read its underlying cursor until the adopted input
// is acknowledged. This is a genuine blocking Next, not early source EOF.
type ackBarrierSource struct {
	mu      sync.Mutex
	initial *work.WorkItem
	waiting chan struct{}
	acked   chan struct{}
	once    sync.Once
}

func (s *ackBarrierSource) Next(ctx context.Context) (*work.WorkItem, error) {
	s.mu.Lock()
	if s.initial != nil {
		item := s.initial
		s.initial = nil
		s.mu.Unlock()
		return item, nil
	}
	s.mu.Unlock()
	s.once.Do(func() { close(s.waiting) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.acked:
		return nil, io.EOF
	}
}

func (s *ackBarrierSource) Close() error { return nil }

func TestFeedbackDrainsWhileSourceWaitsForACK(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	const endpoints = 48 // exceeds Workers*16 without changing queue capacity
	src := &ackBarrierSource{waiting: make(chan struct{}), acked: make(chan struct{})}
	_, seed := makeTestItem("hol.example.test", "/spec", "<html>spec</html>")
	src.initial = work.NewWithCallback(seed, nil, func() { close(src.acked) })
	var seen, refused atomic.Int64
	mod := newHookedModule(func(ctx context.Context, item *httpmsg.HttpRequestResponse, sc *modules.ScanContext) {
		if pathOf(item) != "/spec" {
			if strings.HasPrefix(pathOf(item), "/endpoint-") {
				seen.Add(1)
			}
			return
		}
		select {
		case <-src.waiting: // deterministically enter Next's ACK barrier first
		case <-ctx.Done():
			return
		}
		for i := range endpoints {
			_, rr := makeTestItem("hol.example.test", fmt.Sprintf("/endpoint-%d", i), "<html>ready</html>")
			if !sc.RequestFeeder.Feed(rr) {
				refused.Add(1)
			}
		}
	})
	e := NewExecutor(ExecutorConfig{Workers: 1, SkipBaseline: true}, src, []modules.ActiveModule{mod}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := e.Execute(ctx)
	require.NoError(t, err)
	require.Zero(t, refused.Load(), "a source waiting for ACK must not starve endpoint feedback")
	require.Equal(t, int64(endpoints), seen.Load())
	require.Equal(t, int64(endpoints+1), e.Processed())
}
