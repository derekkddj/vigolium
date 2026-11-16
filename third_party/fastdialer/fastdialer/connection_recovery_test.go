package fastdialer

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/utils"
	"github.com/projectdiscovery/utils/errkit"
)

// The listener is healthy throughout; only the controlled socket dial fails.
// No external network, firewall changes, or port-rebinding race is involved.
func TestDialerConnectionRecovery(t *testing.T) {
	for _, fault := range []struct {
		name string
		err  error
	}{
		{"no_route", syscall.EHOSTUNREACH},
		{"refused", syscall.ECONNREFUSED},
		{"deadline", context.DeadlineExceeded},
		{"cancelled", context.Canceled},
	} {
		t.Run(fault.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var failed atomic.Bool
			failed.Store(true)
			var attempts atomic.Int64
			dialer := &net.Dialer{Timeout: time.Second, Control: func(_, _ string, _ syscall.RawConn) error {
				attempts.Add(1)
				if failed.Load() {
					return fault.err
				}
				return nil
			}}
			options := DefaultOptions
			options.HostsFile = false
			options.ResolversFile = false
			options.Dialer = dialer
			wrap, err := NewDialer(options)
			if err != nil {
				t.Fatal(err)
			}
			defer wrap.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for i := 0; i < 2; i++ {
				conn, err := wrap.Dial(ctx, "tcp", listener.Addr().String())
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Fatal("still-failing socket incorrectly accepted")
				}
				if i == 0 && fault.err != context.Canceled {
					if attempts.Load() != 1 || !errkit.Is(err, utils.ErrPortClosedOrFiltered) || !strings.Contains(err.Error(), fault.err.Error()) {
						t.Fatalf("initial error/single attempt changed: err=%v dials=%d", err, attempts.Load())
					}
				}
			}
			failed.Store(false)
			before := attempts.Load()
			// Even simultaneous later callers must make fresh, independent
			// connections, rather than sharing one socket or a cached error.
			const clients = 8
			var wg sync.WaitGroup
			results := make(chan error, clients)
			start := make(chan struct{})
			for i := 0; i < clients; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					conn, err := wrap.Dial(ctx, "tcp", listener.Addr().String())
					if conn != nil {
						conn.Close()
					}
					results <- err
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Errorf("recovered socket rejected: %v", err)
				}
			}
			if got := attempts.Load() - before; got != clients {
				t.Errorf("new underlying dials=%d, want %d", got, clients)
			}
			// A cancelled/deadline-expired later caller must not connect.
			for _, expired := range []bool{false, true} {
				var stopped context.Context
				var stop context.CancelFunc
				if expired {
					stopped, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				} else {
					stopped, stop = context.WithCancel(ctx)
					stop()
				}
				before := attempts.Load()
				conn, err := wrap.Dial(stopped, "tcp", listener.Addr().String())
				stop()
				if conn != nil {
					conn.Close()
				}
				if err == nil || attempts.Load() != before {
					t.Fatalf("stopped caller made a connection: err=%v dials=%d", err, attempts.Load()-before)
				}
			}
		})
	}
}
