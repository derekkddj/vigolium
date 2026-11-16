package fastdialer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDialerInflightCancellationAndDeadlineRecover(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancelled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var blocked atomic.Bool
			blocked.Store(true)
			started := make(chan struct{})
			var once sync.Once
			opts := DefaultOptions
			opts.HostsFile, opts.ResolversFile = false, false
			opts.Dialer = &net.Dialer{Timeout: time.Second, ControlContext: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
				if blocked.Load() {
					once.Do(func() { close(started) })
					<-ctx.Done() // genuine in-flight cancellation, not a fake error
					return ctx.Err()
				}
				return nil
			}}
			d, err := NewDialer(opts)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			first, stop := context.WithCancel(ctx)
			if deadline {
				stop()
				first, stop = context.WithTimeout(ctx, 100*time.Millisecond)
			}
			defer stop()
			result := make(chan error, 1)
			go func() {
				conn, err := d.Dial(first, "tcp", listener.Addr().String())
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("dial never reached controlled in-flight socket")
			}
			if !deadline {
				stop()
			}
			select {
			case err := <-result:
				if err == nil || first.Err() == nil {
					t.Fatal("stopped in-flight dial did not fail")
				}
			case <-time.After(time.Second):
				t.Fatal("in-flight dial did not honor cancellation/deadline promptly")
			}
			blocked.Store(false)
			conn, err := d.Dial(ctx, "tcp", listener.Addr().String())
			if err != nil {
				t.Fatalf("fresh caller cannot recover after in-flight cancellation: %v", err)
			}
			conn.Close()
		})
	}
}
