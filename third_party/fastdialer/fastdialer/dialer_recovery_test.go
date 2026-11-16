package fastdialer

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDialerRecoveryAndPolicy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	for _, name := range []string{"literal", "hostname", "deny_ip", "deny_port", "validation_rejected"} {
		t.Run(name, func(t *testing.T) {
			options := DefaultOptions
			options.HostsFile = false
			options.ResolversFile = false
			var failed atomic.Bool
			failed.Store(true)
			var attempts atomic.Int64
			options.Dialer = &net.Dialer{Timeout: time.Second, Control: func(_, _ string, _ syscall.RawConn) error {
				attempts.Add(1)
				if failed.Load() {
					return syscall.EHOSTUNREACH
				}
				return nil
			}}
			denied := true
			switch name {
			case "literal", "hostname":
				denied = false
			case "deny_ip":
				options.Deny = []string{"127.0.0.1"}
			case "deny_port":
				options.DenyPortList = []int{portNumber}
			case "validation_rejected":
				options.OnValidateTarget = func(_, _, _ string) error { return errors.New("fixture policy denied") }
			}
			d, err := NewDialer(options)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			address := listener.Addr().String()
			if name == "hostname" {
				// Exercise hostname cache key/resolution path without external DNS.
				ctx = context.WithValue(ctx, IP, "127.0.0.1")
				address = net.JoinHostPort("recovery.invalid", port)
			}
			for i := 0; i < 3; i++ {
				if i > 0 {
					failed.Store(false)
				}
				conn, err := d.Dial(ctx, "tcp", address)
				if conn != nil {
					conn.Close()
				}
				if denied {
					if err != NoAddressAllowedError || attempts.Load() != 0 {
						t.Fatalf("policy bypass on attempt %d: err=%v socket_dials=%d", i, err, attempts.Load())
					}
				} else if i == 0 {
					if err == nil || attempts.Load() != 1 {
						t.Fatalf("invalid initial fault: err=%v dials=%d", err, attempts.Load())
					}
				} else if err != nil || attempts.Load() != int64(i+1) {
					t.Fatalf("recovered dial failed: err=%v dials=%d want=%d", err, attempts.Load(), i+1)
				}
			}
		})
	}
}
