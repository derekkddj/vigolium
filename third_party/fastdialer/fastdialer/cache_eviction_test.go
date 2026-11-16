package fastdialer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer/utils"
	"github.com/projectdiscovery/retryabledns"
)

func TestFailedWrapperEvictionKeepsSuccessor(t *testing.T) {
	opts := DefaultOptions
	opts.HostsFile, opts.ResolversFile = false, false
	d, err := NewDialer(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	newWrap := func() *utils.DialWrap {
		w, err := utils.NewDialWrap(&net.Dialer{}, []string{"127.0.0.1"}, "tcp", "127.0.0.1:1", "1")
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	old, successor, unrelated := newWrap(), newWrap(), newWrap()
	const key = "tcp-127.0.0.1:1"
	if err := d.dialCache.Set(key, old); err != nil {
		t.Fatal(err)
	}
	if err := d.dialCache.Set("other", unrelated); err != nil {
		t.Fatal(err)
	}
	d.forgetFailedDialWrap(key, old)
	if _, err := d.dialCache.GetIFPresent(key); err == nil {
		t.Fatal("failed wrapper was not evicted")
	}
	// Race a replacement publisher against many late failures from old callers.
	// Whether published before, during or after them, it must survive.
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.forgetFailedDialWrap(key, old)
		}()
	}
	d.dialCacheMu.Lock()
	err = d.dialCache.Set(key, successor)
	d.dialCacheMu.Unlock()
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := d.dialCache.GetIFPresent(key); err != nil || got != successor {
		t.Fatalf("late failure evicted healthy successor: got=%p err=%v", got, err)
	}
	if got, err := d.dialCache.GetIFPresent("other"); err != nil || got != unrelated {
		t.Fatal("unrelated destination cache changed")
	}
}

func TestRecoveryKeepsDNSAndFiltersDeniedAnswers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	var blocked atomic.Bool
	blocked.Store(true)
	var attempts, validations atomic.Int64
	opts := DefaultOptions
	opts.HostsFile, opts.ResolversFile = false, false
	opts.Deny = []string{"127.0.0.2"}
	opts.OnValidateTarget = func(_, ip, _ string) error {
		if ip != "127.0.0.1" {
			t.Errorf("denied DNS answer reached validation: %s", ip)
		}
		validations.Add(1)
		return nil
	}
	opts.Dialer = &net.Dialer{Timeout: time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		attempts.Add(1)
		host, _, _ := net.SplitHostPort(address)
		if host != "127.0.0.1" {
			t.Errorf("socket attempted denied DNS answer: %s", address)
		}
		if blocked.Load() {
			return syscall.EHOSTUNREACH
		}
		return nil
	}}
	d, err := NewDialer(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	data := &retryabledns.DNSData{A: []string{"127.0.0.2", "127.0.0.1"}}
	const hostname = "recovery.invalid"
	if err := d.mDnsCache.Set(hostname, data); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	address := net.JoinHostPort(hostname, port)
	if conn, err := d.Dial(ctx, "tcp", address); err == nil {
		conn.Close()
		t.Fatal("controlled first socket failure did not occur")
	}
	blocked.Store(false)
	for i := 0; i < 2; i++ {
		conn, err := d.Dial(ctx, "tcp", address)
		if err != nil {
			t.Fatalf("failed to recover using retained DNS: %v", err)
		}
		conn.Close()
		if got, err := d.GetDNSDataFromCache(hostname); err != nil || got != data {
			t.Fatal("wrapper eviction purged DNS data")
		}
	}
	if attempts.Load() != 3 || validations.Load() != 2 {
		t.Fatalf("unexpected recovery/positive-cache behavior: socket_dials=%d validations=%d", attempts.Load(), validations.Load())
	}
}
