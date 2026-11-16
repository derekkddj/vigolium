package fastdialer

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandshakeAndCancellationKeepHealthyWrapper(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	opts := DefaultOptions
	opts.HostsFile, opts.ResolversFile = false, false
	d, err := NewDialer(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr := srv.Listener.Addr().String()
	key := "tcp-" + addr
	// TCP succeeds; certificate validation intentionally fails. This is not
	// a cached first-socket failure and must not discard the positive wrapper.
	if conn, err := d.DialTLSWithConfig(ctx, "tcp", addr, &tls.Config{}); err == nil {
		conn.Close()
		t.Fatal("expected untrusted fixture certificate to fail")
	}
	positive, err := d.dialCache.GetIFPresent(key)
	if err != nil || positive == nil {
		t.Fatal("TLS error evicted successful socket wrapper")
	}
	conn, err := d.DialTLSWithConfig(ctx, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) // disposable fixture only
	if err != nil {
		t.Fatalf("TLS success after failed handshake: %v", err)
	}
	conn.Close()
	stopped, stop := context.WithCancel(ctx)
	stop()
	if conn, err := d.Dial(stopped, "tcp", addr); err == nil {
		conn.Close()
		t.Fatal("cancelled caller connected")
	}
	if got, err := d.dialCache.GetIFPresent(key); err != nil || got != positive {
		t.Fatal("handshake recovery/cancelled waiter replaced healthy wrapper")
	}
}
