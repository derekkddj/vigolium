package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/types"
)

// Each runner builds a new requester but borrows the same process-wide dialer,
// as API scans in a long-lived server do. A failed scan must not poison the next
// scan once the target is actually reachable. No skip/retry masks the first fail.
func TestPreflightRecoversAcrossScans(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(key, "")
	}
	for _, useTLS := range []bool{false, true} {
		name, scheme := "http", "http"
		if useTLS {
			name, scheme = "https", "https"
		}
		t.Run(name, func(t *testing.T) {
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := reserved.Addr().String()
			if err := reserved.Close(); err != nil {
				t.Fatal(err)
			}
			target := scheme + "://" + addr + "/"
			opts := types.DefaultOptions()
			opts.Silent = true
			opts.Retries = 0
			if err := network.Init(opts); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(network.Close)
			shared := network.CurrentDialer()
			newScan := func() (*Runner, *phaseInfra) {
				req, err := vhttp.NewRequester(opts, &services.Services{Options: opts})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(req.CloseIdleConnections)
				return &Runner{options: opts, scanLogger: database.NewScanLogger(nil, "", "")}, &phaseInfra{httpRequester: req}
			}
			check := func(wantReachable bool) {
				t.Helper()
				r, infra := newScan()
				o := admissionOutcome(TargetAdmission{Admitted: []string{target}})
				err := r.runPreflight(context.Background(), infra, []string{target}, &o)
				if !wantReachable {
					if !errors.Is(err, ErrNoTargetsReachable) || o.Targets.Reached != 0 || !o.Targets.ReachabilityChecked {
						t.Fatalf("dead target not honestly rejected: outcome=%+v err=%v", o, err)
					}
					return
				}
				if err != nil || o.Targets.Reached != 1 || !o.Targets.ReachabilityChecked || len(o.Targets.Unreachable) != 0 {
					t.Fatalf("new native scan rejects recovered target: outcome=%+v err=%v", o, err)
				}
				if network.CurrentDialer() != shared {
					t.Fatal("recovery replaced the shared dialer")
				}
			}
			check(false)
			check(false) // A still-dead target must stay dead, not be assumed good.
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("could not reopen fixture address: %v", err)
			}
			var hits atomic.Int64
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("healthy fixture"))
			}))
			_ = srv.Listener.Close()
			srv.Listener = listener
			if useTLS {
				srv.StartTLS()
			} else {
				srv.Start()
			}
			t.Cleanup(srv.Close)
			plain := srv.Client()
			defer plain.CloseIdleConnections()
			response, err := plain.Get(target)
			if err != nil {
				t.Fatalf("independent client cannot reach recovered fixture: %v", err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK || hits.Load() != 1 {
				t.Fatal("independent HTTP200 recovery precondition failed")
			}
			check(true)
			if hits.Load() != 2 {
				t.Fatalf("recovery verdict made without a new HTTP answer: hits=%d", hits.Load())
			}
			check(true)
			if hits.Load() != 3 {
				t.Fatalf("subsequent native scan failed: hits=%d", hits.Load())
			}
		})
	}
}
