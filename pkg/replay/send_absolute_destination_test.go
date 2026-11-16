package replay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/proxytarget"
)

func TestReplayAbsoluteTargetDialsExplicitDestinationAndReportsNormalization(t *testing.T) {
	const intended = "https://absolute-target.invalid/proof/%2fkeep?q=%2527"
	raw := []byte("GET " + intended + " HTTP/1.1\r\nHost: virtual-host.invalid\r\n\r\n")
	for _, viaProxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("proxy=%t", viaProxy), func(t *testing.T) {
			type requestSeen struct{ target, host string }
			seen := make(chan requestSeen, 1)
			// In proxy mode A is also the proxy endpoint. It records and answers
			// locally, never forwards or resolves a request-target authority.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- requestSeen{r.RequestURI, r.Host}
				_, _ = w.Write([]byte("destination A"))
			}))
			defer srv.Close()
			destination, err := url.Parse(srv.URL)
			require.NoError(t, err)
			dialer := &net.Dialer{}
			base := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != destination.Host {
					return nil, fmt.Errorf("attempted B/DNS instead of destination A: %s", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			}}
			if viaProxy {
				base.Proxy = http.ProxyURL(destination)
			}
			defer base.CloseIdleConnections()
			client := &http.Client{Transport: proxytarget.Wrap(base), Timeout: 2 * time.Second}
			host, port := splitAddr(t, destination.Host)
			result, err := Do(context.Background(), Options{RawRequest: raw,
				Client: client, Scheme: "http", Hostname: host, Port: port,
				CaptureExchange: !viaProxy, NoRedirects: true})
			require.NoError(t, err)
			require.Empty(t, result.Replay.Error)
			require.Equal(t, http.StatusOK, result.Replay.Status)
			require.True(t, bytes.Equal(raw, result.RawMutatedRequest))
			policy := result.Replay.RequestTargetPolicy
			require.NotNil(t, policy)
			require.Equal(t, intended, policy.IntendedTarget)
			require.Equal(t, "/proof/%2fkeep?q=%2527", policy.DirectTarget)
			require.Equal(t, evidence.StateUnknown, policy.Fidelity)
			actual := <-seen
			if viaProxy {
				require.Equal(t, srv.URL+"/proof/%2fkeep?q=%2527", actual.target)
				// net/http's server prefers the absolute target's authority;
				// it does not expose the independently sent virtual Host here.
			} else {
				require.Equal(t, "/proof/%2fkeep?q=%2527", actual.target)
				require.Equal(t, "virtual-host.invalid", actual.host)
				x := result.Replay.Exchange
				require.NotNil(t, x)
				require.Equal(t, srv.URL, x.Service)
				require.Equal(t, "virtual-host.invalid", httpmsg.NewHttpRequest(x.Request).Header("Host"))
				require.Equal(t, "/proof/%2fkeep?q=%2527", httpmsg.NewHttpRequest(x.Request).Path())
				require.NotEqual(t, raw, x.Request) // never label normalized bytes as the original proof
				require.NoError(t, x.Validate())
			}
		})
	}
}

func TestReplayExternalSenderReceivesAbsoluteTargetUnmodified(t *testing.T) {
	raw := []byte("GET https://absolute-target.invalid/proof HTTP/1.1\r\nHost: virtual-host.invalid\r\n\r\n")
	var sent []byte
	result, err := Do(context.Background(), Options{RawRequest: raw, Scheme: "http", Hostname: "destination.invalid", Port: 8080,
		Sender: func(_ context.Context, request []byte) *Summary {
			sent = bytes.Clone(request)
			return &Summary{Status: http.StatusOK}
		}})
	require.NoError(t, err)
	require.Equal(t, raw, sent)
	require.Nil(t, result.Replay.RequestTargetPolicy) // native policy cannot certify an external sender
}
