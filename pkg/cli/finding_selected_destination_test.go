package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
)

func TestSelectedReplaySendsToReceiptDestinationNotAbsoluteAuthority(t *testing.T) {
	const intended = "https://absolute-target.invalid/proof/%2fkeep?q=%2527"
	raw := []byte("GET " + intended + " HTTP/1.1\r\nHost: virtual-host.invalid\r\n\r\n")
	type requestSeen struct{ target, host string }
	seen := make(chan requestSeen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- requestSeen{r.RequestURI, r.Host}
		_, _ = w.Write([]byte("destination A"))
	}))
	defer srv.Close()
	destination, err := url.Parse(srv.URL)
	require.NoError(t, err)
	x := evidence.NewExchange(srv.URL, "https://finding-display.invalid/elsewhere", raw, []byte("HTTP/1.1 200 OK\r\n\r\nstored"), evidence.ProvenanceCaptured)
	f := &database.Finding{ID: 7, ProjectUUID: database.DefaultProjectUUID, Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "proof")}}
	src, err := sourceFromSelectedFinding(f)
	require.NoError(t, err)
	require.Equal(t, srv.URL+"/proof/%2fkeep?q=%2527", src.URL)
	require.Equal(t, destination.Hostname(), src.Hostname)
	require.Equal(t, "http", src.Scheme)
	require.Equal(t, raw, src.BaselineRequest)

	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != destination.Host {
			return nil, fmt.Errorf("attempted B/DNS instead of captured A: %s", addr)
		}
		return dialer.DialContext(ctx, network, addr)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	result, err := replay.Do(context.Background(), replay.Options{
		BaselineRequest: src.BaselineRequest, BaselineResponse: src.BaselineResponse,
		Scheme: src.Scheme, Hostname: src.Hostname, Port: src.Port,
		Client: client, NoRedirects: true, CaptureExchange: true,
	})
	require.NoError(t, err)
	require.Empty(t, result.Replay.Error)
	require.Equal(t, requestSeen{"/proof/%2fkeep?q=%2527", "virtual-host.invalid"}, <-seen)
	require.NotNil(t, result.Replay.RequestTargetPolicy)
	require.Equal(t, intended, result.Replay.RequestTargetPolicy.IntendedTarget)
	require.Equal(t, evidence.StateUnknown, result.Replay.RequestTargetPolicy.Fidelity)
	require.Equal(t, srv.URL, result.Replay.Exchange.Service)
	require.Equal(t, "/proof/%2fkeep?q=%2527", httpmsg.NewHttpRequest(result.Replay.Exchange.Request).Path())
	require.Equal(t, raw, x.Request)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"request_target_policy"`)
	require.Contains(t, string(encoded), `"fidelity":"unknown"`)
}
