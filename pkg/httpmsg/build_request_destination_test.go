package httpmsg

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
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestEvidenceAbsoluteTargetBuildsAndSendsToCapturedService(t *testing.T) {
	const target = "https://absolute-target.invalid/proof/%2fkeep?q=%2527"
	const raw = "GET " + target + " HTTP/1.1\r\nHost: virtual-host.invalid\r\n\r\n"
	type requestSeen struct{ target, host string }
	seen := make(chan requestSeen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- requestSeen{r.RequestURI, r.Host}
		_, _ = w.Write([]byte("destination A"))
	}))
	defer srv.Close()
	destination, err := url.Parse(srv.URL)
	require.NoError(t, err)
	x := evidence.NewExchange(srv.URL, "https://finding-display.invalid/not-the-target", []byte(raw), nil, evidence.ProvenanceCaptured)
	rr, err := FromEvidenceExchange(x)
	require.NoError(t, err)
	u, err := rr.URL()
	require.NoError(t, err)
	require.Equal(t, "http", u.Scheme)
	require.Equal(t, destination.Host, u.Host)
	require.Equal(t, "/proof/%2fkeep?q=%2527", u.RequestURI())
	require.Equal(t, target, rr.Request().Path())
	require.Equal(t, raw, string(rr.Request().Raw()))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := rr.BuildRetryableRequestWithContext(ctx)
	require.NoError(t, err)
	require.Equal(t, destination.Host, req.URL.Host)
	require.Equal(t, "http", req.URL.Scheme)
	require.Equal(t, "virtual-host.invalid", req.Host)
	require.Empty(t, req.RequestURI)
	policy, ok := RequestTargetPolicyFromContext(req.Context())
	require.True(t, ok)
	require.Equal(t, target, policy.IntendedTarget)
	require.Equal(t, "/proof/%2fkeep?q=%2527", policy.DirectTarget)
	require.Equal(t, "absolute_form_normalized", policy.Policy)
	require.Equal(t, evidence.StateUnknown, policy.Fidelity)
	require.Contains(t, policy.Note, "raw-capable sender")

	dials := make(chan string, 1)
	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials <- addr
		if addr != destination.Host {
			return nil, fmt.Errorf("attempted destination B/DNS: %s", addr)
		}
		return dialer.DialContext(ctx, network, addr)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	resp, err := client.Do(req.Request)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, destination.Host, <-dials)
	require.Equal(t, requestSeen{"/proof/%2fkeep?q=%2527", "virtual-host.invalid"}, <-seen)
	require.Equal(t, raw, string(rr.Request().Raw()))
	require.Equal(t, x.ContentHash, rr.Evidence().ContentHash)
	require.NoError(t, rr.Evidence().Validate())
}

func TestPinnedDestinationSurvivesBuildersAndExplicitRetarget(t *testing.T) {
	raw := []byte("GET https://absolute-target.invalid/proof HTTP/1.1\r\nHost: virtual-host.invalid\r\n\r\n")
	x := evidence.NewExchange("http://destination.invalid:8080", "https://finding.invalid/elsewhere", raw, nil, evidence.ProvenanceCaptured)
	rr, err := FromEvidenceExchange(x)
	require.NoError(t, err)
	encoded, err := json.Marshal(rr)
	require.NoError(t, err)
	var decoded HttpRequestResponse
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	retarget, err := NewService("retarget.invalid", 9090, "http")
	require.NoError(t, err)
	variants := []struct {
		name string
		rr   *HttpRequestResponse
		host string
	}{
		{"restored", rr, "destination.invalid:8080"},
		{"clone", rr.Clone(), "destination.invalid:8080"},
		{"JSON", &decoded, "destination.invalid:8080"},
		{"response removed", rr.WithResponse(nil), "destination.invalid:8080"},
		{"header builder", NewHttpRequestResponse(rr.Request().WithHeader("X-Probe", "yes"), nil), "destination.invalid:8080"},
		{"trusted raw builder", NewRequestResponseRaw(raw, rr.Service()), "destination.invalid:8080"},
		{"request service override", NewHttpRequestResponse(rr.Request().WithService(retarget), nil), "retarget.invalid:9090"},
		{"option service override", NewHttpRequestResponse(rr.Request().Apply(WithOptService(retarget)), nil), "retarget.invalid:9090"},
		{"response service override", rr.Clone().WithService(retarget), "retarget.invalid:9090"},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			u, err := GetURLFromService(tc.rr.Request().Raw(), tc.rr.Service())
			require.NoError(t, err)
			require.Equal(t, "http", u.Scheme)
			require.Equal(t, tc.host, u.Host)
			req, err := tc.rr.BuildRetryableRequest()
			require.NoError(t, err)
			require.Equal(t, tc.host, req.URL.Host)
			require.Equal(t, "virtual-host.invalid", req.Host)
			policy, ok := RequestTargetPolicyFromContext(req.Context())
			require.True(t, ok)
			require.Equal(t, evidence.StateUnknown, policy.Fidelity)
		})
	}
	require.False(t, retarget.destinationPinned) // pinning never mutates shared services
}

func TestAbsoluteTargetIngestionAndExplicitEnvelopeDestinationContracts(t *testing.T) {
	const raw = "GET https://absolute-target.invalid/proof HTTP/1.1\r\nHost: virtual-host.invalid\r\n\r\n"
	service, err := NewService("inferred.invalid", 8080, "http")
	require.NoError(t, err)
	ordinary := NewHttpRequestResponse(NewHttpRequestWithService(service, []byte(raw)), nil)
	u, err := ordinary.URL()
	require.NoError(t, err)
	require.Equal(t, "absolute-target.invalid", u.Host)
	require.Equal(t, "https", u.Scheme)

	for _, explicit := range []bool{false, true} {
		envelope := map[string]any{"url": "http://destination.invalid:8080/display", "request": map[string]any{"raw": []byte(raw)}}
		if explicit {
			envelope["service"] = "http://destination.invalid:8080"
		}
		encoded, err := json.Marshal(envelope)
		require.NoError(t, err)
		var decoded HttpRequestResponse
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		u, err := decoded.URL()
		require.NoError(t, err)
		if explicit {
			require.Equal(t, "destination.invalid:8080", u.Host)
			require.Equal(t, "http", u.Scheme)
		} else {
			require.Equal(t, "absolute-target.invalid", u.Host) // legacy URL-only ingestion
			require.Equal(t, "https", u.Scheme)
		}
		require.Equal(t, raw, string(decoded.Request().Raw()))
	}
}
