package dependency_confusion

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestRegistryLookup_StatusMapping(t *testing.T) {
	cases := []struct {
		status int
		want   resolution
	}{
		{http.StatusOK, resolutionClaimed},
		{http.StatusNotFound, resolutionUnclaimed},
		{http.StatusTooManyRequests, resolutionIndeterminate},
		{http.StatusInternalServerError, resolutionIndeterminate},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
		}))
		rc := newRegistryClient(srv.URL, 5*time.Second)
		got, _ := rc.lookup(context.Background(), "left-pad")
		srv.Close()
		if got != c.want {
			t.Errorf("status %d -> %v, want %v", c.status, got, c.want)
		}
	}
}

func TestRegistryLookup_ScopedEncoding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rc := newRegistryClient(srv.URL, 5*time.Second)
	rc.lookup(context.Background(), "@acme/thing")
	if gotPath != "/@acme%2fthing" {
		t.Errorf("scoped name escaping = %q, want /@acme%%2fthing", gotPath)
	}
}

func TestRegistryLookup_NetworkErrorIndeterminate(t *testing.T) {
	// Closed server -> connection error -> indeterminate.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()
	rc := newRegistryClient(url, 1*time.Second)
	if got, _ := rc.lookup(context.Background(), "left-pad"); got != resolutionIndeterminate {
		t.Errorf("network error -> %v, want indeterminate", got)
	}
}

func TestRegistryLookupCompletedRequestWithoutResponseRemainsIndeterminate(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead {
			t.Errorf("registry method = %q, want HEAD", r.Method)
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()
	rc := newRegistryClient(srv.URL, 2*time.Second)
	defer rc.client.CloseIdleConnections()
	got, receipt := rc.lookup(context.Background(), "left-pad")
	require.Equal(t, resolutionIndeterminate, got)
	require.Nil(t, receipt) // error cleanup does not turn a partial receipt into a declaration
	require.EqualValues(t, 1, requests.Load())
}

func TestRegistryLookupReturnsOwnedFinalHEADReceipt(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead {
			t.Errorf("registry method = %q, want HEAD", r.Method)
		}
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("X-Registry-Proof", "owned")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	rc := newRegistryClient(srv.URL, 5*time.Second)
	got, x := rc.lookup(context.Background(), "@acme/private")
	require.Equal(t, resolutionUnclaimed, got)
	require.Equal(t, int32(2), requests.Load()) // existing redirect policy, no evidence refetch
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, srv.URL, x.Service)
	require.Equal(t, srv.URL+"/final", x.URL)
	require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateComplete, x.ResponseState)
	requestLine, _, ok := strings.Cut(string(x.Request), "\r\n")
	require.True(t, ok)
	require.Equal(t, "HEAD /final HTTP/1.1", requestLine)
	require.Contains(t, string(x.Request), "Accept: application/json")
	// The final request target changes, but net/http legitimately retains the
	// original scoped URL in Referer. Evidence must preserve that actual header.
	require.Contains(t, string(x.Request), "\r\nReferer: "+srv.URL+"/@acme%2fprivate\r\n")
	require.Contains(t, string(x.Response), "X-Registry-Proof: owned")
}

type registryUntracedTransport func(*http.Request) (*http.Response, error)

func (f registryUntracedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRegistryLookupUntracedTransportDoesNotFabricateRequest(t *testing.T) {
	rc := newRegistryClient("http://registry.example", 5*time.Second)
	rc.client.Transport = registryUntracedTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			Request: req, StatusCode: http.StatusNotFound, Status: "404 Not Found",
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")),
		}, nil
	})
	got, x := rc.lookup(context.Background(), "@acme/private")
	require.Equal(t, resolutionUnclaimed, got)
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateMissing, x.RequestState)
	require.Empty(t, x.Request)
	require.Contains(t, string(x.Response), "404 Not Found")
	require.Equal(t, "http://registry.example", x.Service)
}
