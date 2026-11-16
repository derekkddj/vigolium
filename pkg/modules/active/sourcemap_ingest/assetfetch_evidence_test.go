package sourcemap_ingest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestAssetCapturePreservesBytesAPIAndOwnsReceipt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"asset":"` + r.URL.Path + `"}`))
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL+"/bundle.js"), modtest.Requester(t)
	legacy, ok := modkit.FetchAssetBytes(ctx, client, "/map", 5)
	require.True(t, ok)
	body, receipt, ok := modkit.FetchAssetBytesCapture(ctx, client, "/map", 5)
	require.True(t, ok)
	require.Equal(t, legacy, body, "comparison bytes and maxBytes are unchanged")
	require.Len(t, body, 5)
	require.NotNil(t, receipt)
	require.NoError(t, receipt.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, receipt.Provenance)
	require.Contains(t, string(receipt.Request), "GET /map HTTP/1.1")
	require.Contains(t, string(receipt.Response), `{"asset":"/map"}`, "comparison cap must not replace HTTP bytes")
	before := receipt.Clone()
	_, later, ok := modkit.FetchAssetBytesCapture(ctx, client, "/different", 0)
	require.True(t, ok)
	require.NotNil(t, later)
	require.NotEqual(t, receipt.ID, later.ID)
	require.Equal(t, before, receipt, "receipt survives chain Close and later buffer reuse")
	require.EqualValues(t, 3, calls.Load(), "exactly one network operation per API call; clustering stays off")
}

func TestAssetCaptureKeepsGuardsAndNoRedirects(t *testing.T) {
	var followed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>catch-all</html>"))
		case "/target":
			followed.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL+"/bundle.js"), modtest.Requester(t)
	for _, path := range []string{"/redirect", "/html", "/absent"} {
		body, receipt, ok := modkit.FetchAssetBytesCapture(ctx, client, path, 0)
		require.False(t, ok)
		require.Nil(t, body)
		require.NotNil(t, receipt, "rejected response is still its own operation, not selected proof")
		require.NoError(t, receipt.Validate())
		require.Equal(t, srv.URL+path, receipt.URL)
	}
	require.Zero(t, followed.Load())
}

func TestFetchedMapReceiptHasAnonymousSentHeaders(t *testing.T) {
	mapBody := mapWithSources(t, true, "/api/original")
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mapBody))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/bundle.js")
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), "Authorization", "Bearer private-input")
	require.NoError(t, err)
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Cookie", "private=session")
	require.NoError(t, err)
	rr = modtest.Response(httpmsg.NewRequestResponseRaw(raw, rr.Service()), "text/javascript", "//# sourceMappingURL=bundle.js.map")
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.False(t, r.BaselineEvidence)
	require.Len(t, r.Evidence, 1)
	require.Contains(t, r.Request, "GET /bundle.js.map HTTP/1.1")
	require.False(t, strings.Contains(strings.ToLower(r.Request), "authorization:"))
	require.False(t, strings.Contains(strings.ToLower(r.Request), "cookie:"))
	require.Contains(t, r.Response, mapBody)
	require.EqualValues(t, 1, requests.Load())
}
