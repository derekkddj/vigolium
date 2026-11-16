package tool

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type failingHTTPReceiptSink struct {
	err error
	id  string
}

func (s failingHTTPReceiptSink) SaveRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, error) {
	return s.id, s.err
}
func (s failingHTTPReceiptSink) SaveRecordBatch(context.Context, []*httpmsg.HttpRequestResponse, string, string) ([]string, error) {
	return nil, s.err
}

func TestWebHTTPFetchPersistsTransportReceiptNotIntendedHeaders(t *testing.T) {
	type requestSeen struct {
		host, body string
		headers    http.Header
	}
	seen := make(chan requestSeen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- requestSeen{r.Host, string(body), r.Header.Clone()}
		_, _ = w.Write([]byte("actual response"))
	}))
	defer srv.Close()
	sink := &recordingSink{}
	fetch := NewWebFetchWithCapture(sink, "proj")
	res, err := fetch.Execute(context.Background(), map[string]any{"url": srv.URL + "/actual", "method": "POST", "body": "sent body",
		"headers": map[string]any{"Authorization": "Bearer fresh", "Host": "intended.invalid"}}, nil)
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Len(t, sink.records, 1)
	actual := <-seen
	rr := sink.records[0]
	require.Equal(t, actual.host, rr.Request().Header("Host")) // existing send behaviour ignores Header[Host]
	require.NotEqual(t, "intended.invalid", actual.host)
	require.Equal(t, actual.body, string(rr.Request().Body()))
	for _, name := range []string{"Authorization", "User-Agent", "Accept-Encoding"} {
		require.Equal(t, actual.headers.Get(name), rr.Request().Header(name), name)
	}
	require.NotEmpty(t, rr.Request().Header("Accept-Encoding"))
	require.Equal(t, true, res.Details["persisted"])
	require.Equal(t, "saved", res.Details["persistence_status"])
	manifest := res.Details["receipt"].(HTTPReceiptManifest)
	require.True(t, manifest.Available)
	require.Equal(t, "http_client_message", manifest.Boundary)
	require.Contains(t, res.Content, manifest.Ref) // model history does not consume Details
	require.Contains(t, res.Content, `"persistence_status":"saved"`)
	x, err := fetch.(HTTPReceiptProvider).SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Equal(t, x.Request, rr.Request().Raw())
	require.Equal(t, x.Response, rr.Response().Raw())
	require.Equal(t, x.ContentHash, rr.Evidence().ContentHash)
	require.Equal(t, srv.URL, x.Service)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateComplete, x.ResponseState)
}

func TestWebHTTPFetchCapRetainsPartialReceiptWithoutCompleteRecord(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("12345678"))
	}))
	defer srv.Close()
	for _, cap := range []float64{3, 8} {
		sink := &recordingSink{}
		fetch := NewWebFetchWithCapture(sink, "proj")
		res, err := fetch.Execute(context.Background(), map[string]any{"url": srv.URL, "max_bytes": cap}, nil)
		require.NoError(t, err)
		require.False(t, res.IsError)
		manifest := res.Details["receipt"].(HTTPReceiptManifest)
		x, err := fetch.(HTTPReceiptProvider).SelectHTTPReceipt(manifest.Ref)
		require.NoError(t, err)
		require.NoError(t, x.Validate())
		require.Equal(t, int64(cap)+1, res.Details["response_body_limit_bytes"])
		require.Equal(t, int64(cap), res.Details["display_body_limit_bytes"])
		if cap == 3 {
			require.Equal(t, 4, res.Details["response_body_bytes_retained"])
			require.Equal(t, true, res.Details["response_body_omitted"])
			require.Equal(t, false, res.Details["response_body_complete"])
			require.Equal(t, true, res.Details["truncated"])
			require.Equal(t, false, res.Details["persisted"])
			require.Equal(t, "capture_unavailable", res.Details["persistence_status"])
			require.Empty(t, sink.records)
			require.Equal(t, evidence.StateTruncated, x.ResponseState)
			require.Equal(t, "1234", string(httpmsg.NewHttpResponse(x.Response).Body())) // retained sentinel, display capped at 3
			require.Contains(t, res.Content, "[truncated at 3 bytes]")
		} else {
			require.Equal(t, 8, res.Details["response_body_bytes_retained"])
			require.Equal(t, false, res.Details["response_body_omitted"])
			require.Equal(t, true, res.Details["response_body_complete"])
			require.Equal(t, false, res.Details["truncated"])
			require.Equal(t, true, res.Details["persisted"])
			require.Len(t, sink.records, 1)
			require.Equal(t, evidence.StateComplete, x.ResponseState)
		}
	}
	require.EqualValues(t, 2, hits.Load()) // no retry/additional request to capture completeness
}

func TestWebHTTPFetchSinkFailuresAreNotExecutionFailuresOrFalseUUIDs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("success")) }))
	defer srv.Close()
	for _, sink := range []failingHTTPReceiptSink{{err: errors.New("store unavailable")}, {}} {
		fetch := NewWebFetchWithCapture(sink, "proj")
		res, err := fetch.Execute(context.Background(), map[string]any{"url": srv.URL}, nil)
		require.NoError(t, err)
		require.False(t, res.IsError)
		require.Contains(t, res.Content, "success")
		require.Equal(t, false, res.Details["persisted"])
		require.Equal(t, "failed", res.Details["persistence_status"])
		require.NotEmpty(t, res.Details["persist_error"])
		require.NotContains(t, res.Details, "record_uuid")
		manifest := res.Details["receipt"].(HTTPReceiptManifest)
		x, err := fetch.(HTTPReceiptProvider).SelectHTTPReceipt(manifest.Ref)
		require.NoError(t, err)
		require.Equal(t, evidence.StateComplete, x.RequestState)
	}
}

type untracedWebTransport func(*http.Request) (*http.Response, error)

func (f untracedWebTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWebHTTPFetchMissingSentCaptureDoesNotFabricatePair(t *testing.T) {
	sink := &recordingSink{}
	fetch := &webFetchTool{captureSink: sink, captureProject: "proj", client: &http.Client{Transport: untracedWebTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{Request: r, StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader("returned")), ContentLength: 8}, nil
	})}}
	res, err := fetch.Execute(context.Background(), map[string]any{"url": "http://example.invalid/", "method": "POST", "body": "not certified"}, nil)
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Contains(t, res.Content, "returned")
	require.Empty(t, sink.records)
	require.Equal(t, false, res.Details["persisted"])
	manifest := res.Details["receipt"].(HTTPReceiptManifest)
	x, err := fetch.SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Empty(t, x.Request)
	require.Equal(t, evidence.StateMissing, x.RequestState)
	require.NotEmpty(t, x.Response)
}

func TestWebHTTPFetchFailureReportsMissingCaptureAndPersistence(t *testing.T) {
	fetch := &webFetchTool{captureSink: &recordingSink{}, captureProject: "proj", client: &http.Client{Transport: untracedWebTransport(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("dial failure")
	})}}
	res, err := fetch.Execute(context.Background(), map[string]any{"url": "http://example.invalid/", "body": "intended"}, nil)
	require.NoError(t, err)
	require.True(t, res.IsError)
	require.Equal(t, false, res.Details["persisted"])
	require.Equal(t, "capture_unavailable", res.Details["persistence_status"])
	manifest := res.Details["receipt"].(HTTPReceiptManifest)
	require.False(t, manifest.Available)
	require.Equal(t, evidence.StateMissing, manifest.RequestState)
	require.Equal(t, evidence.StateMissing, manifest.ResponseState)
}

func TestWebHTTPFetchErrorRetainsPartialReceiptWithoutPersistence(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		responseState  evidence.State
	}{
		{name: "completed request without response", responseState: evidence.StateMissing},
		{name: "response body read error", response: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nprefix", responseState: evidence.StateTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read sent request: %v", err)
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer conn.Close()
				if tc.response != "" {
					if _, err := io.WriteString(conn, tc.response); err != nil {
						t.Errorf("write partial response: %v", err)
					}
				}
			}))
			defer srv.Close()
			sink := &recordingSink{}
			client := srv.Client()
			client.Timeout = 2 * time.Second
			defer client.CloseIdleConnections()
			fetch := &webFetchTool{captureSink: sink, captureProject: "proj", client: client}
			res, err := fetch.Execute(context.Background(), map[string]any{"url": srv.URL + "/partial", "method": "POST", "body": "sent"}, nil)
			require.NoError(t, err)
			require.True(t, res.IsError)
			require.Contains(t, res.Content, "request failed:")
			require.NotContains(t, res.Content, "HTTP/0")
			require.NotEmpty(t, res.Details["execution_error"])
			require.Equal(t, false, res.Details["persisted"])
			require.Equal(t, "capture_unavailable", res.Details["persistence_status"])
			require.Equal(t, false, res.Details["response_body_complete"])
			require.NotContains(t, res.Details, "record_uuid")
			require.NotContains(t, res.Details, "status") // partial status never becomes execution success
			require.Empty(t, sink.records)
			require.EqualValues(t, 1, hits.Load())
			manifest := res.Details["receipt"].(HTTPReceiptManifest)
			require.True(t, manifest.Available)
			require.Contains(t, res.Content, manifest.Ref)
			x, err := fetch.SelectHTTPReceipt(manifest.Ref)
			require.NoError(t, err)
			require.NoError(t, x.Validate())
			require.Equal(t, evidence.StateComplete, x.RequestState)
			require.Equal(t, tc.responseState, x.ResponseState)
			require.Equal(t, "sent", string(httpmsg.NewHttpRequest(x.Request).Body()))
			if tc.response == "" {
				require.Empty(t, x.Response)
				require.Zero(t, res.Details["response_body_bytes_retained"])
			} else {
				require.Equal(t, true, res.Details["response_body_omitted"])
				require.Equal(t, 6, res.Details["response_body_bytes_retained"])
				require.Equal(t, "prefix", string(httpmsg.NewHttpResponse(x.Response).Body()))
			}
		})
	}
}

func TestHTTPReceiptStoreOwnsBytesRejectsIdentityChangesAndExpiresExactRefs(t *testing.T) {
	var store HTTPReceiptStore
	x := evidence.NewExchange("http://example.invalid", "http://example.invalid/", []byte("request"), []byte("response"), evidence.ProvenanceCaptured)
	manifest, err := store.RetainHTTPReceipt(x, "http_client_message")
	require.NoError(t, err)
	require.False(t, store.HTTPReceiptAvailable(x.ID))
	_, err = store.SelectHTTPReceipt(x.ID)
	require.Error(t, err) // exact refs only, not raw exchange IDs
	x.Request[0] = 'X'
	selected, err := store.SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Equal(t, "request", string(selected.Request))
	selected.Request[0] = 'Y'
	selected, err = store.SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Equal(t, "request", string(selected.Request))
	changed := selected.Clone()
	changed.Response = []byte("changed")
	changed.ContentHash = changed.Hash()
	bad, err := store.RetainHTTPReceipt(changed, "http_client_message")
	require.Error(t, err)
	require.False(t, bad.Available)
	require.Equal(t, "identity_conflict", bad.Availability)
	for i := 0; i < httpReceiptMaxEntries; i++ {
		_, err := store.RetainHTTPReceipt(evidence.NewExchange("http://example.invalid", "", nil, nil, evidence.ProvenanceCaptured), "socket_application_bytes")
		require.NoError(t, err)
	}
	require.False(t, store.HTTPReceiptAvailable(manifest.Ref))
	expired := store.RefreshHTTPReceiptAvailability(manifest)
	require.False(t, expired.Available)
	require.Equal(t, "expired", expired.Availability)
	require.Equal(t, manifest.ContentHash, expired.ContentHash)
	_, err = store.SelectHTTPReceipt(manifest.Ref)
	require.Error(t, err)
	_, err = store.SelectHTTPReceipt("http://example.invalid/")
	require.Error(t, err) // never select by URL or invented request identity
	// Reintroducing changed content after eviction cannot retarget an old ref.
	reintroduced, err := store.RetainHTTPReceipt(changed, "http_client_message")
	require.NoError(t, err)
	require.True(t, reintroduced.Available)
	require.NotEqual(t, manifest.Ref, reintroduced.Ref)
	_, err = store.SelectHTTPReceipt(manifest.Ref)
	require.Error(t, err)
	selected, err = store.SelectHTTPReceipt(reintroduced.Ref)
	require.NoError(t, err)
	require.Equal(t, "changed", string(selected.Response))
}
