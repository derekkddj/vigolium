package http

import (
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestClusterLeaderPreservesActualPostReceiptBeforeCacheNormalization(t *testing.T) {
	payload := []byte("{\"method\":\"call\",\"binary\":\"\x00\xff\"}")
	var hits atomic.Int32
	seen := make(chan []byte, 1)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		seen <- body
		_, _ = io.WriteString(w, "actual response")
	}))
	defer srv.Close()
	client := newTestRequester(t)
	rr, err := httpmsg.GetRawRequestFromURL(srv.URL + "/rpc")
	require.NoError(t, err)
	raw, err := httpmsg.SetMethod(rr.Request().Raw(), "POST")
	require.NoError(t, err)
	raw, err = httpmsg.SetBodyString(raw, string(payload))
	require.NoError(t, err)
	service := rr.Service()
	rr, err = httpmsg.ParseRawRequest(string(raw))
	require.NoError(t, err)
	rr = rr.WithService(service)
	// The body starts without a redirect; this used to return a normalized
	// cache view even to the sender, losing GetBody and the submitted bytes.
	first, _, err := client.Execute(rr, Options{})
	require.NoError(t, err)
	x := CaptureEvidence(first)
	// The cache already owns its snapshot; mutations of the sender's live
	// request and later cache views must not poison any other observation.
	first.Request().Header.Set("X-Mutated", "leader")
	first.Request().URL.Path = "/not-the-sent-path"
	first.Close()
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	parsed, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	require.Equal(t, payload, parsed.Request().Body())
	require.Equal(t, payload, <-seen)
	second, _, err := client.Execute(rr, Options{})
	require.NoError(t, err)
	cached := CaptureEvidence(second)
	require.Equal(t, "/rpc", second.Request().URL.Path)
	require.Empty(t, second.Request().Header.Get("X-Mutated"))
	second.Request().Header.Set("X-Mutated", "cache-view")
	second.Request().URL.Path = "/also-not-sent"
	second.Close()
	third, _, err := client.Execute(rr, Options{})
	require.NoError(t, err)
	require.Equal(t, "/rpc", third.Request().URL.Path)
	require.Empty(t, third.Request().Header.Get("X-Mutated"))
	third.Close()
	require.NoError(t, cached.Validate())
	require.Equal(t, evidence.ProvenanceCached, cached.Provenance)
	require.NotEqual(t, x.ID, cached.ID)
	require.Equal(t, evidence.StateUnknown, cached.RequestState)
	require.Contains(t, string(x.Request), strings.TrimPrefix(srv.URL, "http://"))
	require.EqualValues(t, 1, hits.Load())
}
