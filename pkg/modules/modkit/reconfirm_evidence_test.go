package modkit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestBodyDifferentialSelectedReceiptsAreRawOwnedAndBounded(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("Set-Cookie", fmt.Sprintf("sample=%d; Path=/", n))
		w.Header().Set("X-Request-ID", fmt.Sprintf("sample-%d", n))
		if r.URL.Path == "/payload" {
			_, _ = w.Write([]byte("clean page plus introduced marker 49"))
		} else {
			_, _ = w.Write([]byte("clean page"))
		}
	}))
	defer srv.Close()
	payload := modtest.Request(t, srv.URL+"/payload")
	clean := modtest.Request(t, srv.URL+"/clean")
	collector := modkit.NewEvidenceCollector()
	result := modkit.ConfirmBodyDifferential(modtest.Requester(t), clean.Service(), payload.Request().Raw(), clean.Request().Raw(), "", 0,
		modkit.ReconfirmConfig{PayloadRounds: 12, NoRedirects: true, Evidence: collector})
	require.True(t, result.Ran)
	require.True(t, result.Confirmed)
	require.Equal(t, int64(13), hits.Load(), "receipt cap must not reduce comparison rounds")
	require.Len(t, result.Evidence, 3, "first two replays plus the fresh control")
	require.Len(t, collector.Evidence(), 3)
	ids := make(map[string]bool)
	for i, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		require.Equal(t, i == 0, entry.Primary)
		require.False(t, ids[entry.ExchangeID], "same request bytes still have distinct execution identities")
		ids[entry.ExchangeID] = true
		raw := string(entry.Exchange.Response)
		require.Contains(t, raw, "HTTP/1.1 200 OK\r\n")
		require.Contains(t, raw, "Set-Cookie: sample=")
		require.Contains(t, raw, "X-Request-Id: sample-")
		if i < 2 {
			require.Equal(t, evidence.RoleConfirmation, entry.Role)
			require.Contains(t, string(entry.Exchange.Request), "GET /payload HTTP/1.1")
			require.True(t, strings.HasSuffix(raw, "clean page plus introduced marker 49"))
		} else {
			require.Equal(t, evidence.RoleControl, entry.Role)
			require.Contains(t, string(entry.Exchange.Request), "GET /clean HTTP/1.1")
		}
	}
	before := string(collector.Evidence()[0].Exchange.Response)
	result.Evidence[0].Exchange.Response[0] = 'X'
	require.Equal(t, before, string(collector.Evidence()[0].Exchange.Response), "returned entries must not alias the collector")
}

func TestBodyDifferentialInconclusiveRetainsCompletedReplays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("payload marker"))
	}))
	defer srv.Close()
	payload := modtest.Request(t, srv.URL+"/payload")
	result := modkit.ConfirmBodyDifferential(modtest.Requester(t), payload.Service(), payload.Request().Raw(), []byte("invalid request"), "", 0,
		modkit.ReconfirmConfig{NoRedirects: true})
	require.False(t, result.Ran)
	require.False(t, result.Confirmed)
	require.Len(t, result.Evidence, 2)
	require.True(t, result.Evidence[0].Primary)
	for _, entry := range result.Evidence {
		require.Equal(t, evidence.RoleConfirmation, entry.Role)
		require.NoError(t, entry.Exchange.Validate())
		require.Contains(t, string(entry.Exchange.Response), "payload marker")
	}
}

func TestBodyDifferentialPayloadFailureRetainsFirstCompletedReplay(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			_, _ = w.Write([]byte("first completed payload"))
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	payload := modtest.Request(t, srv.URL+"/payload")
	clean := modtest.Request(t, srv.URL+"/clean")
	result := modkit.ConfirmBodyDifferential(modtest.Requester(t), clean.Service(), payload.Request().Raw(), clean.Request().Raw(), "", 0,
		modkit.ReconfirmConfig{NoRedirects: true})
	require.False(t, result.Ran)
	require.Len(t, result.Evidence, 1)
	require.Contains(t, string(result.Evidence[0].Exchange.Response), "first completed payload")
}

func TestReconfirmFindingPreservesCachedBaselineIdentityAndVerdict(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/payload" {
			_, _ = w.Write([]byte("marker already in baseline"))
		} else {
			_, _ = w.Write([]byte("clean page"))
		}
	}))
	defer srv.Close()
	item := modtest.Response(modtest.Request(t, srv.URL+"/clean"), "text/plain", "marker already in baseline")
	inputReceipt := evidence.NewExchange(srv.URL, srv.URL+"/clean", item.Request().Raw(), item.Response().Raw(), evidence.ProvenanceLegacy)
	item = item.WithEvidence(inputReceipt)
	payload := modtest.Request(t, srv.URL+"/payload")
	result := modkit.ReconfirmFinding(modtest.Requester(t), item, string(payload.Request().Raw()))
	require.True(t, result.Ran)
	require.False(t, result.Confirmed)
	require.Equal(t, int64(3), hits.Load(), "the cached baseline must not trigger a send")
	require.Len(t, result.Evidence, 4)
	baseline := result.Evidence[3]
	require.Equal(t, evidence.RoleBaseline, baseline.Role)
	require.False(t, baseline.Primary)
	require.Equal(t, inputReceipt.ID, baseline.ExchangeID)
	require.Equal(t, inputReceipt.Provenance, baseline.Exchange.Provenance)
	require.Equal(t, inputReceipt.RequestState, baseline.Exchange.RequestState)
	require.Equal(t, inputReceipt.ResponseState, baseline.Exchange.ResponseState)
	require.Equal(t, inputReceipt.Response, baseline.Exchange.Response)
	baseline.Exchange.Response[0] = 'X'
	require.Equal(t, inputReceipt.Response, item.Evidence().Response)
}

func TestCrossIDReceiptsPreserveFullResponseButComparisonUsesBody(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Sample", fmt.Sprint(hits.Add(1)))
		_, _ = w.Write([]byte("stable original resource body"))
	}))
	defer srv.Close()
	original := modtest.Request(t, srv.URL+"/original")
	collector := modkit.NewEvidenceCollector()
	verdict := modkit.ConfirmCrossIDDifferential(modtest.Requester(t), original.Service(), original.Request().Raw(), "stable original resource body", 200,
		"different resource data", modkit.CrossIDConfig{SelfRounds: 12, Evidence: collector})
	require.True(t, verdict.Ran)
	require.True(t, verdict.Trustworthy)
	require.Equal(t, 1.0, verdict.SelfRatio, "changing headers must not leak into the body-only metric")
	require.Equal(t, int64(12), hits.Load())
	require.Len(t, collector.Evidence(), 2)
	for _, entry := range collector.Evidence() {
		require.Equal(t, evidence.RoleConfirmation, entry.Role)
		require.False(t, entry.Primary)
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.NoError(t, entry.Exchange.Validate())
		require.Contains(t, string(entry.Exchange.Response), "HTTP/1.1 200 OK\r\n")
		require.Contains(t, string(entry.Exchange.Response), "X-Sample:")
		require.True(t, strings.HasSuffix(string(entry.Exchange.Response), "stable original resource body"))
	}
}

func TestBodyDifferentialRedirectSelectsFinalExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/payload":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Header().Set("X-Final", "selected")
			_, _ = w.Write([]byte("introduced marker"))
		default:
			_, _ = w.Write([]byte("clean page"))
		}
	}))
	defer srv.Close()
	payload := modtest.Request(t, srv.URL+"/payload")
	clean := modtest.Request(t, srv.URL+"/clean")
	result := modkit.ConfirmBodyDifferential(modtest.Requester(t), clean.Service(), payload.Request().Raw(), clean.Request().Raw(), "", 0, modkit.ReconfirmConfig{})
	require.True(t, result.Ran)
	require.True(t, result.Confirmed)
	require.Len(t, result.Evidence, 3)
	for _, entry := range result.Evidence[:2] {
		require.Equal(t, srv.URL+"/final", entry.Exchange.URL)
		require.Contains(t, string(entry.Exchange.Request), "GET /final ")
		require.Contains(t, string(entry.Exchange.Response), "X-Final: selected")
		require.Contains(t, string(entry.Exchange.Response), "introduced marker")
	}
}
