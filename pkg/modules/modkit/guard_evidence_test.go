package modkit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestCachedDecoyProofIsFullOwnedAndDoesNotReplay(t *testing.T) {
	var hits atomic.Int64
	body := strings.Repeat("not found decoy body ", 20000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Control-Path", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	ctx, client, sc := modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), &modkit.ScanContext{}
	first := modkit.NewEvidenceCollector()
	status, comparisonBody, ok := modkit.DecoyFileBaselineWithEvidence(sc, ctx, client, "/orders/run.log", first)
	require.True(t, ok)
	require.Equal(t, 404, status)
	require.Less(t, len(comparisonBody), len(body), "comparison cap remains independent of captured proof")
	x := first.Evidence()[0].Exchange
	require.NoError(t, x.Validate())
	require.Contains(t, string(x.Request), "/orders/vigolium-decoy-")
	require.Contains(t, string(x.Request), ".log HTTP/")
	require.Contains(t, string(x.Response), "X-Control-Path: /orders/vigolium-decoy-")
	require.True(t, strings.HasSuffix(string(x.Response), body))
	require.Equal(t, evidence.StateComplete, x.ResponseState)
	x.Response[0] = 'X'
	second := modkit.NewEvidenceCollector()
	_, _, ok = modkit.DecoyFileBaselineWithEvidence(sc, ctx, client, "/orders/other.log", second)
	require.True(t, ok)
	require.Equal(t, int64(1), hits.Load())
	require.Equal(t, x.ID, second.Evidence()[0].ExchangeID)
	require.NoError(t, second.Evidence()[0].Exchange.Validate())
}

func TestMultiRoundDecoyProofCapDoesNotChangeRounds(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Round", fmt.Sprint(hits.Add(1)))
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "negative control")
	}))
	defer srv.Close()
	proof := modkit.NewEvidenceCollector()
	catchAll := modkit.MultiRoundExtDecoyCatchAllWithEvidence(modtest.Request(t, srv.URL+"/"), modtest.Requester(t),
		"/private/config.json", "candidate", 200, 12, nil, proof)
	require.False(t, catchAll)
	require.Equal(t, int64(12), hits.Load(), "selection cap must not alter existing comparison requests")
	require.Len(t, proof.Evidence(), modkit.MaxEvidencePairs)
	ids := map[string]bool{}
	for i, entry := range proof.Evidence() {
		require.False(t, entry.Primary)
		require.Equal(t, evidence.RoleControl, entry.Role)
		require.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
		require.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Round: %d", i+1))
		require.NoError(t, entry.Exchange.Validate())
	}
}

func TestSoft404ProofUsesCachedExecutionAndAuthGateAddsNoTraffic(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, strings.Repeat("wildcard sample ", 400))
	}))
	defer srv.Close()
	ctx, client, sc := modtest.Request(t, srv.URL+"/candidate"), modtest.Requester(t), &modkit.ScanContext{}
	first, second := modkit.NewEvidenceCollector(), modkit.NewEvidenceCollector()
	require.True(t, modkit.ConfirmNotSoft404WithEvidence(sc, client, ctx, 200, []byte("actual candidate"), "", first))
	require.True(t, modkit.ConfirmNotSoft404WithEvidence(sc, client, ctx, 200, []byte("other candidate"), "", second))
	require.Equal(t, int64(1), hits.Load())
	require.Len(t, first.Evidence(), 1)
	require.Equal(t, first.Evidence()[0].ExchangeID, second.Evidence()[0].ExchangeID)
	require.Equal(t, evidence.RoleControl, first.Evidence()[0].Role)
	require.NotContains(t, string(first.Evidence()[0].Exchange.Request), "GET /candidate HTTP/")
	require.Greater(t, len(first.Evidence()[0].Exchange.Response), 2000)
	auth := modkit.NewEvidenceCollector()
	require.False(t, modkit.ConfirmNotSoft404WithEvidence(sc, client, ctx, 302, nil, "/login", auth))
	require.Empty(t, auth.Evidence())
	require.Equal(t, int64(1), hits.Load())
}

func TestErrorSignatureReplayAndOriginalControlKeepTheirOwnReceipts(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Error-Round", fmt.Sprint(hits.Add(1)))
		if r.URL.Query().Get("q") == "attack" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, "SQL query syntax error")
			return
		}
		_, _ = fmt.Fprint(w, "clean original control")
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL+"/?q=clean"), modtest.Requester(t)
	ip := modtest.InsertionPoint(t, ctx, "q")
	proof := modkit.NewEvidenceCollector()
	require.True(t, modkit.ConfirmMatchReproducesWithEvidence(ctx, ip, client, ip.BuildRequest([]byte("attack")), regexp.MustCompile("SQL query syntax error"), proof))
	require.Equal(t, int64(2), hits.Load())
	entries := proof.Evidence()
	require.Len(t, entries, 2)
	require.Equal(t, evidence.RoleConfirmation, entries[0].Role)
	require.Equal(t, evidence.RoleControl, entries[1].Role)
	require.Contains(t, string(entries[0].Exchange.Request), "q=attack")
	require.Contains(t, string(entries[1].Exchange.Request), "q=clean")
	require.Contains(t, string(entries[0].Exchange.Response), "X-Error-Round: 1")
	require.Contains(t, string(entries[1].Exchange.Response), "X-Error-Round: 2")
	for _, entry := range entries {
		require.False(t, entry.Primary)
		require.NoError(t, entry.Exchange.Validate())
	}
}

func TestEndpointStabilityProofReusesAllActualSamplesWithoutNewRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Stability-Round", fmt.Sprint(hits.Add(1)))
		_, _ = fmt.Fprint(w, "stable unmodified body")
	}))
	defer srv.Close()
	ctx, client, sc := modtest.Request(t, srv.URL+"/original"), modtest.Requester(t), &modkit.ScanContext{}
	first := modkit.NewEvidenceCollector()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, ctx, client, first))
	require.Equal(t, int64(modkit.EndpointStabilitySamples), hits.Load())
	require.Len(t, first.Evidence(), modkit.EndpointStabilitySamples)
	second := modkit.NewEvidenceCollector()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, ctx, client, second))
	require.Equal(t, int64(modkit.EndpointStabilitySamples), hits.Load())
	for i, entry := range first.Evidence() {
		require.False(t, entry.Primary)
		require.Equal(t, evidence.RoleControl, entry.Role)
		require.Equal(t, entry.ExchangeID, second.Evidence()[i].ExchangeID)
		require.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Stability-Round: %d", i+1))
		require.NoError(t, entry.Exchange.Validate())
	}
}

func TestPathGuardsSelectOnlyTheirExecutedControls(t *testing.T) {
	cases := []struct {
		name string
		want int64
		run  func(*modkit.ScanContext, *httpmsg.HttpRequestResponse, *vhttp.Requester, *modkit.EvidenceCollector) bool
	}{
		{"sibling", 1, func(sc *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, c *vhttp.Requester, proof *modkit.EvidenceCollector) bool {
			return modkit.SiblingPathCatchAllWithEvidence(sc, ctx, c, "/admin/docs", func(string) bool { return true }, proof)
		}},
		{"random directory", 1, func(sc *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, c *vhttp.Requester, proof *modkit.EvidenceCollector) bool {
			return modkit.RandomDirCatchAllWithEvidence(sc, ctx, c, func(string) bool { return true }, proof)
		}},
		{"root page", 1, func(sc *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, c *vhttp.Requester, proof *modkit.EvidenceCollector) bool {
			return modkit.RootPageCatchAllWithEvidence(sc, ctx, c, func(string) bool { return true }, proof)
		}},
		{"shell", 2, func(sc *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, c *vhttp.Requester, proof *modkit.EvidenceCollector) bool {
			return modkit.ResemblesCatchAllShellWithEvidence(sc, ctx, c, "candidate docs", proof)
		}},
		{"slug", 1, func(_ *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, c *vhttp.Requester, proof *modkit.EvidenceCollector) bool {
			return modkit.SlugReflectionFPWithEvidence(ctx, c, "/admin/docs", []string{"docs"}, proof)
		}},
		{"root sibling skipped", 0, func(sc *modkit.ScanContext, ctx *httpmsg.HttpRequestResponse, c *vhttp.Requester, proof *modkit.EvidenceCollector) bool {
			return modkit.SiblingServesAnyMarkerWithEvidence(sc, ctx, c, "/docs", []string{"docs"}, proof)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("X-Control-Path", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, "not found")
			}))
			defer srv.Close()
			proof := modkit.NewEvidenceCollector()
			require.False(t, tc.run(&modkit.ScanContext{}, modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), proof))
			require.Equal(t, tc.want, hits.Load())
			require.Len(t, proof.Evidence(), int(tc.want))
			for _, entry := range proof.Evidence() {
				require.False(t, entry.Primary)
				require.Equal(t, evidence.RoleControl, entry.Role)
				require.NoError(t, entry.Exchange.Validate())
				require.Contains(t, string(entry.Exchange.Response), "X-Control-Path:")
			}
		})
	}
}

func TestFetchPathProofSelectsFinalRedirectedConfirmation(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/repeat" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("X-Confirmation", "final")
		_, _ = fmt.Fprint(w, "confirmed resource")
	}))
	defer srv.Close()
	proof := modkit.NewEvidenceCollector()
	status, body, ok := modkit.FetchPathWithEvidence(modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), "/repeat", proof)
	require.True(t, ok)
	require.Equal(t, 200, status)
	require.Equal(t, "confirmed resource", body)
	require.Equal(t, int64(2), hits.Load())
	require.Len(t, proof.Evidence(), 1)
	entry := proof.Evidence()[0]
	require.Equal(t, evidence.RoleConfirmation, entry.Role)
	require.False(t, entry.Primary)
	require.Contains(t, string(entry.Exchange.Request), "GET /final HTTP/")
	require.Contains(t, string(entry.Exchange.Response), "X-Confirmation: final")
	require.NoError(t, entry.Exchange.Validate())
}

func TestAppendGuardProofKeepsPrimaryAndBoundedContext(t *testing.T) {
	result := &output.ResultEvent{}
	primary := collapseReceipt("/attack")
	modkit.SetPrimaryEvidence(result, primary, evidence.RoleAttack, "primary attack")
	proof := modkit.NewEvidenceCollector()
	for i := 0; i < 20; i++ {
		proof.AddExchange(collapseReceipt(fmt.Sprintf("/control-%d", i)), evidence.RoleControl, "guard control")
	}
	modkit.AppendEvidence(result, proof)
	modkit.AppendEvidence(result, proof)
	require.Len(t, result.Evidence, modkit.MaxEvidencePairs+1)
	require.Len(t, result.AdditionalEvidence, modkit.MaxEvidencePairs)
	require.True(t, result.Evidence[0].Primary)
	require.Equal(t, primary.ID, result.Evidence[0].ExchangeID)
	require.Equal(t, string(primary.Request), result.Request)
	require.Equal(t, string(primary.Response), result.Response)
	for _, entry := range result.Evidence[1:] {
		require.False(t, entry.Primary)
	}
}
