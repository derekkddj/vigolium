package client_prototype_pollution

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

const sourceScript = `var params={};location.search.slice(1).split('&').forEach(function(pair){var k=pair.split('=')[0];params[k]=decodeURIComponent(pair.split('=')[1])});`

func TestExternalSourceEvidenceDoesNotSelectReachabilityProbe(t *testing.T) {
	const html = `<html><script src="/assets/app.js"></script></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/assets/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("X-Script-Receipt", "source")
			_, _ = fmt.Fprint(w, sourceScript)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "reachable page without matching JavaScript")
	}))
	defer srv.Close()
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/app"), "text/html", html)
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.Equal(t, output.RecordKindCandidate, result.RecordKind)
	require.False(t, result.BaselineEvidence)
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Equal(t, true, result.Metadata["page_reachable_with_probe"])
	require.Contains(t, result.Request, "GET /assets/app.js HTTP/")
	require.NotContains(t, result.Request, "__proto__")
	require.Contains(t, result.Response, "X-Script-Receipt: source")
	require.Contains(t, result.Response, sourceScript)
	require.Len(t, result.Evidence, 2)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.Equal(t, srv.URL+"/assets/app.js", primary.Exchange.URL)
	require.NoError(t, primary.Exchange.Validate())
	reachability := result.Evidence[1]
	require.False(t, reachability.Primary)
	require.Equal(t, evidence.RoleObservation, reachability.Role)
	require.Contains(t, string(reachability.Exchange.Request), "__proto__")
	require.Contains(t, string(reachability.Exchange.Response), "reachable page without matching JavaScript")
	require.NotEqual(t, primary.ExchangeID, reachability.ExchangeID)
}

func TestInlineSourceEvidenceIsBranchLocalInputAnalysis(t *testing.T) {
	html := "<html><script>" + sourceScript + "</script></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "reachability only")
	}))
	defer srv.Close()
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/app"), "text/html", html)
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].BaselineEvidence)
	require.Empty(t, results[0].Request, "executor inheritance belongs only to the input-analysis branch")
	require.Empty(t, results[0].Response)
	require.Len(t, results[0].Evidence, 1)
	for _, entry := range results[0].Evidence {
		require.False(t, entry.Primary, "reachability is never primary source proof")
		require.Equal(t, evidence.RoleObservation, entry.Role)
		require.Contains(t, string(entry.Exchange.Request), "__proto__")
		require.False(t, evidence.HasSelectedEvidence([]evidence.Entry{entry.Manifest()}), "receipt-less input fallback stays eligible despite supporting context")
	}
}

func TestInputSourceReceiptStaysPrimaryWithSupportingReachability(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		name := "captured input"
		if supplied {
			name = "supplied unknown input"
		}
		t.Run(name, func(t *testing.T) {
			var hits atomic.Int64
			html := "<html><script>" + sourceScript + "</script></html>"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "text/html")
				if r.URL.RawQuery != "" {
					w.Header().Set("X-Reachability-Proof", "not source proof")
					_, _ = fmt.Fprint(w, "reachability only; no source-bearing JavaScript")
					return
				}
				w.Header().Set("X-Input-Source", "original source")
				_, _ = fmt.Fprint(w, html)
			}))
			defer srv.Close()
			client := modtest.Requester(t)
			seed := modtest.Request(t, srv.URL+"/app")
			chain, _, err := client.Execute(seed, vhttp.Options{NoClustering: true})
			require.NoError(t, err)
			inputReceipt := vhttp.CaptureEvidence(chain)
			response := httpmsg.NewHttpResponse(append([]byte(nil), chain.FullResponseBytes()...))
			chain.Close()
			require.NotNil(t, inputReceipt)
			if supplied {
				// Compatibility input can carry honest unknown fidelity. Selection
				// must preserve it and its stamp, not manufacture captured states.
				inputReceipt.Provenance = evidence.ProvenanceSupplied
				inputReceipt.RequestState = evidence.StateUnknown
				inputReceipt.ResponseState = evidence.StateUnknown
				inputReceipt.ContentHash = inputReceipt.Hash()
			}
			require.NoError(t, inputReceipt.Validate())
			ctx := httpmsg.NewHttpRequestResponse(seed.Request(), response).WithEvidence(inputReceipt)
			results, err := New().ScanPerRequest(ctx, client, nil)
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, int64(2), hits.Load(), "source input acquisition plus the existing reachability probe only")
			result := results[0]
			require.Equal(t, output.RecordKindCandidate, result.RecordKind)
			require.Equal(t, output.EvidenceGradeCandidate, result.EvidenceGrade)
			require.False(t, result.BaselineEvidence, "an explicitly selected source receipt needs no input inheritance")
			require.Equal(t, "selected", result.EvidenceStatus)
			require.Equal(t, true, result.Metadata["page_reachable_with_probe"])
			require.Equal(t, false, result.Metadata["runtime_pollution_proven"])
			require.Len(t, result.Evidence, 2)
			primary, supporting := result.Evidence[0], result.Evidence[1]
			require.True(t, primary.Primary)
			require.Equal(t, evidence.RoleObservation, primary.Role)
			require.Equal(t, inputReceipt.ID, primary.ExchangeID)
			require.Equal(t, inputReceipt, primary.Exchange)
			require.Equal(t, string(inputReceipt.Request), result.Request)
			require.Equal(t, string(inputReceipt.Response), result.Response)
			require.Contains(t, result.Response, sourceScript)
			require.NotContains(t, result.Request, "__proto__")
			require.NotContains(t, result.Response, "X-Reachability-Proof:")
			require.False(t, supporting.Primary)
			require.Equal(t, evidence.RoleObservation, supporting.Role)
			require.NotEqual(t, primary.ExchangeID, supporting.ExchangeID)
			require.Contains(t, string(supporting.Exchange.Request), "__proto__")
			require.Contains(t, string(supporting.Exchange.Response), "X-Reachability-Proof: not source proof")
			require.NoError(t, supporting.Exchange.Validate())
			// Core/storage tests are parent-owned. The module already exposes the
			// required role/identity distinction in both hydrated and raw manifests.
			manifest := []evidence.Entry{primary.Manifest(), supporting.Manifest()}
			require.True(t, evidence.HasSelectedEvidence(manifest))
			require.True(t, manifest[0].Primary)
			require.Equal(t, evidence.RoleObservation, manifest[0].Role)
			require.Equal(t, inputReceipt.ID, manifest[0].ExchangeID)
			require.False(t, manifest[1].Primary)
			require.Equal(t, evidence.RoleObservation, manifest[1].Role)
			require.Nil(t, manifest[0].Exchange)
			require.Nil(t, manifest[1].Exchange)
			require.NoError(t, ctx.Evidence().Validate(), "selected copies must not change the input receipt")
		})
	}
}

func TestFetchedInlineSourceSelectsCapturedBaselineReceipt(t *testing.T) {
	html := "<html><script>" + sourceScript + "</script></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, html)
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/app")
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.False(t, result.BaselineEvidence, "a helper-fetched baseline is not the triggering input")
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Contains(t, result.Request, "GET /app HTTP/")
	require.NotContains(t, result.Request, "__proto__")
	require.Contains(t, result.Response, sourceScript)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.Equal(t, evidence.StateComplete, primary.Exchange.RequestState)
	require.Equal(t, evidence.StateComplete, primary.Exchange.ResponseState)
	require.NoError(t, primary.Exchange.Validate())
}
