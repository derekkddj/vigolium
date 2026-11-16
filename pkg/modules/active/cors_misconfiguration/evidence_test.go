package cors_misconfiguration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestCORSRetainsMatchedAndConfirmationExchanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probe  corsProbe
		origin string
	}{
		{"reflection", probes[0], "https://evil.example.com"},
		{"fixed null", probes[1], "null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				origin := r.Header.Get("Origin")
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprintf(w, "captured response for %s", origin)
			}))
			defer srv.Close()
			baseline := modtest.Request(t, srv.URL)
			result, err := New().runProbe(baseline, modtest.Requester(t), tc.probe, tc.origin)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Contains(t, result.Request, "Origin: "+tc.origin)
			require.Contains(t, result.Response, "captured response for "+tc.origin)
			require.Contains(t, result.Response, "Access-Control-Allow-Origin: "+tc.origin)
			require.Equal(t, "selected", result.EvidenceStatus)
			require.False(t, result.BaselineEvidence)
			require.Len(t, result.Evidence, len(result.AdditionalEvidence)+1)
			primary := result.Evidence[0]
			require.True(t, primary.Primary)
			require.Equal(t, evidence.RoleAttack, primary.Role)
			require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
			require.Equal(t, result.Request, string(primary.Exchange.Request))
			require.Equal(t, result.Response, string(primary.Exchange.Response))
			require.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
			require.Equal(t, evidence.ProvenanceSupplied, result.Evidence[1].Exchange.Provenance)
			ids := map[string]bool{primary.ExchangeID: true}
			for _, entry := range result.Evidence[2:] {
				require.NoError(t, entry.Exchange.Validate())
				require.False(t, entry.Primary)
				require.Equal(t, evidence.RoleConfirmation, entry.Role)
				require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
				require.False(t, ids[entry.ExchangeID], "same-Origin replays have distinct execution receipts")
				ids[entry.ExchangeID] = true
			}
			// A later request must not substitute a confirmation response for
			// the primary response, nor the unmodified baseline for proof.
			require.NotEqual(t, modkit.CtxResponseRaw(baseline), result.Response)
			require.GreaterOrEqual(t, len(result.AdditionalEvidence), 2)
			base := output.ParseEvidence(result.AdditionalEvidence[0])
			require.Equal(t, "baseline (unmodified Origin)", base.Label)
			require.Equal(t, modkit.CtxRequestRaw(baseline), base.Request)
			require.Equal(t, modkit.CtxResponseRaw(baseline), base.Response)
			for _, entry := range result.AdditionalEvidence[1:] {
				pair := output.ParseEvidence(entry)
				require.Contains(t, pair.Label, "confirmation")
				require.NotEmpty(t, pair.Request)
				require.NotEmpty(t, pair.Response)
				if tc.name == "reflection" {
					require.NotContains(t, pair.Request, "Origin: "+tc.origin+"\r\n")
				}
			}
		})
	}
}

func TestCORSRetainsSelectiveNegativeControl(t *testing.T) {
	probe := probes[len(probes)-2] // unescaped-dot selective rule
	origin := "https://examplexcom"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent := r.Header.Get("Origin")
		if sent == origin {
			w.Header().Set("Access-Control-Allow-Origin", sent)
		}
		_, _ = fmt.Fprintf(w, "control-aware response for %s", sent)
	}))
	defer srv.Close()
	result, err := New().runProbe(modtest.Request(t, srv.URL), modtest.Requester(t), probe, origin)
	require.NoError(t, err)
	require.NotNil(t, result)
	var found bool
	for _, entry := range result.AdditionalEvidence {
		pair := output.ParseEvidence(entry)
		if strings.Contains(pair.Label, "negative control") {
			found = true
			require.Contains(t, pair.Request, "Origin: https://")
			require.NotContains(t, pair.Request, origin)
			require.Contains(t, pair.Response, "control-aware response for https://")
			require.NotContains(t, pair.Response, "Access-Control-Allow-Origin:")
		}
	}
	require.True(t, found, "the actual non-reflecting control response must be retained")
	require.Len(t, result.Evidence, 4)
	require.Equal(t, evidence.RoleControl, result.Evidence[2].Role)
	require.False(t, result.Evidence[2].Primary)
	require.Equal(t, evidence.ProvenanceCaptured, result.Evidence[2].Exchange.Provenance)
}

func TestCORSReceiptSelectsRedirectedRequestBeforeClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/original" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		_, _ = fmt.Fprint(w, "final redirected response")
	}))
	defer srv.Close()
	result, err := New().runProbe(modtest.Request(t, srv.URL+"/original"), modtest.Requester(t), probes[1], "null")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Contains(t, result.Request, "GET /final HTTP/")
	require.NotContains(t, result.Request, "GET /original HTTP/")
	require.Equal(t, srv.URL+"/final", result.Evidence[0].Exchange.URL)
	require.Contains(t, result.Response, "final redirected response")
	require.NoError(t, result.Evidence[0].Exchange.Validate())
}
