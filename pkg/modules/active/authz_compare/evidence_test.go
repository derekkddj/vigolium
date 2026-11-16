package authz_compare

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCompareEvidenceSelectsFinalSessionRequest(t *testing.T) {
	var sawSessionCookie atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/account":
			http.SetCookie(w, &http.Cookie{Name: "compare_sid", Value: "session-b", Path: "/"})
			http.Redirect(w, r, "/final/account", http.StatusFound)
		case "/final/account":
			cookie, err := r.Cookie("compare_sid")
			if err == nil && cookie.Value == "session-b" && r.Header.Get(sessionMarkerHeader) == "session-b" {
				sawSessionCookie.Store(true)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Receipt", "compare-final")
			_, _ = fmt.Fprint(w, primaryBody)
		default:
			_, _ = fmt.Fprint(w, "unrelated later response")
		}
	}))
	defer srv.Close()

	compareClient := requesterWithMarker(t, "session-b")
	m := New()
	m.SetCompareClients([]*vhttp.Requester{compareClient}, []string{"session-b"})
	baseline := modtest.Response(modtest.Request(t, srv.URL+"/api/account"), "application/json", primaryBody)
	results, err := m.ScanPerRequest(baseline, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, sawSessionCookie.Load())
	result := results[0]
	require.False(t, result.BaselineEvidence)
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Contains(t, result.Request, "GET /final/account HTTP/")
	require.Contains(t, result.Request, sessionMarkerHeader+": session-b")
	require.Contains(t, result.Request, "compare_sid=session-b")
	require.NotContains(t, result.Request, "GET /api/account HTTP/")
	require.Contains(t, result.Response, "X-Receipt: compare-final")
	require.Contains(t, result.Response, primaryBody)
	require.Len(t, result.Evidence, 2)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleAttack, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.Equal(t, srv.URL+"/final/account", primary.Exchange.URL)
	require.Equal(t, result.Request, string(primary.Exchange.Request))
	require.Equal(t, result.Response, string(primary.Exchange.Response))
	require.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
	require.NotContains(t, string(result.Evidence[1].Exchange.Request), "compare_sid=")

	// Exercise the response pool after the selected chain was closed. Neither
	// baseline intent nor a later same-session request may replace the proof.
	later, _, err := compareClient.Execute(modtest.Request(t, srv.URL+"/unrelated"), vhttp.Options{NoClustering: true})
	require.NoError(t, err)
	later.Close()
	require.NoError(t, primary.Exchange.Validate())
	require.Contains(t, result.Response, primaryBody)
	require.NotContains(t, result.Response, "unrelated later response")
}

func TestFetchedPrimaryBaselineSelectsItsOwnRedirectedReceipt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/account" {
			sid := "primary"
			if r.Header.Get(sessionMarkerHeader) == "session-b" {
				sid = "comparison"
			}
			http.SetCookie(w, &http.Cookie{Name: "baseline_sid", Value: sid, Path: "/"})
			http.Redirect(w, r, "/final/account", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Baseline-Proof", "final principal response")
		_, _ = fmt.Fprint(w, primaryBody)
	}))
	defer srv.Close()
	m := New()
	m.SetCompareClients([]*vhttp.Requester{requesterWithMarker(t, "session-b")}, []string{"session-b"})
	results, err := m.ScanPerRequest(modtest.Request(t, srv.URL+"/api/account"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Evidence, 2)
	baseline := results[0].Evidence[1]
	require.False(t, baseline.Primary)
	require.Equal(t, evidence.RoleBaseline, baseline.Role)
	require.Equal(t, evidence.ProvenanceCaptured, baseline.Exchange.Provenance)
	require.Equal(t, srv.URL+"/final/account", baseline.Exchange.URL)
	require.Contains(t, string(baseline.Exchange.Request), "GET /final/account HTTP/")
	require.Contains(t, string(baseline.Exchange.Request), "baseline_sid=primary")
	require.NotContains(t, string(baseline.Exchange.Request), sessionMarkerHeader+": session-b")
	require.Contains(t, string(baseline.Exchange.Response), "X-Baseline-Proof: final principal response")
	require.NoError(t, baseline.Exchange.Validate())
}
