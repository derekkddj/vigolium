package race_interference

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestSendProbeReceiptKeepsRedirectedFinalRequest(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" {
			http.Redirect(w, r, "/final?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		w.Header().Set("X-Probe-Receipt", "final")
		_, _ = fmt.Fprintf(w, "current=%s", r.URL.Query().Get("q"))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/search?q=seed")
	result := New().sendProbe(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), "receiptAnchor", 1)
	require.NoError(t, result.Err)
	require.NotNil(t, result.exchange)
	assert.NoError(t, result.exchange.Validate())
	assert.Equal(t, evidence.ProvenanceCaptured, result.exchange.Provenance)
	assert.Contains(t, string(result.exchange.Request), "GET /final?q=receiptAnchor1")
	assert.NotContains(t, string(result.exchange.Request), "GET /search")
	assert.Contains(t, string(result.exchange.Response), "X-Probe-Receipt: final")
	assert.Contains(t, string(result.exchange.Response), result.Body)
}
