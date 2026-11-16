package nextjs_data_leakage

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCustomEvidenceKeepsDataReproductionAndRejectedDecoy(t *testing.T) {
	var hits atomic.Int32
	dataPath := fmt.Sprintf("/_next/data/%s/dashboard.json", nextBuildID)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(hits.Add(1)))
		if r.URL.Path != dataPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("no such data route"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pageProps":{"secret":"data"}}`))
	}))
	defer srv.Close()
	rr := responseWith(modtest.Request(t, srv.URL+"/dashboard"), 401, "Unauthorized", nil, nextBody)
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.EqualValues(t, 3, hits.Load())
	f := results[0]
	assert.Equal(t, ModuleSeverity, f.Info.Severity)
	assert.Equal(t, ModuleConfidence, f.Info.Confidence)
	require.Len(t, f.Evidence, 3)
	ids := map[string]bool{}
	for i, entry := range f.Evidence {
		assert.Equal(t, i == 0, entry.Primary)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		assert.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Receipt-Seq: %d", i+1))
		assert.NotContains(t, string(entry.Exchange.Request), "Cookie:")
		assert.NotContains(t, string(entry.Exchange.Request), "Authorization:")
		assert.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
	}
	assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
	assert.Equal(t, evidence.RoleConfirmation, f.Evidence[1].Role)
	assert.Equal(t, evidence.RoleControl, f.Evidence[2].Role)
	assert.Contains(t, string(f.Evidence[2].Exchange.Request), catchAllProbeSlug)
	assert.Contains(t, string(f.Evidence[2].Exchange.Response), "404 Not Found")
	assert.Contains(t, f.Response, "X-Receipt-Seq: 1")
	assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
	assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
}
