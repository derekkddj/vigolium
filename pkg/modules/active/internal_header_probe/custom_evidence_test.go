package internal_header_probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCustomEvidenceReservesFreshBaselineSamples(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(hits.Add(1)))
		if r.Header.Get("X-Test-Role") != "" {
			_, _ = fmt.Fprint(w, adminPage)
			return
		}
		_, _ = fmt.Fprint(w, homePage)
	}))
	defer srv.Close()
	rr := withACAH(modtest.Request(t, srv.URL+"/"), "X-Test-Role")
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	f := results[0]
	// Three baseline samples, one canary screen, two sends per nonempty value,
	// and one (non-diverging) empty value. Receipt retention adds no sends.
	assert.EqualValues(t, selfRounds+1+2*(len(battery())-1)+1, hits.Load())
	assert.Equal(t, ModuleSeverity, f.Info.Severity)
	assert.Equal(t, ModuleConfidence, f.Info.Confidence)
	require.True(t, f.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
	assert.Contains(t, f.Response, "X-Receipt-Seq: 5")
	assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
	assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
	baselineCount, contextCount := 0, 0
	ids := map[string]bool{}
	for _, entry := range f.Evidence {
		if !entry.Primary {
			contextCount++
		}
		if entry.Label != "fresh no-header baseline" && !strings.HasPrefix(entry.Label, "no-header stability sample") {
			continue
		}
		baselineCount++
		assert.False(t, entry.Primary)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		assert.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Receipt-Seq: %d", baselineCount))
		assert.NotContains(t, string(entry.Exchange.Request), "X-Test-Role:")
		if baselineCount == 1 {
			assert.Equal(t, evidence.RoleBaseline, entry.Role)
		} else {
			assert.Equal(t, evidence.RoleControl, entry.Role)
		}
		assert.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
	}
	assert.Equal(t, selfRounds, baselineCount)
	assert.LessOrEqual(t, contextCount, modkit.MaxEvidencePairs)
	assert.LessOrEqual(t, len(f.AdditionalEvidence), modkit.MaxEvidencePairs)
}
