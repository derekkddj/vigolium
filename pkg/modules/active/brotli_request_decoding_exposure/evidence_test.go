package brotli_request_decoding_exposure

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestBrotliSelectsDecodedProbeAndRetainsEveryGateControlAndRound(t *testing.T) {
	var hits atomic.Int64
	app := nodeApp(true, true)
	srv := modtest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Sequence", fmt.Sprint(hits.Add(1)))
		app.ServeHTTP(w, r)
	}))
	res, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), modtest.ScanCtxWithTech(srv.URL, "nestjs"))
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, int64(10), hits.Load(), "selection must preserve the existing gate's request count")
	result := res[0]
	require.Equal(t, output.RecordKindCandidate, result.RecordKind)
	require.False(t, result.BaselineEvidence)
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Len(t, result.Evidence, 10, "all ten small gate receipts are relevant and fit the context bound")
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleAttack, primary.Role)
	require.Contains(t, result.Request, "Content-Encoding: br")
	require.Contains(t, result.Response, "X-Receipt-Sequence: 3")
	require.NotContains(t, result.Response, "X-Receipt-Sequence: 10")
	require.Equal(t, string(primary.Exchange.Request), result.Request)
	require.Equal(t, string(primary.Exchange.Response), result.Response)
	confirmations, controls := 0, 0
	ids := map[string]bool{}
	for i, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
		require.Equal(t, i == 0, entry.Primary)
		switch entry.Role {
		case evidence.RoleConfirmation:
			confirmations++
		case evidence.RoleControl:
			controls++
		}
	}
	require.Equal(t, 3, confirmations)
	require.Equal(t, 6, controls)
}
