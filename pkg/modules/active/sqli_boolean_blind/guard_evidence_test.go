package sqli_boolean_blind

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

func TestBooleanLateGuardReservesControlsWithoutLosingStatusOrHPPContext(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL+"/item?id=1"), modtest.Requester(t)
	ip := modtest.InsertionPoint(t, ctx, "id")
	m := New()
	baseFull, baseSig, _, baseline, err := m.sendPayloadReceipt(ctx, client, ip, "1")
	require.NoError(t, err)
	// This boundaried AND pair on an existing row runs the full 15-send path:
	// baseline + TRUE/FALSE + two replays + baseline drift + AND selection +
	// three TRUE/FALSE rounds + invalid syntax. OR selection is not needed.
	const batterySends = int32(15)
	pair := buildMatrixPayloads(true)[0]
	r, err := m.testPayloadPair(ctx, client, ip, "1", pair, baseSig, baseFull, baseline)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, batterySends, hits.Load(), "retention must not shorten the detection battery")
	// Both branches use this append boundary. Fill the legacy context budget,
	// including the non-pair annotations an HPP/status result retains.
	require.Len(t, r.Evidence, 9, "the full matrix battery retains the deciding controls and representative confirmations")
	r.AdditionalEvidence = append(r.AdditionalEvidence, "# [status-oracle] statuses", "# Parameter Pollution (HPP) channel")
	require.Len(t, r.AdditionalEvidence, modkit.MaxEvidencePairs)
	original := *r
	original.Evidence = evidence.CloneEntries(r.Evidence)
	original.AdditionalEvidence = append([]string(nil), r.AdditionalEvidence...)
	primary := r.Evidence[0]
	negativeIDs := map[string]bool{}
	for _, e := range r.Evidence {
		if e.Role == evidence.RoleControl || e.Role == evidence.RoleBaseline {
			negativeIDs[e.ExchangeID] = true
		}
	}
	sc, proof := &modkit.ScanContext{}, modkit.NewEvidenceCollector()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, ctx, client, proof))
	require.Equal(t, batterySends+int32(modkit.EndpointStabilitySamples), hits.Load(), "the original battery plus eight original stability samples only")
	appendStabilityEvidence(r, proof)
	require.Equal(t, primary.ExchangeID, r.Evidence[0].ExchangeID)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, string(primary.Exchange.Request), r.Request)
	require.Equal(t, string(primary.Exchange.Response), r.Response)
	require.LessOrEqual(t, len(r.Evidence), modkit.MaxEvidencePairs+1)
	require.LessOrEqual(t, len(r.AdditionalEvidence), modkit.MaxEvidencePairs)
	require.Contains(t, strings.Join(r.AdditionalEvidence, "\n"), "# [status-oracle]")
	require.Contains(t, strings.Join(r.AdditionalEvidence, "\n"), "Parameter Pollution (HPP)")
	for _, e := range r.Evidence {
		delete(negativeIDs, e.ExchangeID)
	}
	require.Empty(t, negativeIDs, "baseline and every deciding negative control survive; only redundant confirmations yield capacity")
	guardIDs := map[string]bool{}
	for _, e := range proof.Evidence() {
		guardIDs[e.ExchangeID] = true
	}
	retained := 0
	for _, e := range r.Evidence {
		if guardIDs[e.ExchangeID] {
			retained++
			require.False(t, e.Primary)
			require.Equal(t, evidence.RoleControl, e.Role)
		}
	}
	require.GreaterOrEqual(t, retained, 2)
	before := hits.Load()
	cached := modkit.NewEvidenceCollector()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, ctx, client, cached))
	appendStabilityEvidence(&original, cached)
	require.Equal(t, before, hits.Load(), "a second candidate reuses the deciding controls without another send")
	for _, e := range cached.Evidence() {
		require.True(t, guardIDs[e.ExchangeID])
	}
	require.Equal(t, primary.ExchangeID, original.Evidence[0].ExchangeID)
}
