package smart_behavior_detection

import (
	"bufio"
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

func TestBehaviorGuardKeepsCachedControlsAndPrimaryWithinCap(t *testing.T) {
	var hits atomic.Int32
	oracle := sqlHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		oracle(w, r)
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL+"/search?q=widget"), modtest.Requester(t)
	ip := modtest.InsertionPoint(t, ctx, "q")
	cold, err := New().ScanPerInsertionPoint(ctx, ip, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, cold, 1)
	require.True(t, cold[0].Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, cold[0].Evidence[0].Role)
	require.Equal(t, string(cold[0].Evidence[0].Exchange.Request), cold[0].Request)
	require.Equal(t, string(cold[0].Evidence[0].Exchange.Response), cold[0].Response)
	coldSends := hits.Load()
	sc, controls := &modkit.ScanContext{}, modkit.NewEvidenceCollector()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, ctx, client, controls))
	require.Len(t, controls.Evidence(), modkit.EndpointStabilitySamples)
	before := hits.Load()
	warm, err := New().ScanPerInsertionPoint(ctx, ip, client, sc)
	require.NoError(t, err)
	require.Len(t, warm, 1)
	require.Equal(t, coldSends-int32(modkit.EndpointStabilitySamples), hits.Load()-before, "cached guard adds no requests; producer traffic is unchanged")
	r := warm[0]
	require.LessOrEqual(t, len(r.Evidence), modkit.MaxEvidencePairs+1)
	require.LessOrEqual(t, len(r.AdditionalEvidence), modkit.MaxEvidencePairs)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	require.Equal(t, string(r.Evidence[0].Exchange.Request), r.Request)
	require.Equal(t, string(r.Evidence[0].Exchange.Response), r.Response)
	// These are independent scan executions: diffscan adds a fresh cache-buster
	// to each probe/replay. Compare the selected break's operation semantics,
	// not cross-run raw bytes or exchange identity; each result must still mirror
	// its own explicitly selected primary receipt byte-for-byte above.
	coldRequest, err := http.ReadRequest(bufio.NewReader(strings.NewReader(cold[0].Request)))
	require.NoError(t, err)
	warmRequest, err := http.ReadRequest(bufio.NewReader(strings.NewReader(r.Request)))
	require.NoError(t, err)
	require.Equal(t, coldRequest.Method, warmRequest.Method)
	require.Equal(t, coldRequest.URL.Path, warmRequest.URL.Path)
	require.Equal(t, coldRequest.URL.Query().Get("q"), warmRequest.URL.Query().Get("q"))
	require.False(t, sqlStringValid(warmRequest.URL.Query().Get("q")), "selected break is not the unmodified/escape control")
	require.NotEqual(t, cold[0].Evidence[0].ExchangeID, r.Evidence[0].ExchangeID, "separate scans own separate execution identities")
	ids := map[string]bool{}
	for _, e := range controls.Evidence() {
		ids[e.ExchangeID] = true
	}
	retained := 0
	for _, e := range r.Evidence {
		if ids[e.ExchangeID] {
			retained++
			require.False(t, e.Primary)
			require.Equal(t, evidence.RoleControl, e.Role)
		}
	}
	require.GreaterOrEqual(t, retained, 4, "a full producer report must reserve actual stability context")
}
