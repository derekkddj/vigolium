package backslash_transformation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/evidence"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestTransformationEvidenceUsesMatchedReceiptWithoutReportingSend(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Transformation-Receipt", "matched")
		// The anchored payload sends two backslashes before its middle anchor;
		// SearchAnchor expects the server's single-backslash reflection. Decode
		// that pair as well as the hex escape so extraction can reach the probe.
		reflected := strings.ReplaceAll(r.URL.Query().Get("q"), `\\`, `\`)
		_, _ = fmt.Fprint(w, strings.ReplaceAll(reflected, `\x41`, "A"))
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/?q=initial")
	ip := modtest.InsertionPoint(t, ctx, "q")
	client := modtest.Requester(t)
	// This is the package's only real requester fixture. Balance its network.Init
	// reference so Close also stops the mem guardian before TestMain's leak check.
	t.Cleanup(network.Close)
	m := New()
	classified, _, _, err := m.recordAndClassify(ctx, ip, client, `\x41`, false)
	require.NoError(t, err)
	matched := FilterInteresting(classified)
	require.Len(t, matched, 1)
	require.Equal(t, "A", matched[0].Received)
	require.Equal(t, ClassificationInteresting, matched[0].Classification)
	require.NotNil(t, matched[0].exchange)
	selectedID := matched[0].exchange.ID

	// A later call does not become the proof, and reporting must not resend
	// with fresh anchors just to manufacture an HTTP pair.
	later, _, err := client.Execute(modtest.Request(t, srv.URL+"/?q=unrelated-later"), vhttp.Options{NoClustering: true})
	require.NoError(t, err)
	later.Close()
	results, err := m.buildResults(ctx, ip, client, matched, nil, false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, int64(2), calls.Load())
	result := results[0]
	require.Equal(t, "selected", result.EvidenceStatus)
	require.False(t, result.BaselineEvidence)
	require.Contains(t, result.Response, "X-Transformation-Receipt: matched")
	require.NotContains(t, result.Response, "unrelated-later")
	require.NotContains(t, result.Request, "q=initial")
	require.Len(t, result.Evidence, 1)
	primary := result.Evidence[0]
	require.Equal(t, selectedID, primary.ExchangeID)
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.Equal(t, result.Request, string(primary.Exchange.Request))
	require.Equal(t, result.Response, string(primary.Exchange.Response))
	require.NoError(t, primary.Exchange.Validate())
}

func TestTransformationMissingReceiptDoesNotInheritOrResend(t *testing.T) {
	ctx := modtest.Response(modtest.Request(t, "http://example.com/?q=baseline"), "text/plain", "baseline response")
	ip := modtest.InsertionPoint(t, ctx, "q")
	matched := []*TransformResult{{Probe: `\x41`, Received: "A", Classification: ClassificationInteresting, Pretty: `\x41 => A`}}
	// A nil requester is intentional: construction must not issue proof requests.
	results, err := New().buildResults(ctx, ip, nil, matched, nil, false)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "missing", results[0].EvidenceStatus)
	require.False(t, results[0].BaselineEvidence)
	require.Empty(t, results[0].Request)
	require.Empty(t, results[0].Response)
	require.Empty(t, results[0].Evidence)
}
