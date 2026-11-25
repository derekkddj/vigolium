package aspnet_service_exposure

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
	"github.com/vigolium/vigolium/pkg/output"
)

func TestCustomASMXFingerprintReceiptIsOperationLocalSupportingControl(t *testing.T) {
	var hits, controlHits atomic.Int64
	controlBody := strings.Repeat("custom nonexistent service response ", 200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case strings.HasPrefix(r.URL.Path, "/vigolium-svc-404-"):
			w.Header().Set("X-Custom-Control", fmt.Sprint(controlHits.Add(1)))
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, controlBody)
		case r.URL.Path == "/odata/$metadata":
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("X-Source-Proof", "odata")
			_, _ = fmt.Fprint(w, `<edmx:Edmx Version="4.0"><EntityType Name="Order"/></edmx:Edmx>`)
		case r.URL.Path == "/Service.asmx" && r.URL.Query().Has("WSDL"):
			w.Header().Set("Content-Type", "text/xml")
			w.Header().Set("X-Source-Proof", "wsdl")
			_, _ = fmt.Fprint(w, `<wsdl:definitions><wsdl:types/><wsdl:portType/></wsdl:definitions>`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "negative sibling control")
		}
	}))
	defer srv.Close()
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/Service.asmx"), "text/html", "<html>home</html>")
	client, m := modtest.Requester(t), New()
	fp := m.fingerprint404(ctx, client)
	require.NotNil(t, fp)
	require.NotNil(t, fp.receipt)
	require.NoError(t, fp.receipt.Validate())
	require.Equal(t, int64(1), hits.Load())
	require.Contains(t, string(fp.receipt.Request), "GET /vigolium-svc-404-")
	require.Contains(t, string(fp.receipt.Request), ".asmx HTTP/")
	require.True(t, strings.HasSuffix(string(fp.receipt.Response), controlBody))

	endpoint := m.probeEndpoint(ctx, client, commonProbes[0], fp)
	require.NotNil(t, endpoint)
	require.Len(t, endpoint.Evidence, 2+decoyRounds)
	discovery := m.probeServiceDiscovery(ctx, client, "/Service.asmx?WSDL", "ASMX WSDL", wsdlMarkers, fp)
	require.NotNil(t, discovery)
	require.Len(t, discovery.Evidence, 2)
	require.Equal(t, int64(2+decoyRounds+1), hits.Load(), "one fingerprint, one endpoint, existing sibling rounds, and one discovery request only")
	require.Equal(t, int64(1), controlHits.Load(), "shared fingerprint receipt must not be fetched again for reporting")

	for _, result := range []*output.ResultEvent{endpoint, discovery} {
		require.False(t, result.BaselineEvidence)
		require.Equal(t, "selected", result.EvidenceStatus)
		require.LessOrEqual(t, len(result.AdditionalEvidence), modkit.MaxEvidencePairs)
		require.LessOrEqual(t, len(result.Evidence), 1+modkit.MaxEvidencePairs)
		primary := result.Evidence[0]
		require.True(t, primary.Primary)
		require.Equal(t, evidence.RoleObservation, primary.Role)
		require.NotEqual(t, fp.receipt.ID, primary.ExchangeID)
		require.Equal(t, string(primary.Exchange.Request), result.Request)
		require.Equal(t, string(primary.Exchange.Response), result.Response)
		require.Contains(t, result.Response, "X-Source-Proof:")
		require.NotContains(t, result.Response, "X-Custom-Control:")
		control := result.Evidence[1]
		require.False(t, control.Primary)
		require.Equal(t, evidence.RoleControl, control.Role)
		require.Equal(t, fp.receipt.ID, control.ExchangeID)
		require.Equal(t, fp.receipt.ContentHash, control.Exchange.ContentHash)
		require.Equal(t, fp.receipt.CapturedAt, control.Exchange.CapturedAt)
		require.Equal(t, evidence.ProvenanceCaptured, control.Exchange.Provenance)
		require.Equal(t, fp.receipt.Request, control.Exchange.Request)
		require.Equal(t, fp.receipt.Response, control.Exchange.Response)
		require.Contains(t, result.AdditionalEvidence[0], "X-Custom-Control: 1")
		for _, entry := range result.Evidence {
			require.NoError(t, entry.Exchange.Validate())
		}
	}

	// Each candidate gets an owned selection; neither a result mutation nor a
	// later scan operation can corrupt or replace the first control receipt.
	endpoint.Evidence[1].Exchange.Response[0] = 'X'
	require.NoError(t, fp.receipt.Validate())
	require.NoError(t, discovery.Evidence[1].Exchange.Validate())
	next := m.fingerprint404(ctx, client)
	require.NotNil(t, next)
	require.NotNil(t, next.receipt)
	require.NotEqual(t, fp.receipt.ID, next.receipt.ID)
	require.Equal(t, int64(2), controlHits.Load())
	require.Contains(t, string(next.receipt.Response), "X-Custom-Control: 2")
	require.Contains(t, string(fp.receipt.Response), "X-Custom-Control: 1")
	require.NoError(t, fp.receipt.Validate())
	require.NoError(t, next.receipt.Validate())
}
