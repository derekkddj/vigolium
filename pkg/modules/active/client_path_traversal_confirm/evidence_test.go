package client_path_traversal_confirm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestBrowserURLSummaryLeavesHTTPProofMissing(t *testing.T) {
	ctx := modtest.Response(modtest.Request(t, "http://example.com/app"), "text/html", htmlPage)
	u, err := ctx.URL()
	require.NoError(t, err)
	m := New()
	m.Navigate = fakeNavigate(navNormal, "GET")
	confirmed := m.confirmCandidate(context.Background(), u.String(), hashCandidate, nil)
	require.NotNil(t, confirmed)
	result := m.buildResult(ctx, u, confirmed)
	require.Equal(t, output.RecordKindFinding, result.RecordKind, "HTTP receipt availability does not change the existing browser oracle")
	require.Equal(t, "missing", result.EvidenceStatus)
	require.False(t, result.BaselineEvidence)
	require.Empty(t, result.Request, "a URL/method summary is not a raw browser request")
	require.Empty(t, result.Response)
	require.Empty(t, result.Evidence)
	require.Len(t, result.AdditionalEvidence, 4, "browser path observations remain available")
}

func TestBrowserRecordKeepsSuppliedUnknownFidelityAndRoles(t *testing.T) {
	ctx := modtest.Response(modtest.Request(t, "http://example.com/app"), "text/html", htmlPage)
	u, err := ctx.URL()
	require.NoError(t, err)
	m := New()
	var retained []*evidence.Exchange
	m.Navigate = func(runCtx context.Context, nav NavRequest) ([]CapturedRequest, error) {
		requests, err := fakeNavigate(navNormal, "POST")(runCtx, nav)
		for i := range requests {
			rr := modtest.Response(modtest.RequestMethod(t, "POST", requests[i].URL, "csrf=browser-body"), "text/plain", "browser response "+requests[i].URL)
			requests[i].Exchange = browserReceipt(rr)
			retained = append(retained, requests[i].Exchange)
		}
		return requests, err
	}
	confirmed := m.confirmCandidate(context.Background(), u.String(), hashCandidate, nil)
	require.NotNil(t, confirmed)
	require.Len(t, retained, 3)
	result := m.buildResult(ctx, u, confirmed)
	require.Equal(t, "selected", result.EvidenceStatus)
	require.False(t, result.BaselineEvidence)
	require.Contains(t, result.Request, "POST /api/vigolium-cspt-")
	require.Contains(t, result.Request, "csrf=browser-body")
	require.Contains(t, result.Response, "browser response "+confirmed.Payload1URL)
	require.Len(t, result.Evidence, 3)
	for i, role := range []evidence.Role{evidence.RoleAttack, evidence.RoleControl, evidence.RoleConfirmation} {
		entry := result.Evidence[i]
		require.Equal(t, role, entry.Role)
		require.Equal(t, i == 0, entry.Primary)
		require.Equal(t, evidence.ProvenanceSupplied, entry.Exchange.Provenance)
		require.Equal(t, evidence.StateUnknown, entry.Exchange.RequestState)
		require.Equal(t, evidence.StateUnknown, entry.Exchange.ResponseState)
		require.NoError(t, entry.Exchange.Validate())
	}
	require.Equal(t, retained[1].ID, result.Evidence[0].ExchangeID, "the first escape round, not the last browser request, is primary")
	require.Equal(t, retained[0].ID, result.Evidence[1].ExchangeID)
	require.Equal(t, retained[2].ID, result.Evidence[2].ExchangeID)
	retained[1].Request[0] = 'X'
	require.Contains(t, result.Request, "POST /api/")
	require.NoError(t, result.Evidence[0].Exchange.Validate(), "selected bytes outlive the browser record")
}

func TestBrowserReceiptPreservesExistingStamp(t *testing.T) {
	rr := modtest.Response(modtest.Request(t, "http://example.com/api/resource"), "text/plain", "captured resource")
	stamp := evidence.NewExchange("http://example.com", rr.Target(), rr.Request().Raw(), rr.Response().Raw(), evidence.ProvenanceCaptured)
	stamped := rr.WithEvidence(stamp)
	selected := browserReceipt(stamped)
	require.Equal(t, stamp.ID, selected.ID)
	require.Equal(t, stamp.Provenance, selected.Provenance)
	require.Equal(t, stamp.RequestState, selected.RequestState)
	require.Equal(t, stamp.ResponseState, selected.ResponseState)
	require.NoError(t, selected.Validate())
}
