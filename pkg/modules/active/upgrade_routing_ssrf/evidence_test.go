package upgrade_routing_ssrf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestUpgradeRoutingReceiptKeepsMissingRawHTTPRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", "routing")
		if strings.Contains(r.RequestURI, "169.254.169.254") && hasUpgrade(r) {
			_, _ = fmt.Fprint(w, "ami-id: ami-0secret\ninstance-id: i-9\n")
			return
		}
		_, _ = fmt.Fprint(w, "<html><body>normal</body></html>")
	}))
	defer srv.Close()
	results, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/app"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.False(t, result.BaselineEvidence)
	require.Equal(t, "missing", result.EvidenceStatus)
	require.Empty(t, result.Request, "displayRequest is not the rawhttp builder's sent bytes")
	require.Contains(t, result.Response, "X-Receipt: routing")
	require.Contains(t, result.Response, "ami-id:")
	require.Len(t, result.Evidence, 4)
	for i, role := range []evidence.Role{evidence.RoleAttack, evidence.RoleControl, evidence.RoleConfirmation, evidence.RoleConfirmation} {
		entry := result.Evidence[i]
		require.Equal(t, role, entry.Role)
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.StateMissing, entry.Exchange.RequestState)
		require.Empty(t, entry.Exchange.Request)
		require.NotEmpty(t, entry.Exchange.Response)
	}
}
