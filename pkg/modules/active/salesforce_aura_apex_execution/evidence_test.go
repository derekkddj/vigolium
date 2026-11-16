package salesforce_aura_apex_execution

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestApexOperationEvidence(t *testing.T) {
	srv := apexServer(t, func(msg string) string {
		if strings.Contains(msg, "getTemplates") {
			return apexSuccess
		}
		return apexError
	})
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.False(t, r.BaselineEvidence)
	require.Len(t, r.Evidence, 7)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	decoded, err := url.QueryUnescape(r.Request)
	require.NoError(t, err)
	require.Contains(t, decoded, "getTemplates")
	require.Contains(t, r.Response, apexSuccess)
	seen := map[string]bool{}
	controls, confirmations := 0, 0
	for _, entry := range r.Evidence {
		require.NotNil(t, entry.Exchange)
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, seen[entry.ExchangeID], "each round has its own execution identity")
		seen[entry.ExchangeID] = true
		if entry.Role == evidence.RoleControl {
			controls++
			require.Contains(t, string(entry.Exchange.Response), apexError)
		}
		if entry.Role == evidence.RoleConfirmation {
			confirmations++
		}
	}
	require.Equal(t, 2, controls)
	require.Equal(t, confirmRounds, confirmations)
}
