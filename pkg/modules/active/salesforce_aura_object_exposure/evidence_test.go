package salesforce_aura_object_exposure

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestObjectEnumerationOperationEvidence(t *testing.T) {
	srv := auraServer(t, configDataWithCustom())
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.False(t, r.BaselineEvidence)
	require.Len(t, r.Evidence, 5)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	decoded, err := url.QueryUnescape(r.Request)
	require.NoError(t, err)
	require.Contains(t, decoded, "getConfigData")
	require.Contains(t, r.Response, configDataWithCustom())
	seen := map[string]bool{}
	confirmations := 0
	for _, entry := range r.Evidence {
		require.NotNil(t, entry.Exchange)
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, seen[entry.ExchangeID])
		seen[entry.ExchangeID] = true
		if entry.Role == evidence.RoleConfirmation {
			confirmations++
			require.Contains(t, string(entry.Exchange.Response), configDataWithCustom())
		}
	}
	require.Equal(t, confirmRounds, confirmations)
}
