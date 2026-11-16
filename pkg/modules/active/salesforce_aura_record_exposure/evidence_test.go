package salesforce_aura_record_exposure

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestRecordEvidenceIsObjectLocal(t *testing.T) {
	srv := auraServer(t, map[string]bool{"Contact": true, "Broker__c": true}, false)
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, r := range results {
		obj := r.Metadata["object"].(string)
		require.False(t, r.BaselineEvidence)
		require.Len(t, r.Evidence, 7)
		require.True(t, r.Evidence[0].Primary)
		require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
		decoded, err := url.QueryUnescape(r.Request)
		require.NoError(t, err)
		require.Equal(t, obj, entityFromMessage(formMessage(t, decoded)))
		require.Contains(t, r.Response, recordsResp(7))
		seen := map[string]bool{}
		controls, confirmations := 0, 0
		for _, entry := range r.Evidence {
			require.NotNil(t, entry.Exchange)
			require.NoError(t, entry.Exchange.Validate())
			require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
			require.False(t, seen[entry.ExchangeID])
			seen[entry.ExchangeID] = true
			if entry.Role == evidence.RoleControl {
				controls++
				require.Contains(t, string(entry.Exchange.Response), emptyResp())
			}
			if entry.Role == evidence.RoleConfirmation {
				confirmations++
				body, err := url.QueryUnescape(string(entry.Exchange.Request))
				require.NoError(t, err)
				require.Equal(t, obj, entityFromMessage(formMessage(t, body)))
			}
		}
		require.Equal(t, 1, controls)
		require.Equal(t, confirmRounds, confirmations)
	}
}

// Read only the message field from the already-decoded request body.
func formMessage(t *testing.T, raw string) string {
	t.Helper()
	start, end := strings.Index(raw, "message="), strings.Index(raw, "&aura.context=")
	require.GreaterOrEqual(t, start, 0)
	require.Greater(t, end, start)
	return raw[start+len("message=") : end]
}
