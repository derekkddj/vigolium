package servicenow_widget_data_exposure

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestWidgetReceiptsAreTableLocal(t *testing.T) {
	srv := snServer(t, map[string]bool{"sys_user": true, "incident": true}, false, false)
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, r := range results {
		tbl := r.Metadata["table"].(string)
		require.False(t, r.BaselineEvidence)
		require.Len(t, r.Evidence, 5)
		require.True(t, r.Evidence[0].Primary)
		require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
		require.Contains(t, r.Request, "?t="+tbl)
		require.Contains(t, r.Request, "X-Usertoken: TOKENabcdef0123456789ABCDEF")
		require.Contains(t, r.Request, "Cookie: glide_user_route=glide.deadbeef")
		require.Contains(t, r.Response, "Jane Doe")
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
				require.Contains(t, string(entry.Exchange.Request), "?t="+bogusTable)
			}
			if entry.Role == evidence.RoleConfirmation {
				confirmations++
				require.Contains(t, string(entry.Exchange.Request), "?t="+tbl)
			}
		}
		require.Equal(t, 1, controls)
		require.Equal(t, confirmRounds, confirmations)
	}
}
