package aem_xxe

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestXXESelectsFirstExpansionAndSeparateConfirmation(t *testing.T) {
	srv := xxeServer(t, true)
	result := New().probe(modtest.Request(t, srv.URL), modtest.Requester(t), guidePath, srv.URL)
	require.NotNil(t, result)
	require.Len(t, result.Evidence, confirmRounds)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleAttack, primary.Role)
	require.Equal(t, result.Request, string(primary.Exchange.Request))
	parsed, err := httpmsg.FromEvidenceExchange(primary.Exchange)
	require.NoError(t, err)
	require.Equal(t, result.Payload, string(parsed.Request().Body()))
	values, err := url.ParseQuery(result.Payload)
	require.NoError(t, err)
	require.Contains(t, values.Get("guideState"), "vigent")
	require.NotContains(t, result.Response, "vigent")
	for _, entry := range result.Evidence[1:] {
		require.False(t, entry.Primary)
		require.Equal(t, evidence.RoleConfirmation, entry.Role)
		require.NotEqual(t, primary.ExchangeID, entry.ExchangeID)
		confirm, err := httpmsg.FromEvidenceExchange(entry.Exchange)
		require.NoError(t, err)
		require.NotEqual(t, result.Payload, string(confirm.Request().Body()), "each round must retain its own fresh marker")
	}
}
