package aem_cloudsettings_injection

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestWriteReadBackEvidenceKeepsActualPOSTAsPrimary(t *testing.T) {
	srv := cloudsettingsServer(t, true)
	seed, client, m := modtest.Request(t, srv.URL), modtest.Requester(t), New()
	primitive, ok := m.findWritePrimitive(seed, client)
	require.True(t, ok)
	el, ok := m.probeEL(seed, client, primitive)
	require.True(t, ok)
	write := m.buildPreAuthWrite(primitive, srv.URL)
	injection := m.buildELInjection(primitive, el, srv.URL)
	require.NotEqual(t, write.Evidence[0].ExchangeID, injection.Evidence[0].ExchangeID)
	for _, result := range []*output.ResultEvent{write, injection} {
		require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
		require.True(t, result.Evidence[0].Primary)
		parsed, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
		require.NoError(t, err)
		require.Equal(t, "POST", parsed.Request().Method())
		require.Equal(t, writeBase, parsed.Request().Path())
		require.Equal(t, result.Payload, string(parsed.Request().Body()))
		require.Equal(t, string(parsed.Response().Raw()), result.Response)
		require.Contains(t, result.Response, `{"success":true}`)
		require.Len(t, result.Evidence, reproduceRounds+2)
		for _, entry := range result.Evidence[1:] {
			require.Equal(t, evidence.RoleConfirmation, entry.Role)
			readback, err := httpmsg.FromEvidenceExchange(entry.Exchange)
			require.NoError(t, err)
			require.Equal(t, "GET", readback.Request().Method())
			require.Equal(t, readBase, readback.Request().Path())
			require.Contains(t, string(entry.Exchange.Response), "cq-redirect-notice")
		}
	}
}
