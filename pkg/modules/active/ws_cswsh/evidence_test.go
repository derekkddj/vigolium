package ws_cswsh

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestRankedHandshakeKeepsItsOwnCredentialControls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Origin", r.Header.Get("Origin"))
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeWSHandshake(w, r)
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/ws")
	raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Cookie", "session=secret")
	require.NoError(t, err)
	ctx = httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	client := modtest.Requester(t)
	m := New()
	baseline, ok := m.confirmUpgrade(ctx, client, srv.URL, false, false, true)
	require.True(t, ok)
	var accepted []acceptedScenario
	for _, origin := range []string{"https://evil.example.com", "null"} {
		attack, ok := m.confirmUpgrade(ctx, client, origin, false, false, true)
		require.True(t, ok)
		control, ok := m.confirmUpgrade(ctx, client, origin, false, true, false)
		require.True(t, ok)
		accepted = append(accepted, acceptedScenario{
			test: originTest{kind: "cross-site", label: origin}, origin: origin,
			evidence: attack, credentialDependent: true, credentialControl: control,
			browserConfirmed: origin == "null",
		})
	}
	result := m.result(srv.URL+"/ws", credentialPosture{present: true, crossSiteBrowserSessionKnown: true}, accepted, baseline)
	require.True(t, result.IsFinding())
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 6)
	require.Len(t, result.AdditionalEvidence, 5)
	primary := result.Evidence[0]
	require.Equal(t, accepted[1].evidence.first.receipt.ID, primary.ExchangeID)
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleAttack, primary.Role)
	require.Contains(t, result.Request, "Origin: null")
	require.Contains(t, result.Response, "X-Receipt-Origin: null")
	require.Equal(t, baseline.first.receipt.ID, result.Evidence[1].ExchangeID)
	require.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
	ids := map[string]bool{}
	for _, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
		if entry.Role == evidence.RoleControl {
			require.Contains(t, string(entry.Exchange.Request), "Origin: null")
			require.NotContains(t, string(entry.Exchange.Request), "Cookie:")
			require.Contains(t, string(entry.Exchange.Response), "401 Unauthorized")
		}
	}
	require.False(t, ids[accepted[0].credentialControl.first.receipt.ID], "controls must follow the selected scenario")
	require.True(t, ids[accepted[1].credentialControl.first.receipt.ID])
}
