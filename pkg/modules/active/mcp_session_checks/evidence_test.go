package mcp_session_checks

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestFixationEvidenceKeepsSuppliedIDControlAndFollowup(t *testing.T) {
	srv := httptest.NewServer(fixationSessionHandler())
	defer srv.Close()
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL+"/mcp"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.Equal(t, fixationCandidate, result.Payload)
	require.Len(t, result.Evidence, 3)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	attack, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
	require.NoError(t, err)
	require.Equal(t, fixationCandidate, attack.Request().Header("Mcp-Session-Id"))
	require.Equal(t, fixationCandidate, attack.Response().Header("Mcp-Session-Id"))
	require.Contains(t, string(attack.Request().Body()), `"method":"initialize"`)
	require.Equal(t, evidence.RoleControl, result.Evidence[1].Role)
	control, err := httpmsg.FromEvidenceExchange(result.Evidence[1].Exchange)
	require.NoError(t, err)
	require.Empty(t, control.Request().Header("Mcp-Session-Id"))
	require.Contains(t, string(control.Response().Raw()), "session required")
	require.Equal(t, evidence.RoleConfirmation, result.Evidence[2].Role)
	followup, err := httpmsg.FromEvidenceExchange(result.Evidence[2].Exchange)
	require.NoError(t, err)
	require.Equal(t, fixationCandidate, followup.Request().Header("Mcp-Session-Id"))
	require.Contains(t, string(followup.Request().Body()), `"method":"tools/list"`)
}
