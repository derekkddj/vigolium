package mcp_server_probe

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestGroupedResultsSelectActualInvocationAndSecretLeakSeparately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rpc struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &rpc)
		w.Header().Set("Content-Type", "application/json")
		switch rpc.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "actual-issued-session")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"test","version":"1"}}}`)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{}}},{"name":"get_config","inputSchema":{"type":"object","properties":{}}}]}}`)
		case "tools/call":
			text := "first benign invocation"
			if rpc.Params.Name == "get_config" {
				text = "token: ghp_012345678901234567890123456789012345"
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":100,"result":{"content":[{"type":"text","text":"`+text+`"}],"isError":false}}`)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[]}}`)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[]}}`)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()
	seed, client, m := modtest.Request(t, srv.URL+"/mcp"), modtest.Requester(t), New()
	ep := m.tryStreamableHTTP(seed, client, "/mcp")
	require.NotNil(t, ep)
	m.enumerateAndInvoke(seed, client, ep)
	results := m.buildResults(seed, []mcpEndpoint{*ep}, true)
	require.Len(t, results, 2)
	general, secret := results[0], results[1]
	require.NotEqual(t, general.Evidence[0].ExchangeID, secret.Evidence[0].ExchangeID)
	require.Contains(t, general.Request, `"name":"echo"`)
	require.Contains(t, general.Response, "first benign invocation")
	require.Contains(t, secret.Request, `"name":"get_config"`)
	require.Contains(t, secret.Response, "ghp_012345678901234567890123456789012345")
	for _, result := range results {
		require.True(t, result.Evidence[0].Primary)
		require.Equal(t, evidence.RoleObservation, result.Evidence[0].Role)
		parsed, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
		require.NoError(t, err)
		require.Equal(t, "actual-issued-session", parsed.Request().Header("Mcp-Session-Id"))
		require.Equal(t, result.Payload, string(parsed.Request().Body()))
		require.Equal(t, seed.Service().Port(), parsed.Service().Port())
	}
}
