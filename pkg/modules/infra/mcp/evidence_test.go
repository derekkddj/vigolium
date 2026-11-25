package mcp

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
	"github.com/vigolium/vigolium/pkg/output"
)

func TestClientEvidencePreservesSSEAndFinalSessionHeaders(t *testing.T) {
	const sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"first-operation\"}]}}\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rpc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &rpc)
		if rpc.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "server-issued-session")
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"test","version":"1"}}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Operation", "first")
		_, _ = io.WriteString(w, sse)
	}))
	defer srv.Close()
	seed := modtest.Request(t, srv.URL+"/input-only")
	client := NewClient(seed, modtest.Requester(t), "/mcp")
	init, err := client.Initialize()
	require.NoError(t, err)
	require.NotNil(t, init.Exchange)
	client.SetExtraHeaders(map[string]string{"Origin": "https://attacker.example", "Authorization": "Bearer per-operation"})
	res, body, exchange, err := client.CallToolEvidence(7, "read", map[string]any{"path": "first"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, sse, body)
	require.Equal(t, exchange, res.Exchange)
	require.Contains(t, string(exchange.Response), "Content-Type: text/event-stream")
	require.Contains(t, string(exchange.Response), sse)
	original := exchange.Clone()
	client.SetSessionID("later-session")
	client.SetExtraHeaders(map[string]string{"Origin": "https://later.example"})
	_, _, later, err := client.CallToolEvidence(8, "read", map[string]any{"path": "later"})
	require.NoError(t, err)
	require.NotEqual(t, original.ID, later.ID)
	require.Equal(t, original, exchange)
	parsed, err := httpmsg.FromEvidenceExchange(exchange)
	require.NoError(t, err)
	require.Equal(t, "/mcp", parsed.Request().Path())
	require.Equal(t, "server-issued-session", parsed.Request().Header("Mcp-Session-Id"))
	require.Equal(t, "https://attacker.example", parsed.Request().Header("Origin"))
	require.Equal(t, "Bearer per-operation", parsed.Request().Header("Authorization"))
	require.Equal(t, BuildToolsCallRequest(7, "read", map[string]any{"path": "first"}), parsed.Request().Body())
	require.Equal(t, seed.Service().Port(), parsed.Service().Port())
	serialized, err := json.Marshal(res)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), exchange.ID, "transport metadata must not change MCP JSON")
}

func TestClientEvidenceSurvivesJSONRPCParseError(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"uid=1000(probe)"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	client := NewClient(modtest.Request(t, srv.URL), modtest.Requester(t), "/mcp")
	res, raw, exchange, err := client.CallToolEvidence(7, "probe", nil)
	require.Error(t, err)
	require.Nil(t, res)
	require.Equal(t, body, raw)
	require.NotNil(t, exchange)
	require.Contains(t, string(exchange.Response), body)
}

func TestSelectDoesNotRepairMissingRequestFromLegacyFields(t *testing.T) {
	x := evidence.NewExchange("http://destination.example:8080", "", nil,
		[]byte("HTTP/1.1 200 OK\r\n\r\nactual-response"), evidence.ProvenanceCaptured)
	result := NewProof(x).Attack(&output.ResultEvent{Request: "seed request", Response: "JSON projection"})
	require.Empty(t, result.Request)
	require.Equal(t, string(x.Response), result.Response)
	require.Equal(t, "missing", result.EvidenceStatus)
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 1)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	missing := (*Proof)(nil).Observation(&output.ResultEvent{Request: "seed", Response: "seed"})
	require.Empty(t, missing.Request)
	require.Empty(t, missing.Response)
	require.Equal(t, "missing", missing.EvidenceStatus)
}
