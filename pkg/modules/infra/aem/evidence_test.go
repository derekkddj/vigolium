package aem

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestProbeEvidenceOwnsOperationAfterCloseAndLaterSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Probe", r.Header.Get("X-Probe"))
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	client := modtest.Requester(t)
	seed := modtest.Request(t, srv.URL+"/input-only")
	attack := Post(seed, client, "/attack?round=1", "marker=first", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "X-Probe": "first", "Authorization": "Bearer actual-operation",
	})
	require.True(t, attack.OK)
	require.NotNil(t, attack.Exchange)
	original := attack.Exchange.Clone()
	later := Post(seed, client, "/later", "marker=second", map[string]string{"X-Probe": "second"})
	require.True(t, later.OK)
	require.NotEqual(t, original.ID, later.Exchange.ID)
	require.Equal(t, original, attack.Exchange)
	attack.Header.Set("X-Probe", "mutated-analysis-header")
	require.Contains(t, string(attack.Exchange.Response), "X-Probe: first")
	require.NotContains(t, string(attack.Exchange.Response), "mutated-analysis-header")
	parsed, err := httpmsg.FromEvidenceExchange(attack.Exchange)
	require.NoError(t, err)
	require.Equal(t, "POST", parsed.Request().Method())
	require.Equal(t, "/attack?round=1", parsed.Request().Path())
	require.Equal(t, "Bearer actual-operation", parsed.Request().Header("Authorization"))
	require.Equal(t, "first", parsed.Request().Header("X-Probe"))
	require.Equal(t, []byte("marker=first"), parsed.Request().Body())
	require.Equal(t, seed.Service().Host(), parsed.Service().Host())
	require.Equal(t, seed.Service().Port(), parsed.Service().Port())
	require.True(t, bytes.Equal(original.Request, parsed.Request().Raw()))

	proof := NewProof(attack)
	proof.Payload = "marker=first"
	proof.Control(later)
	result := proof.Attack(&output.ResultEvent{Request: "seed must not survive", Response: "seed must not survive"})
	require.Equal(t, string(original.Request), result.Request)
	require.Equal(t, string(original.Response), result.Response)
	require.Equal(t, "marker=first", result.Payload)
	require.Len(t, result.Evidence, 2)
	require.True(t, result.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	require.Equal(t, evidence.RoleControl, result.Evidence[1].Role)
	attack.Exchange.Request[0] = 'X'
	require.Equal(t, original, result.Evidence[0].Exchange)
}

func TestProofMissingRequestIsNotRepairedAndContextIsBounded(t *testing.T) {
	x := evidence.NewExchange("http://destination.example:8080", "http://finding.example/elsewhere", nil,
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"), evidence.ProvenanceCaptured)
	proof := &Proof{Primary: x, Payload: "exact mutation"}
	for i := 0; i < modkit.MaxEvidencePairs+4; i++ {
		proof.Confirmation(ProbeResult{Exchange: x})
	}
	result := proof.Attack(&output.ResultEvent{Request: "GET /input HTTP/1.1\r\n\r\n", Response: "input response"})
	require.Empty(t, result.Request)
	require.Equal(t, string(x.Response), result.Response)
	require.Equal(t, "missing", result.EvidenceStatus)
	require.Equal(t, evidence.StateMissing, result.Evidence[0].Exchange.RequestState)
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, modkit.MaxEvidencePairs+1)
	require.Len(t, result.AdditionalEvidence, modkit.MaxEvidencePairs)
	parsed, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
	require.NoError(t, err)
	require.Empty(t, parsed.Request().Raw(), "response-only receipt must not invent a replay request")
	require.Equal(t, []byte(result.Response), parsed.Response().Raw())

	missing := (*Proof)(nil).Observation(&output.ResultEvent{Request: "seed", Response: "seed"})
	require.Empty(t, missing.Request)
	require.Empty(t, missing.Response)
	require.Equal(t, "missing", missing.EvidenceStatus)
}

func TestProofKeepsUnknownTruncatedStatesAndUnrepairedMessages(t *testing.T) {
	request := []byte("POST /attack HTTP/1.1\r\nHost: virtual.example\r\nContent-Length: 1\r\n\r\nlonger-body")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nshort")
	x := evidence.NewExchange("http://destination.example:8080", "https://finding.example/elsewhere", request, response, evidence.ProvenanceCaptured)
	x.RequestState, x.ResponseState = evidence.StateUnknown, evidence.StateTruncated
	x.ContentHash = x.Hash()
	result := (&Proof{Primary: x}).Attack(&output.ResultEvent{URL: "https://another-finding.example/"})
	selected := result.Evidence[0].Exchange
	require.Equal(t, evidence.StateUnknown, selected.RequestState)
	require.Equal(t, evidence.StateTruncated, selected.ResponseState)
	parsed, err := httpmsg.FromEvidenceExchange(selected)
	require.NoError(t, err)
	require.Equal(t, request, parsed.Request().Raw())
	require.Equal(t, response, parsed.Response().Raw())
	require.Equal(t, "virtual.example", parsed.Request().Header("Host"))
	require.Equal(t, "destination.example", parsed.Service().Host())
	require.Equal(t, 8080, parsed.Service().Port())
}

func TestSiblingIs404SupportsLegacyAndProofCallers(t *testing.T) {
	// Root-level paths are a no-op, so these API compatibility checks send
	// nothing and also cover nil proof collectors.
	require.False(t, SiblingIs404(nil, nil, "/real"))
	require.False(t, SiblingIs404(nil, nil, "/real", (*Proof)(nil)))
}

func TestSiblingIs404RetainsActualControl(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	proof := &Proof{}
	require.True(t, SiblingIs404(modtest.Request(t, srv.URL), modtest.Requester(t), "/servlet/real", proof))
	entries := proof.Context.Evidence()
	require.Len(t, entries, 1)
	require.Equal(t, evidence.RoleControl, entries[0].Role)
	parsed, err := httpmsg.FromEvidenceExchange(entries[0].Exchange)
	require.NoError(t, err)
	require.Contains(t, parsed.Request().Path(), "/servlet/")
	require.NotEqual(t, "/servlet/real", parsed.Request().Path())
	require.Equal(t, 404, parsed.Response().StatusCode())
}
