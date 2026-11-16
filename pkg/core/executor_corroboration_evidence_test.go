package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestObserveProbeResponseSelectsReceiptNotCappedSyntheticPair(t *testing.T) {
	e := &Executor{corroboration: newProbeCorroboration()}
	req := "POST /login HTTP/1.1\r\nHost: h\r\nX-Sent: actual\r\n\r\nemail=a'"
	body := juiceLoginSQLErr + strings.Repeat("x", maxCorroborationBodyBytes+100)
	x := evidence.NewExchange("http://h:80", "http://h/login", []byte(req), []byte("HTTP/1.1 500 Internal Server Error\r\nX-Actual: retained\r\nContent-Type: application/json\r\n\r\n"+body), evidence.ProvenanceCaptured)
	obs := newObs("h", x.URL, "pretransport intent", body, 500)
	obs.CaptureEvidence = func() *evidence.Exchange { return x.Clone() }
	e.observeProbeResponse(obs)
	require.Len(t, e.corroboration.hits, 1)
	r := e.corroboration.hits[0]
	require.Len(t, r.Evidence, 1)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleObservation, r.Evidence[0].Role)
	require.Equal(t, x.ID, r.Evidence[0].ExchangeID)
	require.Equal(t, string(x.Request), r.Request)
	require.Equal(t, string(x.Response), r.Response)
	require.Contains(t, r.Response, "X-Actual: retained")
	require.Greater(t, len(r.Response), maxCorroborationBodyBytes)
	(&Executor{}).finalizeEvidence(r)
	require.Equal(t, "selected", r.EvidenceStatus)
}

func TestObserveProbeResponseWithoutReceiptCannotFabricateHTTPProof(t *testing.T) {
	e := &Executor{corroboration: newProbeCorroboration()}
	e.observeProbeResponse(newObs("h", "http://h/login", "POST /login HTTP/1.1\r\n\r\nintent", juiceLoginSQLErr, 500))
	require.Len(t, e.corroboration.hits, 1)
	r := e.corroboration.hits[0]
	require.Empty(t, r.Request)
	require.Empty(t, r.Response)
	require.Empty(t, r.Evidence)
	require.Equal(t, "missing", r.EvidenceStatus)
	require.Contains(t, r.Metadata["response_preview"], "SQLITE_ERROR")
}
