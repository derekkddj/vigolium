package core

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestEvidencePartialPrimaryClearsStaleLegacySide(t *testing.T) {
	x := evidence.NewExchange("https://example.com:443", "https://example.com/probe", []byte("GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n"), nil, evidence.ProvenanceSupplied)
	r := &output.ResultEvent{URL: x.URL, Request: "old request", Response: "old response", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "timed out")}}
	e := &Executor{}
	e.finalizeEvidence(r)
	require.Equal(t, string(x.Request), r.Request)
	require.Empty(t, r.Response)
	require.Equal(t, "missing", r.EvidenceStatus)
}

func TestEvidenceMultiplePrimariesNeverSelectByOrder(t *testing.T) {
	x := evidence.NewExchange("https://example.com:443", "https://example.com/probe", []byte("GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nfirst"), evidence.ProvenanceCaptured)
	y := evidence.NewExchange(x.Service, x.URL, x.Request, []byte("HTTP/1.1 403 Forbidden\r\n\r\nsecond"), evidence.ProvenanceCaptured)
	for _, entries := range [][]evidence.Entry{
		{evidence.Select(x, evidence.RoleAttack, true, "first"), evidence.Select(y, evidence.RoleConfirmation, true, "second")},
		{evidence.Select(y, evidence.RoleConfirmation, true, "second"), evidence.Select(x, evidence.RoleAttack, true, "first")},
	} {
		r := &output.ResultEvent{URL: x.URL, Request: "stale request", Response: "stale response", Evidence: entries}
		e := &Executor{}
		for i := 0; i < 2; i++ {
			e.finalizeEvidence(r)
			require.Empty(t, r.Request)
			require.Empty(t, r.Response)
			require.Equal(t, "missing", r.EvidenceStatus)
			require.Contains(t, r.Error, "multiple primary evidence selections")
			require.Len(t, r.Evidence, 2)
			require.True(t, r.Evidence[0].Primary)
			require.True(t, r.Evidence[1].Primary)
			require.Equal(t, r.Evidence[0].OccurrenceID, r.Evidence[1].OccurrenceID)
		}
	}
}
