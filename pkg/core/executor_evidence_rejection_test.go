package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestEvidenceRejectedPrimaryCannotRecoverStaleInlineOrStoredIdentity(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale hash", true: "association mismatch"}[mismatch], func(t *testing.T) {
			e, db := newRepoExecutor(t)
			x := evidence.NewExchange("https://probe.test:443", "https://probe.test/probe", []byte("GET /probe HTTP/1.1\r\nHost: probe.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nprobe"), evidence.ProvenanceCaptured)
			entry := evidence.Select(x, evidence.RoleAttack, true, "probe")
			if mismatch {
				entry.ExchangeID = "unrelated-existing-claim"
			} else {
				entry.Exchange.Response[0] = 'X' // invalid, with its old digest
			}
			r := &output.ResultEvent{ModuleID: "rejected-test", URL: x.URL, Request: "GET /old HTTP/1.1\r\nHost: old.test\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nstale", Evidence: []evidence.Entry{entry}, Info: output.Info{Name: "Rejected proof"}}
			e.normalizeLegacyEvidence(r)
			e.finalizeEvidence(r)
			require.Empty(t, r.Request)
			require.Empty(t, r.Response)
			require.Equal(t, "missing", r.EvidenceStatus)
			require.True(t, r.Evidence[0].Primary, "retain the rejected declaration, not a new proof")
			require.Nil(t, r.Evidence[0].Exchange)
			require.True(t, strings.HasPrefix(r.Evidence[0].ExchangeID, "rejected-evidence:"))
			marker := r.Evidence[0].ExchangeID
			for _, entry := range r.Evidence[1:] {
				require.False(t, entry.Primary, "unrelated inline text may be context only")
			}
			e.emitResult(context.Background(), r, nil, nil)
			require.Equal(t, marker, r.Evidence[0].ExchangeID)
			require.Empty(t, r.Request)
			require.Empty(t, r.Response)
			require.Equal(t, "missing", r.EvidenceStatus)
			require.Zero(t, countRecords(t, db), "rejected/stale primary must not create a linked HTTP record")
			stored := loadFindings(t, db)
			require.Len(t, stored, 1, "keep the finding and its unavailable manifest")
			require.Equal(t, "missing", stored[0].EvidenceStatus)
		})
	}
}

func TestEvidenceRecordDestinationIgnoresUnknownAndBaselinePrimaries(t *testing.T) {
	x := evidence.NewExchange("https://probe.test:8443", "https://attribution.test/probe", []byte("GET /probe HTTP/1.1\r\nHost: virtual.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nprobe"), evidence.ProvenanceCaptured)
	for _, role := range []evidence.Role{evidence.RoleUnknown, evidence.RoleBaseline} {
		context := evidence.NewExchange("http://context.test:80", x.URL, x.Request, x.Response, evidence.ProvenanceSupplied)
		for _, entries := range [][]evidence.Entry{
			{evidence.Select(context, role, true, "context"), evidence.Select(x, evidence.RoleAttack, true, "attack")},
			{evidence.Select(x, evidence.RoleAttack, true, "attack"), evidence.Select(context, role, true, "context")},
		} {
			r := &output.ResultEvent{URL: x.URL, Evidence: entries}
			(&Executor{}).finalizeEvidence(r)
			require.Equal(t, "selected", r.EvidenceStatus)
			rr, err := resultEvidenceMessages(r, nil)
			require.NoError(t, err)
			require.Equal(t, "probe.test", rr.Service().Host())
			require.Equal(t, 8443, rr.Service().Port())
		}
	}
}

func TestEvidencePartialReceiptPreservesResponseAbsenceWithoutRawRecord(t *testing.T) {
	x := evidence.NewExchange("http://probe.test:80", "http://probe.test/probe", []byte("GET /probe HTTP/1.1\r\nHost: probe.test\r\n\r\n"), nil, evidence.ProvenanceCaptured)
	r := &output.ResultEvent{URL: x.URL, Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "no answer")}}
	(&Executor{}).finalizeEvidence(r)
	rr, err := resultEvidenceMessages(r, nil)
	require.ErrorContains(t, err, "incomplete evidence")
	require.Nil(t, rr, "a partial primary remains canonical evidence, not a legacy raw record")
	require.Equal(t, string(x.Request), r.Request)
	require.Empty(t, r.Response)
	rr, err = httpmsg.FromEvidenceExchange(r.Evidence[0].Exchange)
	require.NoError(t, err)
	require.False(t, rr.HasResponse())
	require.Nil(t, rr.Response())
	require.Equal(t, evidence.StateMissing, rr.Evidence().ResponseState)
}

func TestEvidenceInputAnalysisWithSupportingContextSelectsSourceOnly(t *testing.T) {
	_, baseline := makeTestItem("example.com", "/source.js", "source observation")
	control := evidence.NewExchange("https://control.test:443", "https://control.test/reachable", []byte("GET /reachable HTTP/1.1\r\nHost: control.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nreachable"), evidence.ProvenanceCaptured)
	r := &output.ResultEvent{URL: baseline.Target(), BaselineEvidence: true, Evidence: []evidence.Entry{evidence.Select(control, evidence.RoleObservation, false, "reachability")}}
	(&Executor{}).prepareResultEvidence(r, baseline, false)
	require.Equal(t, "selected", r.EvidenceStatus)
	require.Equal(t, string(baseline.Request().Raw()), r.Request)
	require.Equal(t, string(baseline.Response().Raw()), r.Response)
	require.False(t, r.Evidence[0].Primary)
	require.Len(t, r.Evidence, 2)
	require.True(t, r.Evidence[1].Primary)
	require.Equal(t, evidence.RoleObservation, r.Evidence[1].Role)
}
