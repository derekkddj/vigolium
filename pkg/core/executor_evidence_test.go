package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestEvidenceMissingProbeNeverAdoptsInputProof(t *testing.T) {
	_, baseline := makeTestItem("example.com", "/swagger.json", "swagger baseline")
	for _, target := range []string{"https://example.com/login", "https://example.com/swagger.json"} {
		t.Run(target, func(t *testing.T) {
			e := &Executor{scanUUID: "scan"}
			r := &output.ResultEvent{URL: target}
			e.prepareResultEvidence(r, baseline, false)
			require.Empty(t, r.Request, "#1521/#1524: omitted probes must not be repaired with a GET baseline")
			require.Empty(t, r.Response)
			require.Equal(t, "missing", r.EvidenceStatus)
			require.Len(t, r.Evidence, 1)
			require.Equal(t, evidence.RoleBaseline, r.Evidence[0].Role)
			require.False(t, r.Evidence[0].Primary)
			require.Equal(t, baseline.Target(), r.Evidence[0].Exchange.URL)
			require.Equal(t, target, r.Evidence[0].FindingURL)
		})
	}
}

func TestEvidenceResponseOnlyNeverInventsRequest(t *testing.T) {
	_, baseline := makeTestItem("example.com", "/login", "baseline200")
	r := &output.ResultEvent{URL: baseline.Target(), Response: "HTTP/1.1 400 Bad Request\r\n\r\nprobe"}
	(&Executor{}).prepareResultEvidence(r, baseline, false)
	require.Empty(t, r.Request)
	require.Equal(t, "missing", r.EvidenceStatus)
	require.Equal(t, evidence.StateMissing, r.Evidence[0].Exchange.RequestState)
	require.Contains(t, string(r.Evidence[0].Exchange.Response), "400")
}

func TestEvidenceSSTIBaselineRequestDoesNotInheritImageResponse(t *testing.T) {
	_, baseline := makeTestItem("example.com", "/image.gif", "GIF89a")
	r := &output.ResultEvent{URL: baseline.Target(), Request: string(baseline.Request().Raw())}
	(&Executor{}).prepareResultEvidence(r, baseline, false)
	require.Empty(t, r.Response, "#1530 report without selected probes must remain missing")
	require.Equal(t, "missing", r.EvidenceStatus)
}

func TestEvidencePassiveAndExplicitInputAnalysisRemainSupported(t *testing.T) {
	_, baseline := makeTestItem("example.com", "/image.gif", "GIF89a")
	for _, passive := range []bool{false, true} {
		r := &output.ResultEvent{URL: baseline.Target(), BaselineEvidence: !passive}
		(&Executor{}).prepareResultEvidence(r, baseline, passive)
		require.Equal(t, string(baseline.Request().Raw()), r.Request)
		require.Equal(t, string(baseline.Response().Raw()), r.Response)
		require.Equal(t, "selected", r.EvidenceStatus)
		require.Equal(t, evidence.RoleObservation, r.Evidence[0].Role)
		require.True(t, r.Evidence[0].Primary)
	}
}

func TestEvidenceSelectionUsesOwnedReceiptNotLastCallOrInline(t *testing.T) {
	_, baseline := makeTestItem("example.com", "/swagger", "baseline")
	x := evidence.NewExchange("https://example.com:443", "https://example.com/login", []byte("POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nsql"), []byte("HTTP/1.1 400 Bad Request\r\n\r\nblocked"), evidence.ProvenanceCaptured)
	r := &output.ResultEvent{URL: x.URL, Request: "stale request", Response: "stale response", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "SQL probe")}}
	e := &Executor{scanUUID: "scan"}
	e.prepareResultEvidence(r, baseline, false)
	require.Equal(t, string(x.Request), r.Request)
	require.Equal(t, string(x.Response), r.Response)
	require.Equal(t, "selected", r.EvidenceStatus)
	x.Response[0] = '!'
	require.NoError(t, r.Evidence[0].Exchange.Validate())
	before := r.Evidence[0].OccurrenceID
	e.finalizeEvidence(r)
	require.Equal(t, before, r.Evidence[0].OccurrenceID)
}

func TestEvidenceSameRequestDifferentResponseDoesNotUseRequestCache(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()
	_, baseline := makeTestItem("example.com", "/same", "baseline")
	id, err := e.repo.SaveRecord(ctx, baseline, "spidering", e.projectUUID)
	require.NoError(t, err)
	e.caches.requestUUIDs.Store(baseline.Request().ID(), id)
	mod := &trackingPassiveModule{id: "changed-response"}
	r := &output.ResultEvent{URL: baseline.Target(), Request: string(baseline.Request().Raw()), Response: "HTTP/1.1 403 Forbidden\r\n\r\nnew answer"}
	e.processResults(ctx, []*output.ResultEvent{r}, mod, baseline, nil)
	findings := loadFindings(t, db)
	require.Len(t, findings, 1)
	require.NotContains(t, findings[0].HTTPRecordUUIDs, id)
	require.Equal(t, 2, countRecords(t, db))
	stored, err := e.repo.GetRecordByUUID(ctx, findings[0].HTTPRecordUUIDs[0])
	require.NoError(t, err)
	require.Equal(t, r.Response, string(stored.RawResponse))
}

func TestEvidenceReceiptSurvivesAnalysisTruncation(t *testing.T) {
	_, rr := makeTestItem("example.com", "/binary", "GIF89a\x00\xfforiginal")
	x := evidence.NewExchange(evidenceService(rr), rr.Target(), rr.Request().Raw(), rr.Response().Raw(), evidence.ProvenanceCaptured)
	rr = rr.WithEvidence(x)
	rr.Response().TruncateBody(2)
	r := &output.ResultEvent{URL: rr.Target()}
	(&Executor{}).prepareResultEvidence(r, rr, true)
	require.Equal(t, string(x.Response), r.Response)
	require.Equal(t, evidence.StateComplete, r.Evidence[0].Exchange.ResponseState)
	require.NoError(t, r.Evidence[0].Exchange.Validate())
}

func TestEvidenceChangedDBInputKeepsHistoricalRecord(t *testing.T) {
	e, db := newRepoExecutor(t)
	ctx := context.Background()
	item, baseline := makeTestItem("example.com", "/same", "old")
	id, err := e.repo.SaveRecord(ctx, baseline, "spidering", e.projectUUID)
	require.NoError(t, err)
	item.RecordUUID = id
	changed := baseline.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 403 Forbidden\r\n\r\nnew")))
	e.saveToDatabase(ctx, item, changed, nil)
	require.Equal(t, 2, countRecords(t, db))
	old, err := e.repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, string(baseline.Response().Raw()), string(old.RawResponse))
	require.NotEqual(t, id, e.ResolveRequestUUID(changed.Request().ID()))
}
