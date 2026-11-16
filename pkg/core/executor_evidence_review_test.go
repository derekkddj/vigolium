package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

type evidenceReviewHook struct {
	pre  func(*httpmsg.HttpRequestResponse) *httpmsg.HttpRequestResponse
	post func(*output.ResultEvent) *output.ResultEvent
}

func (h evidenceReviewHook) RunPreHooks(r *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	if h.pre != nil {
		r = h.pre(r)
	}
	return r, nil
}
func (h evidenceReviewHook) RunPostHooks(r *output.ResultEvent) (*output.ResultEvent, error) {
	if h.post != nil {
		r = h.post(r)
	}
	return r, nil
}

func TestEvidencePostHookCannotRehashSealedCapture(t *testing.T) {
	for _, timestamp := range []bool{false, true} {
		t.Run(map[bool]string{false: "rehash", true: "timestamp"}[timestamp], func(t *testing.T) {
			x := evidence.NewExchange("https://example.com:443", "https://example.com/", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\noriginal"), evidence.ProvenanceCaptured)
			r := &output.ResultEvent{ModuleID: "test", URL: x.URL, Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "")}}
			e, _ := newTestExecutor(ExecutorConfig{}, nil)
			e.hooks = evidenceReviewHook{post: func(r *output.ResultEvent) *output.ResultEvent {
				if timestamp {
					r.Evidence[0].Exchange.CapturedAt = x.CapturedAt.Add(time.Hour)
				} else {
					r.Evidence[0].Exchange.Response = []byte("HTTP/1.1 500 Error\r\n\r\nforged")
					r.Evidence[0].Exchange.ContentHash = r.Evidence[0].Exchange.Hash()
				}
				return r
			}}
			got := e.emitResult(context.Background(), r, nil, nil).event
			require.NotNil(t, got)
			require.Equal(t, x, got.Evidence[0].Exchange)
			require.Contains(t, got.Error, "rewrite sealed evidence")
			require.Equal(t, string(x.Response), got.Response)
		})
	}
}

func TestEvidenceFinalOccurrenceUsesPostHookAttribution(t *testing.T) {
	x := evidence.NewExchange("https://example.com:443", "https://example.com/probe", []byte("GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nanswer"), evidence.ProvenanceCaptured)
	r := &output.ResultEvent{ModuleID: "test", URL: x.URL, Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "")}}
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	e.scanUUID = "current-scan"
	e.hooks = evidenceReviewHook{post: func(r *output.ResultEvent) *output.ResultEvent {
		r.URL = "https://example.com/assertion"
		entry := evidence.Select(x, evidence.RoleControl, false, "")
		entry.OccurrenceID, entry.FindingURL, entry.ScanUUID = "producer-conflict", "old-url", "old-scan"
		r.Evidence = append(r.Evidence, entry)
		return r
	}}
	first := e.emitResult(context.Background(), r, nil, nil).event
	require.NotNil(t, first)
	id := first.Evidence[0].OccurrenceID
	for _, entry := range first.Evidence {
		require.Equal(t, id, entry.OccurrenceID)
		require.Equal(t, first.URL, entry.FindingURL)
		require.Equal(t, e.scanUUID, entry.ScanUUID)
	}
	second := e.emitResult(context.Background(), r, nil, nil).event
	require.NotEqual(t, id, second.Evidence[0].OccurrenceID, "reused event must be another occurrence")
}

func TestEvidencePassiveProjectionPreservesFullReusedInput(t *testing.T) {
	for _, projection := range []string{"empty", "request", "response", "both"} {
		t.Run(projection, func(t *testing.T) {
			_, rr := makeTestItem("example.com", "/binary", "\x00\xfffull-response")
			req := httpmsg.NewHttpRequestWithService(rr.Service(), []byte("POST /binary HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\n\x00\xfffull-request"))
			rr = httpmsg.NewHttpRequestResponse(req, rr.Response())
			e, _ := newTestExecutor(ExecutorConfig{SkipBaseline: true}, nil)
			fetched, ok := e.fetchBaseline(context.Background(), rr)
			require.True(t, ok)
			snapshot := fetched.req.Evidence()
			require.NotNil(t, snapshot)
			fetched.req.Request().TruncateBody(2)
			fetched.req.Response().TruncateBody(2)
			r := &output.ResultEvent{URL: rr.Target()}
			if projection == "request" || projection == "both" {
				r.Request = string(fetched.req.Request().Raw())
			}
			if projection == "response" || projection == "both" {
				r.Response = string(fetched.req.Response().Raw())
			}
			e.prepareResultEvidence(r, fetched.req, true)
			require.Equal(t, string(snapshot.Request), r.Request)
			require.Equal(t, string(snapshot.Response), r.Response)
			require.Equal(t, "selected", r.EvidenceStatus)
			require.Equal(t, evidence.ProvenanceSupplied, r.Evidence[0].Exchange.Provenance)
		})
	}
}

func TestEvidenceOtherBaselineNeverSuppressesScanInput(t *testing.T) {
	_, rr := makeTestItem("example.com", "/input", "input")
	rr = suppliedInputSnapshot(rr)
	for _, role := range []evidence.Role{evidence.RoleBaseline, evidence.RoleObservation} {
		x := rr.Evidence()
		x.ID = "another-execution"
		r := &output.ResultEvent{URL: rr.Target(), Evidence: []evidence.Entry{evidence.Select(x, role, false, "")}}
		(&Executor{}).prepareResultEvidence(r, rr, false)
		require.Len(t, r.Evidence, 2)
		require.Equal(t, rr.Evidence().ID, r.Evidence[1].ExchangeID)
	}
}

func TestEvidenceMixedLegacyAndHookPairsRemainUnclassified(t *testing.T) {
	_, rr := makeTestItem("example.com", "/input", "input")
	r := &output.ResultEvent{ModuleID: "test", URL: rr.Target()}
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	e.prepareResultEvidence(r, rr, false)
	e.hooks = evidenceReviewHook{post: func(r *output.ResultEvent) *output.ResultEvent {
		r.Request, r.Response = "GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 400 Bad Request\r\n\r\nprobe"
		r.AdditionalEvidence = []string{output.BuildEvidence("informal attack", "GET /control HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\ncontrol")}
		return r
	}}
	got := e.emitResult(context.Background(), r, nil, nil).event
	require.Equal(t, "unclassified", got.EvidenceStatus)
	require.Len(t, got.Evidence, 3)
	require.Equal(t, evidence.RoleBaseline, got.Evidence[0].Role)
	require.Equal(t, evidence.RoleUnknown, got.Evidence[1].Role)
	require.Equal(t, evidence.RoleUnknown, got.Evidence[2].Role)
}

func TestEvidencePreHookOutOfScopeRejectedBeforeFetch(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	_, rr := makeTestItem("allowed.example", "/", "old-answer")
	scopeCfg := *config.DefaultScopeConfig()
	scopeCfg.Host = config.ScopeRule{Include: []string{"allowed.example"}}
	e, _ := newTestExecutor(ExecutorConfig{ScopeMatcher: config.NewScopeMatcher(scopeCfg)}, nil)
	e.httpClient = modtest.Requester(t)
	e.hooks = evidenceReviewHook{pre: func(_ *httpmsg.HttpRequestResponse) *httpmsg.HttpRequestResponse {
		changed, err := httpmsg.GetRawRequestFromURL(server.URL)
		require.NoError(t, err)
		return changed.WithResponse(rr.Response())
	}}
	require.False(t, e.processItem(context.Background(), work.NewWithModules(rr, nil)))
	require.Zero(t, sent.Load())
	require.EqualValues(t, 1, e.scopeRejected.Load())
}

func TestEvidenceRecordUsesReceiptServiceWithoutBodyRepair(t *testing.T) {
	e, db := newRepoExecutor(t)
	x := evidence.NewExchange("http://probe.example:8081", "http://probe.example:8081/actual", []byte("POST /actual HTTP/1.1\r\nHost: probe.example\r\nContent-Length: 999\r\n\r\n\x00\xffshort"), []byte("HTTP/1.1 200 OK\r\n\r\n\x00\xffanswer"), evidence.ProvenanceCaptured)
	// Explicit complete capture at the message boundary; declared body framing
	// must still remain untouched rather than repaired by request ingestion.
	r := &output.ResultEvent{ModuleID: "test", URL: "https://assertion.example/vuln", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "")}}
	outcome := e.emitResult(context.Background(), r, nil, nil)
	require.NotEqual(t, emissionDropped, outcome.outcome)
	findings := loadFindings(t, db)
	require.Len(t, findings, 1)
	require.Len(t, findings[0].HTTPRecordUUIDs, 1)
	record, err := e.repo.GetRecordByUUID(context.Background(), findings[0].HTTPRecordUUIDs[0])
	require.NoError(t, err)
	require.Equal(t, "http", record.Scheme)
	require.Equal(t, "probe.example", record.Hostname)
	require.Equal(t, 8081, record.Port)
	require.Equal(t, x.Request, record.RawRequest)
	require.Equal(t, x.Response, record.RawResponse)
}
