package vigtool

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/replay"
)

func replayReceiptSeed(t *testing.T, repo *database.Repository, target string) *database.HTTPRecord {
	t.Helper()
	rr, err := httpmsg.ParseRawRequestWithURL("POST /start HTTP/1.1\r\nHost: original.invalid\r\nAuthorization: Bearer stale\r\nContent-Length: 8\r\n\r\nold body", target)
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 401 Unauthorized\r\n\r\nold response")))
	id, err := repo.SaveRecordWithLineage(context.Background(), rr, "original-input", database.DefaultProjectUUID, database.RecordLineage{
		ParentUUID: "historical-parent", RootUUID: "historical-root", Target: "submitted input", ChainTruncated: true, Remarks: []string{"input note"},
	})
	require.NoError(t, err)
	rec, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	return rec
}

func TestReplayRequestPersistsCapturedFinalExchangeAndPreservesHistory(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "learned", Value: "yes", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusSeeOther)
			return
		}
		seen <- r.Clone(r.Context())
		_, _ = w.Write([]byte("fresh response"))
	}))
	defer srv.Close()
	repo := newVigtoolTestRepo(t)
	old := replayReceiptSeed(t, repo, srv.URL+"/start")
	finding := &database.Finding{ProjectUUID: old.ProjectUUID, FindingHash: "olium-replay-history", ModuleID: "historical", OriginRecordUUID: old.UUID, URL: old.URL, Status: database.StatusTriaged}
	require.NoError(t, repo.SaveFindingDirect(context.Background(), finding))
	r := &replayRequestTool{ctx: &SessionsContext{Repo: repo, ProjectUUID: old.ProjectUUID}}
	r.clientOnce.Do(func() {
		r.client = srv.Client()
		r.client.Jar, _ = cookiejar.New(nil)
	})
	res, err := r.Execute(context.Background(), map[string]any{"record_uuid": old.UUID[:8], "raw_request": string(old.RawRequest),
		"extra_headers": map[string]any{"Authorization": "Bearer fresh"}}, nil)
	require.NoError(t, err)
	require.False(t, res.IsError, res.Content)
	id := res.Details["replay_record_uuid"].(string)
	require.NotEqual(t, old.UUID, id)
	require.Equal(t, old.UUID, res.Details["record_uuid"])
	require.Equal(t, true, res.Details["persisted"])
	require.Equal(t, "saved", res.Details["persistence_status"])
	require.Equal(t, "intended", res.Details["mutated_request_kind"])
	manifest := res.Details["receipt"].(tool.HTTPReceiptManifest)
	x, err := r.SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateComplete, x.ResponseState)
	actual := <-seen
	stored, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, "GET", stored.Method)
	require.Equal(t, "/final", stored.Path)
	require.Equal(t, srv.URL+"/final", stored.URL)
	require.Equal(t, srv.URL, x.Service)
	require.Equal(t, x.Request, stored.RawRequest)
	require.Equal(t, x.Response, stored.RawResponse)
	req := httpmsg.NewHttpRequest(stored.RawRequest)
	require.Empty(t, req.Body())
	for _, name := range []string{"Authorization", "Cookie", "User-Agent", "Accept-Encoding"} {
		require.Equal(t, actual.Header.Get(name), req.Header(name), name)
	}
	require.Equal(t, "original-input", stored.Source)
	require.Equal(t, old.ParentUUID, stored.ParentUUID)
	require.Equal(t, old.RootUUID, stored.RootUUID)
	require.Equal(t, old.Target, stored.Target)
	require.Equal(t, old.ChainTruncated, stored.ChainTruncated)
	require.Contains(t, stored.Remarks, "input note")
	history, err := repo.GetRecordByUUID(context.Background(), old.UUID)
	require.NoError(t, err)
	require.Equal(t, old.RawRequest, history.RawRequest)
	require.Equal(t, old.RawResponse, history.RawResponse)
	var linked string
	require.NoError(t, repo.DB().NewRaw("SELECT origin_record_uuid FROM findings WHERE finding_hash = ?", finding.FindingHash).Scan(context.Background(), &linked))
	require.Equal(t, old.UUID, linked)
	require.NotContains(t, res.Content, "\"request_bytes\":\"", "receipt manifests must not embed base64 request bodies")
}

func TestReplayRequestKeepsPartialReceiptOnExecutionErrorWithoutPersistingFakePair(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	old := replayReceiptSeed(t, repo, "http://127.0.0.1/start")
	x := evidence.NewExchange("http://127.0.0.1", "http://127.0.0.1/actual", []byte("GET /actual HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\npartial"), evidence.ProvenanceCaptured)
	x.ResponseState = evidence.StateTruncated
	x.ContentHash = x.Hash()
	r := &replayRequestTool{ctx: &SessionsContext{Repo: repo, ProjectUUID: old.ProjectUUID}, doReplay: func(_ context.Context, opts replay.Options) (*replay.Result, error) {
		require.True(t, opts.CaptureExchange)
		return &replay.Result{RawMutatedRequest: []byte("NOT SENT"), Replay: &replay.Summary{Exchange: x, Error: "body read failed"}}, errors.New("execution failed")
	}}
	res, err := r.Execute(context.Background(), map[string]any{"record_uuid": old.UUID, "raw_request": string(old.RawRequest)}, nil)
	require.NoError(t, err)
	require.True(t, res.IsError)
	require.Equal(t, false, res.Details["persisted"])
	require.Equal(t, "capture_unavailable", res.Details["persistence_status"])
	require.Contains(t, res.Content, "execution failed")
	require.Contains(t, res.Content, "body read failed")
	manifest := res.Details["receipt"].(tool.HTTPReceiptManifest)
	require.True(t, manifest.Available)
	selected, err := r.SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Equal(t, x.Request, selected.Request)
	require.Equal(t, x.Response, selected.Response)
	require.Equal(t, evidence.StateTruncated, selected.ResponseState)
	require.NotContains(t, string(selected.Request), "NOT SENT")
	count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}

func TestReplayRequestCompleteReceiptSurvivesOuterErrorAndSaveFailureIsExplicit(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	old := replayReceiptSeed(t, repo, "http://127.0.0.1/start")
	x := evidence.NewExchange("http://127.0.0.1", "http://127.0.0.1/actual", []byte("GET /actual HTTP/1.1\r\nHost: sent\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nfresh"), evidence.ProvenanceCaptured)
	r := &replayRequestTool{ctx: &SessionsContext{Repo: repo, ProjectUUID: old.ProjectUUID}, doReplay: func(context.Context, replay.Options) (*replay.Result, error) {
		return &replay.Result{Replay: &replay.Summary{Exchange: x}}, errors.New("post-execution error")
	}}
	res, err := r.Execute(context.Background(), map[string]any{"record_uuid": old.UUID, "raw_request": string(old.RawRequest)}, nil)
	require.NoError(t, err)
	require.True(t, res.IsError)
	require.Equal(t, true, res.Details["persisted"])
	require.NotEmpty(t, res.Details["replay_record_uuid"])
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id, err := r.persistReplayExchange(ctx, old.UUID, &replay.Result{Replay: &replay.Summary{Exchange: x}})
	require.Error(t, err)
	require.Empty(t, id)
}

func TestReplayRequestMissingCaptureNeverUsesMutatedRequestAndSummaryAsEvidence(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	old := replayReceiptSeed(t, repo, "http://127.0.0.1/start")
	r := &replayRequestTool{ctx: &SessionsContext{Repo: repo, ProjectUUID: old.ProjectUUID}, doReplay: func(context.Context, replay.Options) (*replay.Result, error) {
		return &replay.Result{RawMutatedRequest: old.RawRequest, Replay: &replay.Summary{Status: 200, RawBody: []byte("not a capture")}}, nil
	}}
	res, err := r.Execute(context.Background(), map[string]any{"record_uuid": old.UUID, "raw_request": string(old.RawRequest)}, nil)
	require.NoError(t, err)
	require.False(t, res.IsError) // execution and persistence statuses are separate
	require.Equal(t, false, res.Details["persisted"])
	require.Equal(t, "capture_unavailable", res.Details["persistence_status"])
	manifest := res.Details["receipt"].(tool.HTTPReceiptManifest)
	require.False(t, manifest.Available)
	require.Equal(t, "missing_capture", manifest.Availability)
	require.Equal(t, evidence.StateMissing, manifest.RequestState)
}

func TestReplayRequestPersistenceFailureDoesNotHideSuccessfulCapturedExecution(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	old := replayReceiptSeed(t, repo, "http://127.0.0.1/start")
	x := evidence.NewExchange("http://127.0.0.1", "http://127.0.0.1/actual", []byte("GET /actual HTTP/1.1\r\nHost: sent\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nfresh"), evidence.ProvenanceCaptured)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	r := &replayRequestTool{ctx: &SessionsContext{Repo: repo, ProjectUUID: old.ProjectUUID}, doReplay: func(context.Context, replay.Options) (*replay.Result, error) {
		calls++
		cancel() // completes execution, but persistence must fail on this context
		return &replay.Result{Replay: &replay.Summary{Exchange: x}}, nil
	}}
	res, err := r.Execute(ctx, map[string]any{"record_uuid": old.UUID, "raw_request": string(old.RawRequest)}, nil)
	require.NoError(t, err)
	require.False(t, res.IsError)
	require.Equal(t, 1, calls) // a persistence failure never retries network work
	require.Equal(t, false, res.Details["persisted"])
	require.Equal(t, "failed", res.Details["persistence_status"])
	require.NotEmpty(t, res.Details["persist_error"])
	require.NotContains(t, res.Details, "replay_record_uuid")
	manifest := res.Details["receipt"].(tool.HTTPReceiptManifest)
	selected, err := r.SelectHTTPReceipt(manifest.Ref)
	require.NoError(t, err)
	require.Equal(t, x.Request, selected.Request)
	require.Equal(t, x.Response, selected.Response)
}

func TestReplayRequestNilResultErrorAndLiveBaselineReceipts(t *testing.T) {
	for _, withBaseline := range []bool{false, true} {
		t.Run("execution_error", func(t *testing.T) {
			repo := newVigtoolTestRepo(t)
			old := replayReceiptSeed(t, repo, "http://127.0.0.1/start")
			x := evidence.NewExchange("http://127.0.0.1", "http://127.0.0.1/baseline", []byte("GET /baseline HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nbaseline"), evidence.ProvenanceCaptured)
			r := &replayRequestTool{ctx: &SessionsContext{Repo: repo, ProjectUUID: old.ProjectUUID}, doReplay: func(context.Context, replay.Options) (*replay.Result, error) {
				if withBaseline {
					return &replay.Result{Baseline: &replay.Summary{Exchange: x}}, errors.New("replay failed")
				}
				return nil, errors.New("replay failed")
			}}
			res, err := r.Execute(context.Background(), map[string]any{"record_uuid": old.UUID, "raw_request": string(old.RawRequest)}, nil)
			require.NoError(t, err)
			require.True(t, res.IsError)
			require.True(t, json.Valid([]byte(res.Content)))
			require.Equal(t, false, res.Details["persisted"])
			require.False(t, res.Details["receipt"].(tool.HTTPReceiptManifest).Available)
			baseline := res.Details["baseline_receipt"].(tool.HTTPReceiptManifest)
			require.Equal(t, withBaseline, baseline.Available)
			if withBaseline {
				selected, err := r.SelectHTTPReceipt(baseline.Ref)
				require.NoError(t, err)
				require.Equal(t, x.Request, selected.Request)
				require.Equal(t, x.Response, selected.Response)
			}
		})
	}
}
