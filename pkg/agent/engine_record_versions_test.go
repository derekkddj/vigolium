package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func recordVersionTestRepo(t *testing.T) *database.Repository {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "versions.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(context.Background()))
	return database.NewRepository(db)
}

func recordVersionTestRequest(t *testing.T, target string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.ParseRawRequestWithURL("POST /start HTTP/1.1\r\nHost: original.invalid\r\nAuthorization: Bearer stale\r\nContent-Length: 8\r\n\r\nold body", target)
	require.NoError(t, err)
	return rr
}

func TestSourceAnalysisAdoptsObservedVersionWithoutRewritingAgentInput(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	repo := recordVersionTestRepo(t)
	engine := &Engine{repo: repo}
	merged := &SourceAnalysisResult{HTTPRecords: []AgentHTTPRecord{{
		Method: "POST", URL: srv.URL + "/start", Body: "old body", Notes: "source route",
		Headers: map[string]string{"Authorization": "Bearer stale"},
	}}}
	result, raw, prompt, err := engine.postProcessSourceAnalysisWithMerged(context.Background(), SourceAnalysisConfig{
		TargetURL: srv.URL, ProjectUUID: database.DefaultProjectUUID,
	}, merged, "original output", "original prompt")
	require.NoError(t, err)
	require.EqualValues(t, 1, hits.Load()) // the positive fixture must take the live reprobe path
	require.Equal(t, "original output", raw)
	require.Equal(t, "original prompt", prompt)
	rec := result.HTTPRecords[0]
	require.NotEmpty(t, rec.RecordUUID)
	require.NotNil(t, rec.ObservedExchange)
	capture := rec.ObservedExchange.Evidence()
	require.NotNil(t, capture)
	require.Equal(t, evidence.ProvenanceCaptured, capture.Provenance)
	require.Equal(t, evidence.StateComplete, capture.RequestState)
	require.Equal(t, evidence.StateComplete, capture.ResponseState)
	require.NoError(t, capture.Validate())
	require.Equal(t, "old body", rec.Body) // source intent remains separate
	require.Equal(t, "source route", rec.Notes)
	require.Empty(t, rec.ObservedExchange.Request().Body()) // actual reprobe sends no body
	require.Equal(t, http.StatusTemporaryRedirect, rec.ObservedExchange.Response().StatusCode())
	stored, err := repo.GetRecordByUUID(context.Background(), rec.RecordUUID)
	require.NoError(t, err)
	require.Equal(t, stored.RawRequest, rec.ObservedExchange.Request().Raw())
	require.Equal(t, stored.RawResponse, rec.ObservedExchange.Response().Raw())
	require.Equal(t, stored.RawRequest, capture.Request)
	require.Equal(t, stored.RawResponse, capture.Response)
	// Direct repository queries use the stored service hostname, not the prompt's host:port.
	seeds, err := repo.GetUnprobedRecordsBySource(context.Background(), database.DefaultProjectUUID, "source-analysis", stored.Hostname, 200)
	require.NoError(t, err)
	require.Len(t, seeds, 1)
	require.NotEqual(t, seeds[0].UUID, rec.RecordUUID)
	require.Equal(t, "old body", string(httpmsg.NewHttpRequest(seeds[0].RawRequest).Body()))

	converted, err := ToHTTPRequestResponse(rec)
	require.NoError(t, err)
	require.NotSame(t, rec.ObservedExchange, converted)
	require.Equal(t, capture, converted.Evidence())
	require.Equal(t, stored.RawRequest, converted.Request().Raw())
	require.Equal(t, stored.RawResponse, converted.Response().Raw())
	filtered, notes, ids := filterSourceRecordsByHostname(result.HTTPRecords, srv.URL)
	require.Len(t, filtered, 1)
	require.Equal(t, []string{"source route"}, notes)
	require.Equal(t, []string{rec.RecordUUID}, ids)
	require.Equal(t, stored.RawRequest, filtered[0].Request().Raw())
	require.Contains(t, formatRouteStatusSummary(filtered), "3xx: 1")
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), rec.RecordUUID)
	require.NotContains(t, string(encoded), "ObservedExchange")
}

func TestAgentRecordVersionAdoptionKeepsPartialSuccessAndHistoricalLinks(t *testing.T) {
	ctx := context.Background()
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, "http://127.0.0.1/start")
	oldUUID, err := repo.SaveRecord(ctx, seed, "source-analysis", database.DefaultProjectUUID)
	require.NoError(t, err)
	finding := &database.Finding{ProjectUUID: database.DefaultProjectUUID, ModuleID: "history", FindingHash: "agent-version-history", OriginRecordUUID: oldUUID, URL: seed.Target(), Status: database.StatusTriaged}
	require.NoError(t, repo.SaveFindingDirect(ctx, finding))
	observed := seed.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfresh")))
	versionUUID, err := repo.SaveRecordVersion(ctx, oldUUID, observed)
	require.NoError(t, err)
	records := []AgentHTTPRecord{
		{RecordUUID: oldUUID, Method: "POST", URL: seed.Target(), Body: "old body", Notes: "input"},
		{RecordUUID: "failed", URL: "http://127.0.0.1/failed"},
		{RecordUUID: "unmapped", URL: "http://127.0.0.1/unmapped"},
		{RecordUUID: oldUUID, URL: seed.Target()}, // repeated current slot is adopted too
	}
	err = adoptAgentRecordVersions(ctx, repo, database.DefaultProjectUUID, records, map[string]string{oldUUID: versionUUID, "failed": "missing-version"})
	require.Error(t, err)
	for _, i := range []int{0, 3} {
		require.Equal(t, versionUUID, records[i].RecordUUID)
		require.Equal(t, observed.Request().Raw(), records[i].ObservedExchange.Request().Raw())
		require.Equal(t, observed.Response().Raw(), records[i].ObservedExchange.Response().Raw())
	}
	require.Equal(t, "old body", records[0].Body)
	require.Equal(t, "input", records[0].Notes)
	require.Equal(t, "failed", records[1].RecordUUID)
	require.Nil(t, records[1].ObservedExchange)
	require.Equal(t, "unmapped", records[2].RecordUUID)
	history, err := repo.GetRecordByUUID(ctx, oldUUID)
	require.NoError(t, err)
	require.False(t, history.HasResponse)
	require.Equal(t, seed.Request().Raw(), history.RawRequest)
	var linked string
	require.NoError(t, repo.DB().NewRaw("SELECT origin_record_uuid FROM findings WHERE finding_hash = ?", finding.FindingHash).Scan(ctx, &linked))
	require.Equal(t, oldUUID, linked)
}

func TestObservedVersionAdoptionRejectsRequestOnlyAndForeignProject(t *testing.T) {
	ctx := context.Background()
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, "http://127.0.0.1/start")
	id, err := repo.SaveRecord(ctx, seed, "source-analysis", database.DefaultProjectUUID)
	require.NoError(t, err)
	_, err = loadObservedRecordVersion(ctx, repo, database.DefaultProjectUUID, id)
	require.ErrorContains(t, err, "no complete stored exchange")
	version, err := repo.SaveRecordVersion(ctx, id, seed.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\ncomplete"))))
	require.NoError(t, err)
	_, err = loadObservedRecordVersion(ctx, repo, "different-project", version)
	require.ErrorContains(t, err, "another project")
}

func TestObservedVersionAdoptionRequiresLiveReceiptToMatchSavedPair(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("fresh response"))
	}))
	defer srv.Close()
	ctx := context.Background()
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, srv.URL+"/start")
	oldUUID, err := repo.SaveRecord(ctx, seed, "source-analysis", database.DefaultProjectUUID)
	require.NoError(t, err)
	observed := probeSingleRecordWithLimit(ctx, srv.Client(), seed, seed.Target(), 4096)
	require.NotNil(t, observed)
	capture := observed.Evidence()
	require.NotNil(t, capture)
	versionUUID, err := repo.SaveRecordVersion(ctx, oldUUID, observed)
	require.NoError(t, err)
	loaded, err := loadObservedRecordVersion(ctx, repo, database.DefaultProjectUUID, versionUUID, observed)
	require.NoError(t, err)
	require.NotSame(t, observed, loaded)
	require.Equal(t, capture, loaded.Evidence())

	partial := capture.Clone()
	partial.ResponseState = evidence.StateTruncated
	partial.ContentHash = partial.Hash()
	otherDestination := capture.Clone()
	otherDestination.Service = "http://different-destination.invalid:8080"
	otherDestination.ContentHash = otherDestination.Hash()
	for _, tc := range []struct {
		name     string
		observed *httpmsg.HttpRequestResponse
	}{
		{"missing capture", nil},
		{"missing receipt", observed.WithEvidence(nil)},
		{"changed request", httpmsg.NewHttpRequestResponse(observed.Request().WithHeader("X-Changed", "yes"), observed.Response()).WithEvidence(capture)},
		{"changed response", observed.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\ndifferent response"))).WithEvidence(capture)},
		{"incomplete receipt", observed.WithEvidence(partial)},
		{"different destination", observed.WithEvidence(otherDestination)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			versions := map[string]string{oldUUID: versionUUID}
			captures := map[string]*httpmsg.HttpRequestResponse{oldUUID: tc.observed}
			agentRecords := []AgentHTTPRecord{{RecordUUID: oldUUID, URL: seed.Target(), Body: "old body"}}
			require.Error(t, adoptAgentRecordVersions(ctx, repo, database.DefaultProjectUUID, agentRecords, versions, captures))
			require.Equal(t, oldUUID, agentRecords[0].RecordUUID)
			require.Nil(t, agentRecords[0].ObservedExchange)
			swarmRecords := []*httpmsg.HttpRequestResponse{seed}
			ids := []string{oldUUID}
			require.Error(t, adoptSwarmRecordVersions(ctx, repo, database.DefaultProjectUUID, swarmRecords, ids, versions, captures))
			require.Equal(t, oldUUID, ids[0])
			require.Same(t, seed, swarmRecords[0])
		})
	}
}
