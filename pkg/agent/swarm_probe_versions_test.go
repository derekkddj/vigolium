package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestValidateProbeAndSavePublishesAlignedSentVersionsWithLineage(t *testing.T) {
	type requestSeen struct {
		body, host, auth, userAgent string
	}
	seen := make(chan requestSeen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- requestSeen{string(body), r.Host, r.Header.Get("Authorization"), r.Header.Get("User-Agent")}
		_, _ = w.Write([]byte("fresh"))
	}))
	defer srv.Close()
	ctx := context.Background()
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, srv.URL+"/start").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 401 Unauthorized\r\n\r\nold response")))
	oldUUID, err := repo.SaveRecordWithLineage(ctx, seed, "source-analysis", database.DefaultProjectUUID, database.RecordLineage{
		ParentUUID: "historical-parent", RootUUID: "historical-root", Target: "submitted input", ChainTruncated: true, Remarks: []string{"seed note"},
	})
	require.NoError(t, err)
	records := []*httpmsg.HttpRequestResponse{nil, seed}
	ids := (&SwarmRunner{repo: repo}).validateProbeAndSave(ctx, records, []string{"invalid", "new note"}, []string{"", oldUUID},
		map[string]string{"Authorization": "Bearer fresh"}, "agent-swarm-source", database.DefaultProjectUUID, ProbeConfig{Concurrency: 1})
	require.Len(t, ids, 2)
	require.Empty(t, ids[0])
	require.NotEmpty(t, ids[1])
	require.NotEqual(t, oldUUID, ids[1])
	require.NotSame(t, seed, records[1])
	require.Equal(t, http.StatusOK, records[1].Response().StatusCode())
	actual := <-seen
	require.Equal(t, "old body", actual.body)
	require.Equal(t, actual.body, string(records[1].Request().Body()))
	require.Equal(t, actual.host, records[1].Request().Header("Host"))
	require.Equal(t, "original.invalid", actual.host)
	require.Equal(t, "Bearer fresh", actual.auth)
	require.Equal(t, actual.auth, records[1].Request().Header("Authorization"))
	require.Equal(t, actual.userAgent, records[1].Request().Header("User-Agent"))
	require.NotEmpty(t, actual.userAgent)
	require.Equal(t, evidence.StateComplete, records[1].Evidence().RequestState)
	stored, err := repo.GetRecordByUUID(ctx, ids[1])
	require.NoError(t, err)
	require.Equal(t, records[1].Request().Raw(), stored.RawRequest)
	require.Equal(t, records[1].Response().Raw(), stored.RawResponse)
	require.Equal(t, "source-analysis", stored.Source)
	require.Equal(t, "historical-parent", stored.ParentUUID)
	require.Equal(t, "historical-root", stored.RootUUID)
	require.Equal(t, "submitted input", stored.Target)
	require.True(t, stored.ChainTruncated)
	require.Contains(t, stored.Remarks, "seed note")
	require.Contains(t, stored.Remarks, "new note")
	history, err := repo.GetRecordByUUID(ctx, oldUUID)
	require.NoError(t, err)
	require.Equal(t, seed.Request().Raw(), history.RawRequest)
	require.Equal(t, seed.Response().Raw(), history.RawResponse)
	require.Equal(t, "Bearer stale", seed.Request().Header("Authorization"))
}

func TestSwarmReprobeAdoptsPartialSuccessIntoCurrentListsOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	ctx := context.Background()
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, srv.URL+"/start")
	broken, err := httpmsg.ParseRawRequestWithURL("POST /broken HTTP/1.1\r\nHost: original.invalid\r\n\r\n", srv.URL+"/broken")
	require.NoError(t, err)
	oldUUID, err := repo.SaveRecord(ctx, seed, "agent-swarm-source", database.DefaultProjectUUID)
	require.NoError(t, err)
	brokenUUID, err := repo.SaveRecord(ctx, broken, "agent-swarm-source", database.DefaultProjectUUID)
	require.NoError(t, err)
	finding := &database.Finding{ProjectUUID: database.DefaultProjectUUID, ModuleID: "history", FindingHash: "swarm-version-history", OriginRecordUUID: oldUUID, URL: seed.Target(), Status: database.StatusTriaged}
	require.NoError(t, repo.SaveFindingDirect(ctx, finding))
	records := []*httpmsg.HttpRequestResponse{seed, broken, seed}
	ids := []string{oldUUID, brokenUUID, oldUUID}
	versions, err := (&SwarmRunner{repo: repo}).reprobeUnprobedRecords(ctx, database.DefaultProjectUUID, hostnameFromURL(srv.URL),
		map[string]string{"Authorization": "Bearer fresh"}, "agent-swarm-source", records, ids)
	require.ErrorContains(t, err, "reprobe "+brokenUUID)
	require.Len(t, versions, 1)
	require.NotEmpty(t, versions[oldUUID])
	for _, i := range []int{0, 2} {
		require.Equal(t, versions[oldUUID], ids[i])
		require.NotSame(t, seed, records[i])
		require.Empty(t, records[i].Request().Body()) // fallback actually sent no body
		require.Equal(t, "Bearer fresh", records[i].Request().Header("Authorization"))
		require.Equal(t, http.StatusTemporaryRedirect, records[i].Response().StatusCode())
		capture := records[i].Evidence()
		require.NotNil(t, capture)
		require.Equal(t, evidence.ProvenanceCaptured, capture.Provenance)
		require.NoError(t, capture.Validate())
		stored, err := repo.GetRecordByUUID(ctx, ids[i])
		require.NoError(t, err)
		require.Equal(t, stored.RawRequest, capture.Request)
		require.Equal(t, stored.RawResponse, capture.Response)
	}
	require.NotSame(t, records[0], records[2])
	require.Equal(t, records[0].Evidence(), records[2].Evidence())
	require.Equal(t, brokenUUID, ids[1])
	require.Same(t, broken, records[1])
	require.False(t, records[1].HasResponse())
	require.Contains(t, formatRouteStatusSummary(records), "3xx: 2")
	require.Contains(t, formatRouteStatusSummary(records), "no-response: 1")
	history, err := repo.GetRecordByUUID(ctx, oldUUID)
	require.NoError(t, err)
	require.Equal(t, seed.Request().Raw(), history.RawRequest)
	require.False(t, history.HasResponse)
	failedHistory, err := repo.GetRecordByUUID(ctx, brokenUUID)
	require.NoError(t, err) // failed request-only seeds are historical records too
	require.Equal(t, broken.Request().Raw(), failedHistory.RawRequest)
	require.False(t, failedHistory.HasResponse)
	require.Empty(t, failedHistory.RawResponse)
	var linked string
	require.NoError(t, repo.DB().NewRaw("SELECT origin_record_uuid FROM findings WHERE finding_hash = ?", finding.FindingHash).Scan(ctx, &linked))
	require.Equal(t, oldUUID, linked)
}

func TestSwarmRecordUUIDsAfterProbeKeepsRetryIdentitySeparateFromSuccess(t *testing.T) {
	previousUUIDs := []string{"failed-seed", "successful-seed", ""}
	savedUUIDs := []string{"", "complete-version", "", "new-record"}
	currentUUIDs := swarmRecordUUIDsAfterProbe(previousUUIDs, savedUUIDs)
	require.Equal(t, []string{"failed-seed", "complete-version", "", "new-record"}, currentUUIDs)
	require.Equal(t, []string{"failed-seed", "successful-seed", ""}, previousUUIDs)
	require.Equal(t, []string{"", "complete-version", "", "new-record"}, savedUUIDs)
}

func TestSourceAnalysisProbeFailuresRetainSeedForSwarmFallbackAdoption(t *testing.T) {
	for _, tc := range []struct {
		name, response string
	}{
		{name: "no response"},
		{name: "incomplete response", response: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nprefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt := hits.Add(1)
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read sent request: %v", err)
					return
				}
				if attempt > 2 {
					_, _ = w.Write([]byte("fresh fallback"))
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer conn.Close()
				if tc.response != "" {
					if _, err := io.WriteString(conn, tc.response); err != nil {
						t.Errorf("write partial response: %v", err)
					}
				}
			}))
			defer srv.Close()
			ctx := context.Background()
			repo := recordVersionTestRepo(t)
			runner := &SwarmRunner{repo: repo}
			agentRecords := []AgentHTTPRecord{{
				Method: "POST", URL: srv.URL + "/start", Body: "old body", Notes: "source route",
				Headers: map[string]string{"Authorization": "Bearer stale"},
			}}
			count, err := (&Engine{repo: repo}).ingestHTTPRecords(ctx, agentRecords, Options{
				Source: "source-analysis", ProjectUUID: database.DefaultProjectUUID,
			})
			require.NoError(t, err)
			require.Equal(t, 1, count)
			oldUUID := agentRecords[0].RecordUUID
			require.NotEmpty(t, oldUUID)
			seed, err := repo.GetRecordByUUID(ctx, oldUUID)
			require.NoError(t, err)
			require.Equal(t, "source-analysis", seed.Source)
			require.NotEqual(t, hostnameFromURL(srv.URL), seed.Hostname) // service hostname excludes the test server's port
			records, notes, recordUUIDs := filterSourceRecordsByHostname(agentRecords, srv.URL)
			require.Len(t, records, 1)
			require.Equal(t, []string{oldUUID}, recordUUIDs)
			notes[0] = "failed probe note"
			authHeaders := map[string]string{"Authorization": "Bearer fresh"}
			savedUUIDs := runner.validateProbeAndSave(ctx, records, notes, recordUUIDs, authHeaders,
				"agent-swarm-source", database.DefaultProjectUUID, ProbeConfig{Concurrency: 1, Timeout: 2 * time.Second})
			require.EqualValues(t, 2, hits.Load())     // initial probe and its retry both failed
			require.Equal(t, []string{""}, savedUUIDs) // no failed probe claimed as a saved success
			require.False(t, records[0].HasResponse())
			require.Nil(t, records[0].Evidence())
			n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)

			// Use the production source-analysis assignment, then its fallback queries.
			recordUUIDs = swarmRecordUUIDsAfterProbe(recordUUIDs, savedUUIDs)
			require.Equal(t, []string{oldUUID}, recordUUIDs)
			for _, source := range []string{"source-analysis", "agent-swarm-source"} {
				versions, err := runner.reprobeUnprobedRecords(ctx, database.DefaultProjectUUID, hostnameFromURL(srv.URL), authHeaders, source, records, recordUUIDs)
				require.NoError(t, err)
				if source == "source-analysis" {
					require.NotEmpty(t, versions[oldUUID])
					require.Equal(t, versions[oldUUID], recordUUIDs[0])
				}
			}
			require.EqualValues(t, 3, hits.Load())
			require.NotEqual(t, oldUUID, recordUUIDs[0])
			require.Equal(t, []string{""}, savedUUIDs) // fallback identity is separate from probe success
			require.Equal(t, "Bearer fresh", records[0].Request().Header("Authorization"))
			require.Empty(t, records[0].Request().Body()) // the fallback sent no source-intended body
			require.True(t, records[0].HasResponse())
			require.Equal(t, "fresh fallback", string(records[0].Response().Body()))
			liveEvidence := records[0].Evidence()
			require.NotNil(t, liveEvidence)
			require.Equal(t, evidence.ProvenanceCaptured, liveEvidence.Provenance)
			require.Equal(t, evidence.StateComplete, liveEvidence.RequestState)
			require.Equal(t, evidence.StateComplete, liveEvidence.ResponseState)
			require.NoError(t, liveEvidence.Validate())
			stored, err := repo.GetRecordByUUID(ctx, recordUUIDs[0])
			require.NoError(t, err)
			require.Equal(t, "source-analysis", stored.Source)
			require.Equal(t, records[0].Request().Raw(), stored.RawRequest)
			require.Equal(t, records[0].Response().Raw(), stored.RawResponse)
			require.Equal(t, stored.RawRequest, liveEvidence.Request)
			require.Equal(t, stored.RawResponse, liveEvidence.Response)
			history, err := repo.GetRecordByUUID(ctx, oldUUID)
			require.NoError(t, err)
			require.Equal(t, seed.RawRequest, history.RawRequest)
			require.Equal(t, seed.RawResponse, history.RawResponse)
			require.False(t, history.HasResponse)
			require.Equal(t, "old body", string(httpmsg.NewHttpRequest(history.RawRequest).Body()))
			require.Equal(t, "Bearer stale", httpmsg.NewHttpRequest(history.RawRequest).Header("Authorization"))
			require.NotContains(t, history.Remarks, "failed probe note")
		})
	}
}

func TestSwarmAdoptionReadFailureDoesNotReplaceUUIDOrExchange(t *testing.T) {
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, "http://127.0.0.1/start")
	records := []*httpmsg.HttpRequestResponse{seed}
	ids := []string{"old"}
	err := adoptSwarmRecordVersions(context.Background(), repo, database.DefaultProjectUUID, records, ids, map[string]string{"old": "missing-version"})
	require.Error(t, err)
	require.Equal(t, []string{"old"}, ids)
	require.Same(t, seed, records[0])
}

func TestProbeSingleRecordAdoptsFinalRedirectRequestAndResponse(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "learned", Value: "yes", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusSeeOther)
			return
		}
		seen <- r.Clone(r.Context())
		_, _ = w.Write([]byte("final response"))
	}))
	defer srv.Close()
	seed := recordVersionTestRequest(t, srv.URL+"/start")
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	probed := probeSingleRecordWithLimit(context.Background(), client, seed, srv.URL+"/start", 4096)
	require.NotNil(t, probed)
	actual := <-seen
	require.Equal(t, "GET", probed.Request().Method())
	require.Equal(t, "/final", probed.Request().Path())
	require.Empty(t, probed.Request().Body())
	for _, name := range []string{"Authorization", "Cookie", "User-Agent", "Accept-Encoding"} {
		require.Equal(t, actual.Header.Get(name), probed.Request().Header(name), name)
	}
	require.Equal(t, actual.Host, probed.Request().Header("Host"))
	require.Equal(t, "final response", string(probed.Response().Body()))
	require.Equal(t, evidence.StateComplete, probed.Evidence().RequestState)
	require.Equal(t, evidence.StateComplete, probed.Evidence().ResponseState)
	require.False(t, seed.HasResponse())
	require.Equal(t, "old body", string(seed.Request().Body()))
}

type swarmUntracedTransport func(*http.Request) (*http.Response, error)

func (f swarmUntracedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProbeSingleRecordRejectsMissingAndIncompleteCaptures(t *testing.T) {
	t.Run("missing sent capture", func(t *testing.T) {
		seed := recordVersionTestRequest(t, "http://127.0.0.1/start")
		client := &http.Client{Transport: swarmUntracedTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{Request: r, StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header: make(http.Header), Body: io.NopCloser(strings.NewReader("new response")), ContentLength: 12}, nil
		})}
		require.Nil(t, probeSingleRecordWithLimit(context.Background(), client, seed, seed.Target(), 4096))
		require.False(t, seed.HasResponse())
	})
	t.Run("body limit", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 512)))
		}))
		defer srv.Close()
		seed := recordVersionTestRequest(t, srv.URL+"/start")
		require.Nil(t, probeSingleRecordWithLimit(context.Background(), srv.Client(), seed, seed.Target(), 16))
		require.False(t, seed.HasResponse())
	})
}

func TestChangedProbeAuthInvalidatesResponseBeforeFailedProbe(t *testing.T) {
	seed := recordVersionTestRequest(t, "http://127.0.0.1/start").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 401 Unauthorized\r\n\r\nold response")))
	records := []*httpmsg.HttpRequestResponse{seed}
	refreshProbeAuth(records, map[string]string{"Authorization": "Bearer fresh"})
	require.False(t, records[0].HasResponse())
	require.Nil(t, records[0].Evidence())
	require.Equal(t, "Bearer fresh", records[0].Request().Header("Authorization"))
	require.True(t, seed.HasResponse())
	require.Equal(t, "Bearer stale", seed.Request().Header("Authorization"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probeRecordsWithConfig(ctx, records, ProbeConfig{Concurrency: 1, Timeout: time.Second})
	require.False(t, records[0].HasResponse())
}

func TestValidateProbeAndSaveRejectsFailedAndIncompleteProbes(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		bodyLimit      bool
	}{
		{name: "completed request without response"},
		{name: "response body read error", response: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nprefix"},
		{name: "body limit", bodyLimit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read sent request: %v", err)
					return
				}
				if tc.bodyLimit {
					_, _ = w.Write([]byte(strings.Repeat("x", 512)))
					return
				}
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("hijack: %v", err)
					return
				}
				defer conn.Close()
				if tc.response != "" {
					if _, err := io.WriteString(conn, tc.response); err != nil {
						t.Errorf("write partial response: %v", err)
					}
				}
			}))
			defer srv.Close()
			ctx := context.Background()
			repo := recordVersionTestRepo(t)
			seed := recordVersionTestRequest(t, srv.URL+"/start").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 401 Unauthorized\r\n\r\nold response")))
			oldUUID, err := repo.SaveRecord(ctx, seed, "source-analysis", database.DefaultProjectUUID)
			require.NoError(t, err)
			records := []*httpmsg.HttpRequestResponse{nil, seed}
			ids := (&SwarmRunner{repo: repo}).validateProbeAndSave(ctx, records, []string{"", "failed probe note"}, []string{"", oldUUID},
				map[string]string{"Authorization": "Bearer fresh"}, "agent-swarm-source", database.DefaultProjectUUID,
				ProbeConfig{Concurrency: 1, Timeout: 2 * time.Second, MaxBodySize: 16})
			require.Equal(t, []string{"", ""}, ids)
			require.EqualValues(t, 2, hits.Load()) // original probe and the existing retry
			require.NotSame(t, seed, records[1])
			require.False(t, records[1].HasResponse())
			require.Nil(t, records[1].Evidence())
			require.Equal(t, "Bearer fresh", records[1].Request().Header("Authorization"))
			require.Equal(t, "Bearer stale", seed.Request().Header("Authorization"))
			history, err := repo.GetRecordByUUID(ctx, oldUUID)
			require.NoError(t, err)
			require.Equal(t, seed.Request().Raw(), history.RawRequest)
			require.Equal(t, seed.Response().Raw(), history.RawResponse)
			require.NotContains(t, history.Remarks, "failed probe note")
			n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
		})
	}
}

func TestValidateProbeAndSaveDoesNotPromoteExplicitPartialReceipt(t *testing.T) {
	ctx := context.Background()
	repo := recordVersionTestRepo(t)
	seed := recordVersionTestRequest(t, "http://127.0.0.1/start").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nprefix")))
	x := evidence.NewExchange("http://127.0.0.1", seed.Target(), seed.Request().Raw(), seed.Response().Raw(), evidence.ProvenanceCaptured)
	x.ResponseState = evidence.StateTruncated
	x.ContentHash = x.Hash()
	records := []*httpmsg.HttpRequestResponse{seed.WithEvidence(x)}
	ids := (&SwarmRunner{repo: repo}).validateProbeAndSave(ctx, records, nil, nil, nil, "agent-swarm", database.DefaultProjectUUID, ProbeConfig{Concurrency: 1})
	require.Equal(t, []string{""}, ids)
	require.Equal(t, evidence.StateTruncated, records[0].Evidence().ResponseState)
	n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
}
