package authsession

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func reprobeRepository(t *testing.T) *database.Repository {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "reprobe.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(context.Background()))
	return database.NewRepository(db)
}

func seedReprobeRecord(t *testing.T, repo *database.Repository, target string, response bool) *database.HTTPRecord {
	t.Helper()
	raw := "POST /start HTTP/1.1\r\nHost: original.invalid\r\nAuthorization: Bearer stale\r\nContent-Length: 8\r\n\r\nold body"
	rr, err := httpmsg.ParseRawRequestWithURL(raw, target)
	require.NoError(t, err)
	if response {
		rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 401 Unauthorized\r\n\r\nold response")))
	}
	id, err := repo.SaveRecord(context.Background(), rr, "source-analysis", database.DefaultProjectUUID)
	require.NoError(t, err)
	rec, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	return rec
}

func TestReprobeRecordVersionsActualAuthRedirectExchangePreservesHistory(t *testing.T) {
	observed := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "learned", Value: "yes", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusSeeOther)
			return
		}
		observed <- r.Clone(r.Context())
		_, _ = w.Write([]byte("fresh response"))
	}))
	defer srv.Close()
	repo := reprobeRepository(t)
	old := seedReprobeRecord(t, repo, srv.URL+"/start", true)
	ctx := context.Background()
	finding := &database.Finding{ProjectUUID: database.DefaultProjectUUID, ModuleID: "legacy", FindingHash: "reprobe-history",
		OriginRecordUUID: old.UUID, URL: old.URL, Status: database.StatusTriaged}
	require.NoError(t, repo.SaveFindingDirect(ctx, finding))
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	var savedUUID string
	var saved *httpmsg.HttpRequestResponse
	id, status, err := reprobeRecord(ctx, repo, client, old, map[string]string{"Authorization": "Bearer fresh"},
		func(versionUUID string, exchange *httpmsg.HttpRequestResponse) {
			savedUUID, saved = versionUUID, exchange
		})
	require.NoError(t, err)
	require.Equal(t, id, savedUUID)
	require.NotNil(t, saved)
	require.NotNil(t, saved.Evidence())
	require.NoError(t, saved.Evidence().Validate())
	require.Equal(t, http.StatusOK, status)
	require.NotEqual(t, old.UUID, id)
	version, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, version.RawRequest, saved.Evidence().Request)
	require.Equal(t, version.RawResponse, saved.Evidence().Response)
	actual := <-observed
	require.Equal(t, "GET", version.Method)
	require.Equal(t, "/final", version.Path)
	require.Equal(t, srv.URL+"/final", version.URL)
	req := httpmsg.NewHttpRequest(version.RawRequest)
	require.Empty(t, req.Body()) // not the stored POST body plus a new GET response
	for _, name := range []string{"Authorization", "Cookie", "User-Agent", "Accept-Encoding"} {
		require.Equal(t, actual.Header.Get(name), req.Header(name), name)
	}
	require.Equal(t, "fresh response", string(version.ParsedResponse().Body()))
	history, err := repo.GetRecordByUUID(ctx, old.UUID)
	require.NoError(t, err)
	require.Equal(t, old.RawRequest, history.RawRequest)
	require.Equal(t, old.RawResponse, history.RawResponse)
	var linked string
	require.NoError(t, repo.DB().NewRaw("SELECT origin_record_uuid FROM findings WHERE finding_hash = ?", finding.FindingHash).Scan(ctx, &linked))
	require.Equal(t, old.UUID, linked)
}

func TestReprobeUnprobedRecordsReturnsVersionUUIDsWithoutMutatingSeeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer fresh" {
			t.Errorf("sent Authorization = %q, want fresh session", got)
		}
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	repo := reprobeRepository(t)
	old := seedReprobeRecord(t, repo, srv.URL+"/start", false)
	var observed *httpmsg.HttpRequestResponse
	var callbackOldUUID, callbackVersionUUID string
	versions, err := ReprobeUnprobedRecords(context.Background(), repo, database.DefaultProjectUUID, old.Hostname,
		map[string]string{"Authorization": "Bearer fresh"}, "source-analysis",
		func(oldUUID, versionUUID string, exchange *httpmsg.HttpRequestResponse) {
			callbackOldUUID, callbackVersionUUID, observed = oldUUID, versionUUID, exchange
		})
	require.NoError(t, err)
	require.Equal(t, old.UUID, callbackOldUUID)
	require.Equal(t, versions[old.UUID], callbackVersionUUID)
	require.NotNil(t, observed)
	require.NotNil(t, observed.Evidence())
	require.NoError(t, observed.Evidence().Validate())
	require.Len(t, versions, 1)
	id := versions[old.UUID]
	require.NotEmpty(t, id)
	require.NotEqual(t, old.UUID, id)
	version, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, version.RawRequest, observed.Evidence().Request)
	require.Equal(t, version.RawResponse, observed.Evidence().Response)
	require.Equal(t, http.StatusTemporaryRedirect, version.StatusCode) // no redirects remains the policy
	require.Equal(t, "/next", version.ResponseLocation)
	require.Equal(t, "Bearer fresh", httpmsg.NewHttpRequest(version.RawRequest).Header("Authorization"))
	require.Empty(t, httpmsg.NewHttpRequest(version.RawRequest).Body())
	history, err := repo.GetRecordByUUID(context.Background(), old.UUID)
	require.NoError(t, err)
	require.False(t, history.HasResponse)
	require.Equal(t, old.RawRequest, history.RawRequest)
}

type reprobeTestTransport func(*http.Request) (*http.Response, error)

func (f reprobeTestTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestReprobeRecordMissingSentCaptureDoesNotWrite(t *testing.T) {
	repo := reprobeRepository(t)
	old := seedReprobeRecord(t, repo, "http://127.0.0.1/start", false)
	client := &http.Client{Transport: reprobeTestTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader("new response")), ContentLength: 12}, nil
	})}
	id, _, err := reprobeRecord(context.Background(), repo, client, old, nil)
	require.ErrorContains(t, err, "no complete captured exchange")
	require.Empty(t, id)
	n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

func TestReprobeRecordErrorCaptureDoesNotPublishVersionOrStatus(t *testing.T) {
	for _, tc := range []struct{ name, response string }{
		{name: "completed request without response"},
		{name: "response body read error", response: "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nprefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read sent request: %v", err)
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
			repo := reprobeRepository(t)
			old := seedReprobeRecord(t, repo, srv.URL+"/start", true)
			client := srv.Client()
			client.Timeout = 2 * time.Second
			defer client.CloseIdleConnections()
			callbacks := 0
			id, status, err := reprobeRecord(ctx, repo, client, old, map[string]string{"Authorization": "Bearer fresh"},
				func(string, *httpmsg.HttpRequestResponse) { callbacks++ })
			require.Error(t, err)
			require.Zero(t, callbacks)
			if tc.response != "" {
				require.ErrorContains(t, err, io.ErrUnexpectedEOF.Error())
			}
			require.Empty(t, id)
			require.Zero(t, status) // a real partial 200 is not a successful saved reprobe
			n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			history, err := repo.GetRecordByUUID(ctx, old.UUID)
			require.NoError(t, err)
			require.Equal(t, old.RawRequest, history.RawRequest)
			require.Equal(t, old.RawResponse, history.RawResponse)
		})
	}
}
