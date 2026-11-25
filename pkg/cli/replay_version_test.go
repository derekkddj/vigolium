package cli

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/replay"
)

func replayVersionFixture(t *testing.T, target string) (*database.Repository, *database.HTTPRecord) {
	t.Helper()
	directRowFixture(t)
	swapGlobal(t, &globalStateless, false)
	swapGlobal(t, &globalGlobDB, "")
	db, err := getDB()
	require.NoError(t, err)
	repo := database.NewRepository(db)
	raw := "POST /start HTTP/1.1\r\nHost: original.invalid\r\nAuthorization: Bearer stale\r\nContent-Length: 8\r\n\r\nold body"
	rr, err := httpmsg.ParseRawRequestWithURL(raw, target)
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 401 Unauthorized\r\n\r\nold response")))
	id, err := repo.SaveRecord(context.Background(), rr, database.RecordSourceIngestCLI, database.DefaultProjectUUID)
	require.NoError(t, err)
	old, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	return repo, old
}

func TestReplayVersionCapturesAuthRedirectAndAdoptsUUID(t *testing.T) {
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
	repo, old := replayVersionFixture(t, srv.URL+"/start")
	swapGlobal(t, &replayInReplace, true)
	swapGlobal(t, &replayNoRedirects, false)
	cookieJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := replay.NewClient(cookieJar, 0, proxyenv.Choice{})
	defer client.CloseIdleConnections()
	src := sourceFromDBRecord(old)
	out, err := (&replayRun{client: client}).one(context.Background(), src, map[string]string{"Authorization": "Bearer fresh"})
	require.NoError(t, err)
	require.NotEqual(t, old.UUID, out.RecordUUID)
	require.Equal(t, out.RecordUUID, src.RecordUUID)
	version, err := repo.GetRecordByUUID(context.Background(), out.RecordUUID)
	require.NoError(t, err)
	require.Equal(t, "/final", version.Path)
	require.Equal(t, "GET", version.Method)
	req := httpmsg.NewHttpRequest(version.RawRequest)
	require.Empty(t, req.Body())
	actual := <-observed
	for _, name := range []string{"Authorization", "Cookie", "User-Agent", "Accept-Encoding"} {
		require.Equal(t, actual.Header.Get(name), req.Header(name), name)
	}
	require.Equal(t, "fresh response", string(version.ParsedResponse().Body()))
	require.Equal(t, out.Result.Replay.Exchange.Request, version.RawRequest)
	require.Equal(t, out.Result.Replay.Exchange.Response, version.RawResponse)
	history, err := repo.GetRecordByUUID(context.Background(), old.UUID)
	require.NoError(t, err)
	require.Equal(t, old.RawRequest, history.RawRequest)
	require.Equal(t, old.RawResponse, history.RawResponse)
}

func TestPersistReplayResponseRejectsMissingOrIncompleteCapture(t *testing.T) {
	repo, old := replayVersionFixture(t, "http://127.0.0.1/start")
	for _, state := range []evidence.State{evidence.StateMissing, evidence.StateUnknown, evidence.StateTruncated} {
		t.Run(string(state), func(t *testing.T) {
			src := sourceFromDBRecord(old)
			result := &replay.Result{RawMutatedRequest: []byte("intended only"), Replay: &replay.Summary{Status: 200, RawBody: []byte("new response")}}
			if state != evidence.StateMissing {
				x := evidence.NewExchange("http://127.0.0.1", "http://127.0.0.1/start", old.RawRequest,
					[]byte("HTTP/1.1 200 OK\r\n\r\nnew response"), evidence.ProvenanceCaptured)
				x.RequestState = state
				x.ContentHash = x.Hash()
				result.Replay.Exchange = x
			}
			err := persistReplayResponse(context.Background(), src, result)
			require.ErrorContains(t, err, "no complete captured exchange")
			require.Equal(t, old.UUID, src.RecordUUID)
		})
	}
	n, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	history, err := repo.GetRecordByUUID(context.Background(), old.UUID)
	require.NoError(t, err)
	require.Equal(t, old.RawRequest, history.RawRequest)
	require.Equal(t, old.RawResponse, history.RawResponse)
}
