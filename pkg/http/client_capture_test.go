package http

import (
	"io"
	stdhttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestDoCapturedFinalHeadersRedirectAndBody(t *testing.T) {
	observed := make(chan *stdhttp.Request, 1)
	bodies := make(chan string, 1)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/start" {
			stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "learned", Value: "yes", Path: "/"})
			stdhttp.Redirect(w, r, "/final", stdhttp.StatusTemporaryRedirect)
			return
		}
		body, _ := io.ReadAll(r.Body)
		observed <- r.Clone(r.Context())
		bodies <- string(body)
		_, _ = w.Write([]byte("final body"))
	}))
	defer srv.Close()
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	req, err := stdhttp.NewRequest("POST", srv.URL+"/start", strings.NewReader("sent body"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer fresh")
	chain, err := DoCaptured(client, req, 1024)
	require.NoError(t, err)
	x := CaptureEvidence(chain)
	chain.Close()
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateComplete, x.ResponseState)
	require.Equal(t, srv.URL+"/final", x.URL)
	rr, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	require.Equal(t, "/final", rr.Request().Path())
	require.Equal(t, <-bodies, string(rr.Request().Body()))
	final := <-observed
	for _, name := range []string{"Authorization", "Cookie", "Accept-Encoding", "User-Agent"} {
		require.NotEmpty(t, final.Header.Get(name), name)
		require.Equal(t, final.Header.Get(name), rr.Request().Header(name), name)
	}
	require.Equal(t, "final body", string(rr.Response().Body()))
}

type captureTestTransport func(*stdhttp.Request) (*stdhttp.Response, error)

func (f captureTestTransport) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	return f(req)
}

func TestDoCapturedUntracedTransportNeverFabricatesRequest(t *testing.T) {
	client := &stdhttp.Client{Transport: captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: io.NopCloser(strings.NewReader("response")), ContentLength: 8}, nil
	})}
	req, err := stdhttp.NewRequest("GET", "http://intended.invalid/original", nil)
	require.NoError(t, err)
	chain, err := DoCaptured(client, req, 1024)
	require.NoError(t, err)
	defer chain.Close()
	x := CaptureEvidence(chain)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateMissing, x.RequestState)
	require.Empty(t, x.Request)
}

func TestDoCapturedBodyIsSentBytesNotGetBodyRecipe(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	req, err := stdhttp.NewRequest("POST", srv.URL, strings.NewReader("actual"))
	require.NoError(t, err)
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("different intended bytes")), nil
	}
	chain, err := DoCaptured(srv.Client(), req, 1024)
	require.NoError(t, err)
	defer chain.Close()
	x := CaptureEvidence(chain)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateComplete, x.RequestState)
	rr, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	require.Equal(t, "actual", string(rr.Request().Body()))
	require.Equal(t, "actual", string(rr.Response().Body()))
}

func TestDoCapturedHonorsExplicitBodyLimit(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.(stdhttp.Flusher).Flush() // chunked: no Content-Length to detect clipping
		_, _ = w.Write([]byte("more than four bytes"))
	}))
	defer srv.Close()
	req, err := stdhttp.NewRequest("GET", srv.URL, nil)
	require.NoError(t, err)
	chain, err := DoCaptured(srv.Client(), req, 4)
	require.NoError(t, err)
	defer chain.Close()
	x := CaptureEvidence(chain)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateTruncated, x.ResponseState)
}
