package http

import (
	"bytes"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	httpUtils "github.com/projectdiscovery/utils/http"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestCaptureEvidenceActualHeadersBodyRedirectAndOwnership(t *testing.T) {
	body := []byte{'p', 0, 0xff, 'z'}
	type observedRequest struct {
		header stdhttp.Header
		body   []byte
	}
	observed := make(chan observedRequest, 24)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/start" {
			stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "learned", Value: "yes", Path: "/"})
			stdhttp.Redirect(w, r, "/final", stdhttp.StatusTemporaryRedirect)
			return
		}
		body, _ := io.ReadAll(r.Body)
		observed <- observedRequest{header: r.Header.Clone(), body: body}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{'R', 0, 0xff, 'S'})
	}))
	defer srv.Close()
	r := newTestRequester(t)
	view, err := r.WithAdditionalHeaders([]string{"Authorization: Bearer definitive", "X-Custom: final"})
	require.NoError(t, err)
	raw := []byte("POST " + srv.URL + "/start HTTP/1.1\r\nHost: " + strings.TrimPrefix(srv.URL, "http://") + "\r\nContent-Length: 4\r\n\r\n")
	raw = append(raw, body...)
	rr, err := httpmsg.ParseRawRequest(string(raw))
	require.NoError(t, err)
	chain, _, err := view.Execute(rr, Options{NoClustering: true})
	require.NoError(t, err)
	x := CaptureEvidence(chain)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateComplete, x.ResponseState)
	require.Equal(t, srv.URL+"/final", x.URL)
	require.True(t, bytes.HasPrefix(x.Request, []byte("POST /final HTTP/1.1\r\n")), "%q", x.Request)
	require.True(t, bytes.HasSuffix(x.Request, body))
	final := <-observed
	require.Equal(t, body, final.body)
	captured := httpmsg.NewHttpRequest(x.Request)
	for _, name := range []string{"Authorization", "X-Custom", "Cookie", "User-Agent", "Accept"} {
		require.NotEmpty(t, final.header.Get(name), name)
		require.Equal(t, final.header.Get(name), captured.Header(name), name)
	}
	original := bytes.Clone(x.Response)
	// Rewinding overwrites pooled bytes; close and subsequent calls reuse them.
	RedirectChainHops(chain)
	chain.Close()
	for i := 0; i < 20; i++ {
		other, _, err := view.Execute(makeTestRR(t, srv.URL+"/final"), Options{NoClustering: true})
		require.NoError(t, err)
		other.Close()
	}
	require.Equal(t, original, x.Response)
	require.NoError(t, x.Validate())
	require.True(t, bytes.HasSuffix(x.Response, []byte{'R', 0, 0xff, 'S'}))
}

func TestCaptureEvidenceNeverCertifiesAnIntendedTransportRequest(t *testing.T) {
	for _, opts := range []Options{{}, {RawRequest: true}, {RawRequest: true, RawRequestTarget: "/literal"}} {
		req, err := stdhttp.NewRequest("POST", "http://intended.example/original", strings.NewReader("intended"))
		require.NoError(t, err)
		resp := &stdhttp.Response{StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: io.NopCloser(strings.NewReader("response")), ContentLength: 8}
		stampCapture(resp, req, opts)
		chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
		require.NoError(t, chain.Fill())
		x := CaptureEvidence(chain)
		chain.Close()
		require.Empty(t, x.Request)
		require.Equal(t, evidence.StateMissing, x.RequestState)
		require.NotEmpty(t, x.Response)
		require.NoError(t, x.Validate())
	}
}

func TestCaptureEvidenceMissingTransportDefaultsRemainUnknown(t *testing.T) {
	req, err := stdhttp.NewRequest("POST", "http://test.example/", strings.NewReader("actual"))
	require.NoError(t, err)
	req.Header.Set("Content-Length", "999") // std transport ignores the stale input header.
	resp := &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: make(stdhttp.Header), Body: io.NopCloser(strings.NewReader("body")), ContentLength: 4}
	stampCapture(resp, req, Options{})
	chain := httpUtils.NewResponseChain(resp, MaxBodyRead)
	require.NoError(t, chain.Fill())
	x := CaptureEvidence(chain)
	chain.Close()
	require.Equal(t, evidence.StateUnknown, x.RequestState)
	require.Equal(t, "6", httpmsg.NewHttpRequest(x.Request).Header("Content-Length"))
	require.NotContains(t, string(x.Request), "Accept-Encoding:")
	require.True(t, bytes.HasSuffix(x.Request, []byte("actual")))
	require.NoError(t, x.Validate())
}

func TestCaptureEvidenceLimitedBodyAndHEADBoundary(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		req, err := stdhttp.NewRequest(method, "http://test.example/", nil)
		require.NoError(t, err)
		body := "long-response"
		if method == "HEAD" {
			body = ""
		}
		resp := &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: 13}
		stampCapture(resp, req, Options{})
		chain := httpUtils.NewResponseChain(resp, 4)
		require.NoError(t, chain.Fill())
		x := CaptureEvidence(chain)
		chain.Close()
		if method == "HEAD" {
			require.Equal(t, evidence.StateComplete, x.ResponseState)
		} else {
			require.Equal(t, evidence.StateTruncated, x.ResponseState)
		}
		require.NoError(t, x.Validate())
	}
}

func TestCaptureEvidenceClusteredResponseIsNotFreshCapture(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "response")
	}))
	defer srv.Close()
	client := newTestRequester(t)
	rr := makeTestRR(t, srv.URL+"/probe")
	for i := 0; i < 2; i++ {
		chain, _, err := client.Execute(rr, Options{})
		require.NoError(t, err)
		x := CaptureEvidence(chain)
		chain.Close()
		if i == 0 {
			require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
			require.Equal(t, evidence.StateComplete, x.RequestState)
			require.Equal(t, evidence.StateComplete, x.ResponseState)
		} else {
			require.Equal(t, evidence.ProvenanceCached, x.Provenance)
			require.Equal(t, evidence.StateUnknown, x.RequestState)
			require.Equal(t, evidence.StateUnknown, x.ResponseState)
		}
		require.NoError(t, x.Validate())
	}
	require.Equal(t, int64(1), hits.Load())
}

func TestCaptureEvidenceRawBytesAreAuthoritative(t *testing.T) {
	r := newTestRequester(t)
	addr, head := rawLineListener(t)
	rr := makeTestRR(t, "http://"+addr+"/")
	raw := []byte("GET /literal HTTP/1.1\r\nHost: " + addr + "\r\nX-Proof: two\r\nX-Proof: one\r\n\r\n")
	chain, _, err := r.Execute(rr, Options{RawBytes: raw})
	require.NoError(t, err)
	x := CaptureEvidence(chain)
	chain.Close()
	require.Equal(t, raw, x.Request)
	require.Equal(t, "http://"+addr+"/literal", x.URL)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Contains(t, <-head, "GET /literal HTTP/1.1")
}
