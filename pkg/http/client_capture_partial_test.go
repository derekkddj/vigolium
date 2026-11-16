package http

import (
	"errors"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestDoCapturedCompletedWriteWithoutAnswerRetainsRequestOnly(t *testing.T) {
	sent := make(chan string, 1)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		sent <- string(body)
		conn, _, err := w.(stdhttp.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close() // the request arrived, but no HTTP response was sent
		}
	}))
	defer srv.Close()
	req, err := stdhttp.NewRequest("POST", srv.URL+"/timeout", strings.NewReader("actually sent"))
	require.NoError(t, err)
	chain, err := DoCaptured(srv.Client(), req, 1024)
	require.Error(t, err)
	require.NotNil(t, chain)
	x := CaptureEvidence(chain)
	chain.Close()
	require.NoError(t, x.Validate())
	require.Equal(t, "actually sent", <-sent)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateMissing, x.ResponseState)
	require.Empty(t, x.Response, "no synthetic status-zero response may become evidence")
	require.True(t, strings.HasSuffix(string(x.Request), "\r\n\r\nactually sent"))
}

func TestDoCapturedUnexpectedEOFReturnsErrorAndAvailableResponse(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		conn, rw, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial")
		_ = rw.Flush()
	}))
	defer srv.Close()
	req, err := stdhttp.NewRequest("GET", srv.URL+"/partial", nil)
	require.NoError(t, err)
	chain, err := DoCaptured(srv.Client(), req, 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "normalization must not hide a body read failure")
	require.NotNil(t, chain)
	x := CaptureEvidence(chain)
	chain.Close()
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateTruncated, x.ResponseState)
	rr, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	require.Equal(t, []byte("partial"), rr.Response().Body())
	require.Equal(t, "20", rr.Response().Header("Content-Length"))
}

type failingCaptureBody struct {
	closed bool
}

var errCaptureRead = errors.New("capture fixture read failed")

func (b *failingCaptureBody) Read(p []byte) (int, error) {
	return copy(p, []byte{'a', 0, 0xff}), errCaptureRead
}
func (b *failingCaptureBody) Close() error { b.closed = true; return nil }

func TestDoCapturedFillFailureRetainsBinaryBytesAndClosesBody(t *testing.T) {
	body := &failingCaptureBody{}
	client := &stdhttp.Client{Transport: captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		// An instrumented transport certifies only these reported headers/write.
		trace := httptrace.ContextClientTrace(req.Context())
		trace.WroteHeaderField("Host", []string{req.URL.Host})
		trace.WroteHeaders()
		trace.WroteRequest(httptrace.WroteRequestInfo{})
		return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: body, ContentLength: -1}, nil
	})}
	req, err := stdhttp.NewRequest("GET", "http://fixture.invalid/partial", nil)
	require.NoError(t, err)
	chain, err := DoCaptured(client, req, 1024)
	require.Error(t, err)
	require.NotNil(t, chain)
	x := CaptureEvidence(chain)
	chain.Close()
	require.True(t, body.closed)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateTruncated, x.ResponseState)
	require.True(t, strings.HasSuffix(string(x.Response), string([]byte{'a', 0, 0xff})))
}

func TestDoCapturedUntracedFailureReturnsNoInventedRequest(t *testing.T) {
	client := &stdhttp.Client{Transport: captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		return nil, errCaptureRead
	})}
	req, err := stdhttp.NewRequest("GET", "http://intended.invalid/not-sent", nil)
	require.NoError(t, err)
	chain, err := DoCaptured(client, req, 1024)
	require.ErrorIs(t, err, errCaptureRead)
	require.Nil(t, chain)
}
