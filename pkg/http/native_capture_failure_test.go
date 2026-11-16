package http

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// An instrumented fixture certifies only headers and the body it actually reads.
func completeNativeCaptureWrite(req *stdhttp.Request, extra stdhttp.Header) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	trace := httptrace.ContextClientTrace(req.Context())
	trace.WroteHeaderField("Host", []string{req.URL.Host})
	for name, values := range extra {
		trace.WroteHeaderField(name, values)
	}
	trace.WroteHeaders()
	trace.WroteRequest(httptrace.WroteRequestInfo{})
}

type nativeFixtureRoundTripper struct{ next stdhttp.RoundTripper }

func (t *nativeFixtureRoundTripper) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	return t.next.RoundTrip(req)
}

func (t *nativeFixtureRoundTripper) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func nativeCaptureFixtureRequester(t *testing.T, transport stdhttp.RoundTripper) *Requester {
	t.Helper()
	r := newTestRequester(t)
	r.retries = 0
	transport = &nativeFixtureRoundTripper{next: transport}
	r.client.HTTPClient.Transport = transport
	r.clientNoRedir.HTTPClient.Transport = transport
	pinHTTP2Fallback(r.client, transport)
	pinHTTP2Fallback(r.clientNoRedir, transport)
	t.Cleanup(r.CloseIdleConnections)
	return r
}

func TestNativeCaptureConnectionDropOwnsRequestWithoutResponseOrChain(t *testing.T) {
	seen := make(chan []byte, 1)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
		body, _ := io.ReadAll(req.Body)
		seen <- body
		conn, _, err := w.(stdhttp.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	r := newTestRequester(t)
	r.retries = 0
	t.Cleanup(r.CloseIdleConnections)
	payload := []byte{'s', 0, 0xff, 't'}
	rr, err := httpmsg.ParseRawRequest("POST " + srv.URL + "/drop HTTP/1.1\r\nHost: " + strings.TrimPrefix(srv.URL, "http://") + "\r\nContent-Length: 4\r\n\r\n" + string(payload))
	require.NoError(t, err)
	r.customHeaders["Authorization"] = "Bearer actually-sent"
	chain, elapsed, err := r.Execute(rr, Options{NoClustering: true})
	require.Error(t, err)
	require.Nil(t, chain, "native error callers must not inherit pooled buffers")
	require.Positive(t, elapsed, "a failed send reports its own send-to-failure time")
	require.Equal(t, payload, <-seen)
	require.EqualValues(t, 1, r.RequestsSent())
	require.Equal(t, TransportErrReset, ClassifyTransportError(err))
	var captureErr *RequestCaptureError
	require.ErrorAs(t, err, &captureErr)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateMissing, x.ResponseState)
	require.Empty(t, x.Response, "no status-zero response may be serialized")
	require.Contains(t, string(x.Request), "Authorization: Bearer actually-sent\r\n")
	require.True(t, bytes.HasSuffix(x.Request, payload))
	original := x.Clone()
	x.Request[0] = 'X'
	x.URL = "http://mutated.invalid/"
	require.Equal(t, original, CaptureFailureEvidence(err), "the error's receipt is immutable")
}

func TestNativeCaptureSentTimeoutPreservesDeadlineAndReceipt(t *testing.T) {
	seen := make(chan struct{}, 1)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
		seen <- struct{}{}
		<-req.Context().Done()
	}))
	defer srv.Close()
	r := newTestRequester(t)
	r.retries = 0
	t.Cleanup(r.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	chain, _, err := r.ExecuteContext(ctx, makeTestRR(t, srv.URL+"/sent-timeout"), Options{NoClustering: true, IgnoreTimeoutTracking: true})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, chain)
	select {
	case <-seen:
	default:
		t.Fatal("timeout fixture did not receive the request")
	}
	// retryablehttp's policy replaces the transport error with ctx.Err() when
	// the context expires; capture must preserve that cause, not invent a URL error.
	require.ErrorIs(t, err, ctx.Err())
	var captureErr *RequestCaptureError
	require.ErrorAs(t, err, &captureErr)
	require.True(t, captureErr.Unwrap() == ctx.Err(), "capture must preserve the exact retry policy error")
	require.Equal(t, TransportErrTimeout, ClassifyTransportError(err))
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateMissing, x.ResponseState)
	require.Empty(t, x.Response)
	require.EqualValues(t, 1, r.RequestsSent())
	original := x.Clone()
	require.NotEmpty(t, x.Request)
	x.Request[0] = 'X'
	x.URL = "http://mutated.invalid/"
	require.Equal(t, original, CaptureFailureEvidence(err), "timeout receipt clones cannot mutate the error-owned evidence")
}

func TestNativeCaptureUnexpectedEOFReturnsOwnedPartialBody(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
		conn, rw, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 20\r\nX-Actual: yes\r\n\r\npartial\x00\xff")
		_ = rw.Flush()
	}))
	defer srv.Close()
	r := newTestRequester(t)
	r.retries = 0
	t.Cleanup(r.CloseIdleConnections)
	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/partial"), Options{NoClustering: true})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "body normalization must not hide failure")
	require.Nil(t, chain)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateTruncated, x.ResponseState)
	rr, parseErr := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, parseErr)
	require.Equal(t, []byte("partial\x00\xff"), rr.Response().Body())
	require.Equal(t, "20", rr.Response().Header("Content-Length"))
	require.Equal(t, "yes", rr.Response().Header("X-Actual"))
	// Traffic diagnostics must render the buffered partial capture, not consume
	// the live reader ahead of Fill and turn a failed read into a false success.
	r.services.Options.DumpTraffic = true
	chain, _, err = r.Execute(makeTestRR(t, srv.URL+"/partial"), Options{NoClustering: true})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Nil(t, chain)
	dumped := CaptureFailureEvidence(err)
	require.NotNil(t, dumped)
	require.True(t, bytes.HasSuffix(dumped.Response, []byte("partial\x00\xff")))
	require.Equal(t, evidence.StateTruncated, dumped.ResponseState)
	require.NoError(t, dumped.Validate())
	require.NoError(t, x.Validate(), "dumping a later capture cannot rewrite retained bytes")
}

func TestNativeCaptureBodyFailureClosesBodyAndDoesNotCacheFailure(t *testing.T) {
	var sends atomic.Int64
	var bodies []*failingCaptureBody
	transport := captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		sends.Add(1)
		completeNativeCaptureWrite(req, nil)
		body := &failingCaptureBody{}
		bodies = append(bodies, body)
		return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: body, ContentLength: -1}, nil
	})
	r := nativeCaptureFixtureRequester(t, transport)
	r.clusterer = NewRequestClustererWithSize(16)
	var first *evidence.Exchange
	for i := 0; i < 24; i++ {
		chain, elapsed, err := r.Execute(makeTestRR(t, "http://fixture.invalid/fail"), Options{})
		require.ErrorIs(t, err, errCaptureRead)
		require.Nil(t, chain)
		require.Zero(t, elapsed)
		x := CaptureFailureEvidence(err)
		require.NotNil(t, x)
		require.NoError(t, x.Validate())
		require.Equal(t, evidence.StateTruncated, x.ResponseState)
		require.True(t, bytes.HasSuffix(x.Response, []byte{'a', 0, 0xff}))
		if first == nil {
			first = x
		} else {
			require.NotEqual(t, first.ID, x.ID)
		}
	}
	for _, body := range bodies {
		require.True(t, body.closed, "Fill failure must close its live reader")
	}
	require.EqualValues(t, 24, sends.Load())
	require.EqualValues(t, 24, r.RequestsSent())
	require.Zero(t, r.clusterer.Stats().RetainedBytes)
	require.NoError(t, first.Validate(), "later pool reuse cannot rewrite the first receipt")
}

func TestNativeCaptureUntracedDialAndIncompleteWritesCannotInventRequest(t *testing.T) {
	for _, test := range []struct {
		name string
		rt   stdhttp.RoundTripper
		want error
	}{
		{"untraced", captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) { return nil, errCaptureRead }), errCaptureRead},
		{"incomplete-write", captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
			trace := httptrace.ContextClientTrace(req.Context())
			trace.WroteHeaderField("Host", []string{req.URL.Host})
			trace.WroteHeaders()
			trace.WroteRequest(httptrace.WroteRequestInfo{Err: errCaptureRead})
			return nil, errCaptureRead
		}), errCaptureRead},
		{"dial-failed", &stdhttp.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}}, syscall.ECONNREFUSED},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := nativeCaptureFixtureRequester(t, test.rt)
			chain, _, err := r.Execute(makeTestRR(t, "http://fixture.invalid/not-certified"), Options{NoClustering: true})
			require.ErrorIs(t, err, test.want)
			require.Nil(t, chain)
			require.Nil(t, CaptureFailureEvidence(err))
			require.EqualValues(t, 1, r.RequestsSent(), "existing attempt counter is not redefined by tracing")
		})
	}
	require.Nil(t, CaptureFailureEvidence(nil))
	require.Nil(t, CaptureFailureEvidence(errors.New("external failure")))
}

func TestNativeCaptureUntracedResponseFailureKeepsResponseButNotIntent(t *testing.T) {
	body := &failingCaptureBody{}
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: body, ContentLength: -1}, nil
	}))
	chain, _, err := r.Execute(makeTestRR(t, "http://fixture.invalid/intended"), Options{NoClustering: true})
	require.ErrorIs(t, err, errCaptureRead)
	require.Nil(t, chain)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.Empty(t, x.Request)
	require.Equal(t, evidence.StateMissing, x.RequestState)
	require.Equal(t, evidence.StateTruncated, x.ResponseState)
	require.NoError(t, x.Validate())
	require.True(t, body.closed)
}

func TestNativeCaptureRetriesSelectOnlyFinalActualAttempt(t *testing.T) {
	for _, finalTraced := range []bool{true, false} {
		name := "final-untraced"
		if finalTraced {
			name = "final-traced"
		}
		t.Run(name, func(t *testing.T) {
			var sends atomic.Int64
			r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
				attempt := sends.Add(1)
				if attempt < 3 || finalTraced {
					extra := stdhttp.Header{"X-Attempt": {"earlier"}}
					if attempt == 3 {
						extra.Set("X-Attempt", "final")
					}
					completeNativeCaptureWrite(req, extra)
				}
				return nil, io.EOF
			}))
			r.retries = 2
			r.retryBackoff = func(int) time.Duration { return 0 }
			chain, _, err := r.Execute(makeTestRR(t, "http://fixture.invalid/retry"), Options{NoClustering: true})
			require.ErrorIs(t, err, io.EOF)
			require.Contains(t, err.Error(), "giving up after 3 attempts")
			require.Nil(t, chain)
			require.EqualValues(t, 3, sends.Load())
			require.EqualValues(t, 3, r.RequestsSent())
			x := CaptureFailureEvidence(err)
			if !finalTraced {
				require.Nil(t, x, "an earlier completed attempt must not stand in for the final one")
				return
			}
			require.NotNil(t, x)
			require.Contains(t, string(x.Request), "X-Attempt: final\r\n")
			require.NotContains(t, string(x.Request), "earlier")
			require.Empty(t, x.Response)
			require.NoError(t, x.Validate())
		})
	}
}

func TestNativeCaptureBackoffCancellationPreservesLastActualSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		completeNativeCaptureWrite(req, nil)
		return nil, io.EOF
	}))
	r.retries = 2
	r.retryBackoff = func(int) time.Duration { cancel(); return time.Hour }
	chain, _, err := r.ExecuteContext(ctx, makeTestRR(t, "http://fixture.invalid/backoff"), Options{NoClustering: true})
	require.ErrorIs(t, err, context.Canceled, "the gate's original cancellation cause is retained")
	require.Nil(t, chain)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Empty(t, x.Response)
	require.NoError(t, x.Validate())
	require.EqualValues(t, 1, r.RequestsSent())
}

func TestNativeCaptureCachedClientsAreBoundedIsolatedAndConcurrencySafe(t *testing.T) {
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		completeNativeCaptureWrite(req, stdhttp.Header{"X-Actual-Path": {req.URL.Path}})
		return nil, io.EOF
	}))
	originalClient, originalTransport := r.client.HTTPClient, r.client.HTTPClient.Transport
	originalFallback := r.client.HTTPClient2
	first := r.captureClients.get(r.client, false)
	for i := 0; i < 20; i++ {
		require.Same(t, first, r.captureClients.get(r.client, false))
	}
	require.NotSame(t, originalClient, first.HTTPClient)
	require.Same(t, originalClient, r.client.HTTPClient)
	require.Same(t, originalFallback, r.client.HTTPClient2)
	require.Equal(t, originalTransport, r.client.HTTPClient.Transport)
	require.Equal(t, originalClient.Timeout, first.HTTPClient.Timeout)
	require.Equal(t, originalFallback.Timeout, first.HTTPClient2.Timeout)
	require.Equal(t, originalClient.Jar, first.HTTPClient.Jar)
	require.Equal(t, originalTransport, first.HTTPClient.Transport.(*capturingRoundTripper).base)
	require.Equal(t, originalFallback.Transport, first.HTTPClient2.Transport.(*capturingRoundTripper).base)
	require.Same(t, r.captureClients, r.WithContext(context.Background()).captureClients)
	anonymous, err := r.CloneWithoutCredentials()
	require.NoError(t, err)
	require.NotSame(t, r.captureClients, anonymous.captureClients)
	anonClient := anonymous.captureClients.get(anonymous.client, false)
	require.NotSame(t, first.HTTPClient.Jar, anonClient.HTTPClient.Jar)
	require.Equal(t, originalTransport, anonClient.HTTPClient.Transport.(*capturingRoundTripper).base)

	const count = 24
	receipts := make(chan *evidence.Exchange, count)
	inputs := make([]*httpmsg.HttpRequestResponse, count)
	for i := range inputs {
		inputs[i] = makeTestRR(t, "http://fixture.invalid/"+strings.Repeat("x", i+1))
	}
	var wg sync.WaitGroup
	for _, input := range inputs {
		wg.Add(1)
		go func(input *httpmsg.HttpRequestResponse) {
			defer wg.Done()
			chain, _, err := r.Execute(input, Options{NoClustering: true})
			if chain != nil {
				chain.Close()
			}
			receipts <- CaptureFailureEvidence(err)
		}(input)
	}
	wg.Wait()
	close(receipts)
	ids, paths := map[string]bool{}, map[string]bool{}
	for x := range receipts {
		require.NotNil(t, x)
		require.NoError(t, x.Validate())
		require.False(t, ids[x.ID])
		ids[x.ID] = true
		parsed := httpmsg.NewHttpRequest(x.Request)
		paths[parsed.Path()] = true
		require.Equal(t, parsed.Path(), parsed.Header("X-Actual-Path"))
	}
	require.Len(t, paths, count)
	require.Same(t, first, r.captureClients.clients[0].client)
	require.Nil(t, r.captureClients.clients[1].client, "no per-request client or transport cache growth")
}

func TestNativeCaptureRequestBudgetBoundsBytesWithoutChangingSend(t *testing.T) {
	var sent []byte
	transport := captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		sent, _ = io.ReadAll(req.Body)
		completeNativeCaptureWrite(req, nil)
		return nil, io.EOF
	})
	capture := &captureTransport{base: transport, maxBody: 4}
	req, err := stdhttp.NewRequest("POST", "http://fixture.invalid/bounded", strings.NewReader("actual ten"))
	require.NoError(t, err)
	_, err = (&stdhttp.Client{Transport: capture}).Do(req)
	require.ErrorIs(t, err, io.EOF)
	x := requestOnlyFailureEvidence(capture.finalRequest())
	require.NotNil(t, x)
	require.Equal(t, "actual ten", string(sent), "capture clipping cannot clip the outgoing body")
	require.True(t, bytes.HasSuffix(x.Request, []byte("actu")))
	require.Equal(t, evidence.StateTruncated, x.RequestState)
	require.Empty(t, x.Response)
	require.LessOrEqual(t, len(x.Request), maxCaptureRequestHeaders+4)
	require.NoError(t, x.Validate())
	require.Nil(t, capture.finalRequest().Body)
	require.Nil(t, capture.finalRequest().GetBody)
	require.Nil(t, capture.finalRequest().Context().Value(requestCaptureKey{}), "no invocation or trace context is retained")
}

func TestNativeCaptureLibraryFallbackSelectsFinalTransportOnly(t *testing.T) {
	for _, traced := range []bool{false, true} {
		name := "untraced-fallback"
		if traced {
			name = "traced-fallback"
		}
		t.Run(name, func(t *testing.T) {
			var primarySends, fallbackSends atomic.Int64
			r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
				primarySends.Add(1)
				completeNativeCaptureWrite(req, stdhttp.Header{"X-Transport": {"primary"}})
				return nil, errors.New("net/http: HTTP/1.x transport connection broken: malformed HTTP response")
			}))
			r.client.HTTPClient2.Transport = &nativeFixtureRoundTripper{next: captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
				fallbackSends.Add(1)
				if traced {
					completeNativeCaptureWrite(req, stdhttp.Header{"X-Transport": {"fallback"}})
				}
				return nil, io.EOF
			})}
			chain, _, err := r.Execute(makeTestRR(t, "http://fixture.invalid/fallback"), Options{NoClustering: true})
			require.ErrorIs(t, err, io.EOF)
			require.Nil(t, chain)
			require.EqualValues(t, 1, primarySends.Load())
			require.EqualValues(t, 1, fallbackSends.Load())
			require.EqualValues(t, 1, r.RequestsSent(), "library fallback counting is unchanged")
			x := CaptureFailureEvidence(err)
			if !traced {
				require.Nil(t, x, "the primary's earlier write must not certify the fallback")
				return
			}
			require.NotNil(t, x)
			require.Contains(t, string(x.Request), "X-Transport: fallback\r\n")
			require.NotContains(t, string(x.Request), "primary")
			require.NoError(t, x.Validate())
		})
	}
}

func TestNativeCaptureClippedHeadersCannotCertifyRequest(t *testing.T) {
	capture := &captureTransport{maxBody: 4, base: captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		completeNativeCaptureWrite(req, stdhttp.Header{"X-Large": {strings.Repeat("x", maxCaptureRequestHeaders+1)}})
		return nil, io.EOF
	})}
	req, err := stdhttp.NewRequest("GET", "http://fixture.invalid/too-large", nil)
	require.NoError(t, err)
	_, err = (&stdhttp.Client{Transport: capture}).Do(req)
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, requestOnlyFailureEvidence(capture.finalRequest()))
}

func TestNativeCaptureDecoderUnexpectedEOFKeepsDecodedPartialEvidence(t *testing.T) {
	payload := bytes.Repeat([]byte("decoded actual bytes\x00\xff"), 24)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := writer.Write(payload)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	wire := bytes.Clone(compressed.Bytes()[:compressed.Len()-4]) // incomplete gzip footer, clean raw EOF
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		completeNativeCaptureWrite(req, nil)
		return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: stdhttp.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(bytes.NewReader(wire)), ContentLength: int64(len(wire))}, nil
	}))
	chain, _, err := r.Execute(makeTestRR(t, "http://fixture.invalid/partial-gzip"), Options{NoClustering: true})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF, "normalization cannot suppress a decoder read failure")
	require.Nil(t, chain)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.True(t, bytes.HasSuffix(x.Response, payload))
	require.Equal(t, evidence.StateTruncated, x.ResponseState)
	require.NoError(t, x.Validate())
}

func TestNativeCaptureTransparentReplayKeepsFinalWrittenBodyOnly(t *testing.T) {
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		trace := httptrace.ContextClientTrace(req.Context())
		trace.GetConn("fixture.invalid:80")
		completeNativeCaptureWrite(req, stdhttp.Header{"X-Attempt": {"first"}})
		reader, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		req.Body = reader
		trace.GetConn("fixture.invalid:80")
		completeNativeCaptureWrite(req, stdhttp.Header{"X-Attempt": {"final"}})
		return nil, io.EOF
	}))
	r.client.RequestLogHook = func(req *stdhttp.Request, _ int) {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("final")), nil
		}
	}
	rr, err := httpmsg.ParseRawRequest("POST http://fixture.invalid/replayed HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 5\r\n\r\nfirst")
	require.NoError(t, err)
	chain, _, err := r.Execute(rr, Options{NoClustering: true})
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, chain)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.True(t, bytes.HasSuffix(x.Request, []byte("final")))
	require.Contains(t, string(x.Request), "X-Attempt: final\r\n")
	require.NotContains(t, string(x.Request), "first")
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.NoError(t, x.Validate())
	require.EqualValues(t, 1, r.RequestsSent())
}

func TestNativeCaptureTransparentFinalDialFailureCannotRetainEarlierWrite(t *testing.T) {
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		trace := httptrace.ContextClientTrace(req.Context())
		trace.GetConn("fixture.invalid:80")
		completeNativeCaptureWrite(req, nil)
		trace.GetConn("fixture.invalid:80") // a new attempt that never writes headers or body
		return nil, syscall.ECONNREFUSED
	}))
	chain, _, err := r.Execute(makeTestRR(t, "http://fixture.invalid/replayed"), Options{NoClustering: true})
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
	require.Nil(t, chain)
	require.Nil(t, CaptureFailureEvidence(err))
}

func TestNativeCaptureLateCallbacksCannotMutateDetachedChain(t *testing.T) {
	var trace *httptrace.ClientTrace
	client := &stdhttp.Client{Transport: captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		trace = httptrace.ContextClientTrace(req.Context())
		trace.GetConn("fixture.invalid:80")
		completeNativeCaptureWrite(req, nil)
		return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(stdhttp.Header), Body: io.NopCloser(strings.NewReader("answer")), ContentLength: 6}, nil
	})}
	req, err := stdhttp.NewRequest("GET", "http://fixture.invalid/detached", nil)
	require.NoError(t, err)
	chain, err := DoCaptured(client, req, 1024)
	require.NoError(t, err)
	defer chain.Close()
	original := CaptureEvidence(chain)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 64; i++ {
			trace.GetConn("late.invalid:80")
			trace.WroteHeaderField("X-Late", []string{"not-this-receipt"})
			trace.WroteHeaders()
			trace.WroteRequest(httptrace.WroteRequestInfo{Err: errCaptureRead})
		}
	}()
	for i := 0; i < 64; i++ {
		require.Equal(t, original, CaptureEvidence(chain))
	}
	wg.Wait()
	require.NoError(t, original.Validate())
}
