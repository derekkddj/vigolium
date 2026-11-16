package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/projectdiscovery/retryablehttp-go"
	httpUtils "github.com/projectdiscovery/utils/http"
)

// DoCaptured sends through a caller-owned standard client and fills a response
// chain, including any available partial capture alongside an error. The caller
// must close every nonnil chain and CaptureEvidence before Close/Previous. Only headers
// reported by the transport and a successfully written body certify a request; a
// custom transport without tracing remains missing, never an intended pair.
// This is an HTTP-message boundary, not TLS, proxy or HTTP/2 wire framing.
func DoCaptured(client *stdhttp.Client, req *stdhttp.Request, maxBody int64) (*httpUtils.ResponseChain, error) {
	if client == nil || req == nil {
		return nil, fmt.Errorf("capture requires a client and request")
	}
	if maxBody <= 0 {
		maxBody = MaxBodyRead
	}
	copyClient := *client
	transport := client.Transport
	if transport == nil {
		transport = stdhttp.DefaultTransport
	}
	capture := &captureTransport{base: transport, maxBody: maxBody}
	copyClient.Transport = capture
	resp, requestErr := copyClient.Do(req)
	if resp == nil {
		// net/http discards the response on a transport error, but a completed
		// traced write can still certify the request. Keep only the final
		// attempt, never an earlier redirect request with another hop's answer.
		last := capture.finalRequest()
		if last == nil {
			return nil, requestErr
		}
		meta, _ := last.Context().Value(captureContextKey{}).(*captureContext)
		if meta == nil || meta.rawUnknown || len(meta.raw) == 0 {
			return nil, requestErr
		}
		meta.responseMissing = true
		return httpUtils.NewResponseChain(&stdhttp.Response{Request: last}, maxBody), requestErr
	}
	chain, fillErr := fillCapturedResponse(resp, maxBody)
	return chain, errors.Join(requestErr, fillErr)
}

func joinCaptureErrors(err, readErr error) error {
	if readErr == nil {
		return err
	}
	return errors.Join(err, readErr)
}

func fillCapturedResponse(resp *stdhttp.Response, maxBody int64) (*httpUtils.ResponseChain, error) {
	// Observe read failures before the utility's normalization can suppress an
	// unexpected EOF. Its buffers still contain all available decoded bytes.
	var observed *capturedResponseBody
	if resp.Body != nil {
		observed = &capturedResponseBody{ReadCloser: resp.Body}
		resp.Body = observed
	}
	previousIgnoredError := resp.Header.Get("x-nuclei-ignore-error")
	chain := httpUtils.NewResponseChain(resp, maxBody)
	fillErr := chain.Fill()
	// Decoder failures can arise above the observed raw reader (e.g. a gzip
	// footer cut short after a clean raw EOF). The utility suppresses some of
	// them but records its error in this header. Do not mistake a preexisting
	// server-supplied header for a newly observed read failure, or promote the
	// utility's intentional size-limit suppression into a transport failure.
	if ignored := resp.Header.Get("x-nuclei-ignore-error"); ignored != previousIgnoredError && strings.Contains(ignored, "unexpected EOF") && (observed == nil || observed.readErr == nil) {
		fillErr = errors.Join(fillErr, io.ErrUnexpectedEOF)
	}
	if observed != nil {
		fillErr = errors.Join(fillErr, observed.readErr)
		_ = observed.Close() // Fill does not close the body on every failure path.
	}
	if fillErr != nil {
		if resp.Request != nil {
			if meta, _ := resp.Request.Context().Value(captureContextKey{}).(*captureContext); meta != nil {
				meta.responseFailed = true
			}
		}
	}
	return chain, fillErr
}

// Each cached retry client owns only stateless transport wrappers. Invocation
// state lives on the outgoing context, so concurrent sends never share a last
// request and credential/context views never mutate the shared HTTP clients.
type requestCaptureKey struct{}

type capturingRoundTripper struct{ base stdhttp.RoundTripper }

func (t *capturingRoundTripper) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	capture, _ := req.Context().Value(requestCaptureKey{}).(*captureTransport)
	if capture == nil {
		return t.base.RoundTrip(req)
	}
	return capture.roundTrip(t.base, req)
}

func (t *capturingRoundTripper) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

type capturedRetryClient struct {
	source *retryablehttp.Client
	client *retryablehttp.Client
}

type capturedRetryClients struct {
	mu      sync.Mutex
	clients [2]capturedRetryClient // redirect and no-redirect; bounded per credential view
}

func (c *capturedRetryClients) get(src *retryablehttp.Client, noRedirects bool) *retryablehttp.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := 0
	if noRedirects {
		i = 1
	}
	if c.clients[i].source == src {
		return c.clients[i].client
	}
	base := *src.HTTPClient
	transport := base.Transport
	if transport == nil {
		transport = stdhttp.DefaultTransport
	}
	base.Transport = &capturingRoundTripper{base: transport}
	// Do not copy retryablehttp.Client: it contains an atomic request counter.
	// Construct once, not per request (which would reset KillIdleConn's cadence).
	// Wrapping before construction also prevents the library from creating an
	// unused cloned HTTP/2 transport for every send. Both wrappers share the
	// existing scan transports, jars, timeouts and redirect policies.
	opts := scanRetryOptions()
	opts.Timeout = base.Timeout
	opts.KillIdleConn = killIdleConns(transport)
	clone := retryablehttp.NewWithHTTPClient(&base, opts)
	clone.CheckRetry, clone.Backoff = src.CheckRetry, src.Backoff
	clone.ErrorHandler = src.ErrorHandler
	clone.RequestLogHook, clone.ResponseLogHook = src.RequestLogHook, src.ResponseLogHook
	if src.HTTPClient2 != nil {
		fallback := *src.HTTPClient2
		fallbackTransport := fallback.Transport
		if fallbackTransport == nil {
			fallbackTransport = stdhttp.DefaultTransport
		}
		fallback.Transport = &capturingRoundTripper{base: fallbackTransport}
		clone.HTTPClient2 = &fallback
	}
	c.clients[i] = capturedRetryClient{source: src, client: clone}
	return clone
}

type captureTransport struct {
	base        stdhttp.RoundTripper
	maxBody     int64
	lastMu      sync.Mutex
	lastRequest *stdhttp.Request // owned by this one invocation; final hop/fallback only
}

func (t *captureTransport) finalRequest() *stdhttp.Request {
	t.lastMu.Lock()
	defer t.lastMu.Unlock()
	return t.lastRequest
}

func (t *captureTransport) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	return t.roundTrip(t.base, req)
}

const maxCaptureRequestHeaders = 64 << 10

func (t *captureTransport) roundTrip(base stdhttp.RoundTripper, req *stdhttp.Request) (*stdhttp.Response, error) {
	meta := &captureContext{id: uuid.NewString(), at: time.Now().UTC(), rawUnknown: true, maxBody: t.maxBody}
	// Capture the body as the transport consumes it, not from an intended
	// GetBody replay that could differ from the bytes actually written.
	var body bytes.Buffer

	// net/http may add defaults (gzip, User-Agent, framing) without updating
	// resp.Request.Header. Observe them rather than guessing their values.
	var mu sync.Mutex
	var headers bytes.Buffer
	var wroteHeaders, wroteRequest, bodyTruncated, finalized bool
	unsupported := len(req.Trailer) > 0
	var wireAttempts int
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			mu.Lock()
			defer mu.Unlock()
			if finalized {
				return
			}
			// net/http can replay a request after a stale pooled connection.
			// On HTTP/1 it waits for the prior write loop before this callback.
			// Reset even before a dial: a failed final dial must not retain the
			// previous attempt's successfully written request. Uninstrumented
			// transports with repeated header blocks still fail closed below.
			if wireAttempts > 0 {
				meta.id, meta.at = uuid.NewString(), time.Now().UTC()
			}
			wireAttempts++
			headers.Reset()
			body.Reset()
			wroteHeaders, wroteRequest, bodyTruncated = false, false, false
			unsupported = len(req.Trailer) > 0
		},
		WroteHeaderField: func(name string, values []string) {
			mu.Lock()
			defer mu.Unlock()
			if finalized {
				return
			}
			if strings.HasPrefix(name, ":") {
				// HTTP/2 pseudo headers cannot certify an HTTP/1 request line.
				unsupported = true
				return
			}
			for _, value := range values {
				if len(name)+len(value)+4 > maxCaptureRequestHeaders-headers.Len() {
					unsupported = true
					return // a bounded capture must not certify clipped headers
				}
				fmt.Fprintf(&headers, "%s: %s\r\n", name, value)
			}
		},
		WroteHeaders: func() {
			mu.Lock()
			defer mu.Unlock()
			if finalized {
				return
			}
			if wroteHeaders {
				unsupported = true // multiple wire attempts cannot share one header block
			}
			wroteHeaders = true
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			mu.Lock()
			defer mu.Unlock()
			if !finalized {
				wroteRequest = info.Err == nil
			}
		},
	}
	ctx := context.WithValue(req.Context(), captureContextKey{}, meta)
	traced := req.WithContext(httptrace.WithClientTrace(ctx, trace))
	recordBody := func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		if finalized {
			return
		}
		remaining := max(t.maxBody-int64(body.Len()), 0)
		if int64(len(data)) > remaining {
			bodyTruncated = true
			data = data[:int(remaining)]
		}
		body.Write(data)
	}
	if req.Body != nil && req.Body != stdhttp.NoBody {
		traced.Body = &capturedRequestBody{ReadCloser: req.Body, record: recordBody}
	}
	if req.GetBody != nil {
		traced.GetBody = func() (io.ReadCloser, error) {
			mu.Lock()
			if !finalized {
				unsupported = true // only a subsequent GetConn can separate this attempt
			}
			mu.Unlock()
			reader, err := req.GetBody()
			if err != nil || reader == nil {
				return reader, err
			}
			return &capturedRequestBody{ReadCloser: reader, record: recordBody}, nil
		}
	}
	resp, err := base.RoundTrip(traced)
	mu.Lock()
	requestTarget := ""
	if traced.URL != nil {
		requestTarget = traced.URL.RequestURI()
	}
	if traced.URL != nil && len(traced.Method)+len(requestTarget)+12 <= maxCaptureRequestHeaders-headers.Len() && wroteHeaders && wroteRequest && !unsupported {
		var raw bytes.Buffer
		fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\n", traced.Method, requestTarget)
		raw.Write(headers.Bytes())
		raw.WriteString("\r\n")
		raw.Write(body.Bytes())
		meta.raw, meta.rawUnknown, meta.rawTruncated = raw.Bytes(), false, bodyTruncated
	}
	// A response can arrive before a request's write goroutine exits. Late
	// callbacks cannot mutate or upgrade this already-detached receipt.
	finalized = true
	mu.Unlock()
	last := traced.Clone(context.WithValue(context.Background(), captureContextKey{}, meta))
	last.Body, last.GetBody = nil, nil
	t.lastMu.Lock()
	t.lastRequest = last
	t.lastMu.Unlock()
	if resp != nil {
		// Custom transports may omit resp.Request. This locator does not certify
		// the request: without trace callbacks meta.rawUnknown remains true.
		resp.Request = last
	}
	return resp, err
}

type capturedResponseBody struct {
	io.ReadCloser
	readErr   error
	closeOnce sync.Once
	closeErr  error
}

func (b *capturedResponseBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.ReadCloser.Close() })
	return b.closeErr
}

func (b *capturedResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && b.readErr == nil {
		b.readErr = err
	}
	return n, err
}

type capturedRequestBody struct {
	io.ReadCloser
	record func([]byte)
}

func (b *capturedRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.record(p[:n])
	}
	return n, err
}

// clientTimeoutMark is the text net/http gives a Client.Timeout expiry, which
// host-error tracking and transport classification recognise.
const clientTimeoutMark = "Client.Timeout exceeded"

// clientTimeoutErr restores clientTimeoutMark on a client timeout that lost it.
type clientTimeoutErr struct{ err error }

func (e *clientTimeoutErr) Error() string {
	return e.err.Error() + " (" + clientTimeoutMark + " while awaiting headers)"
}
func (e *clientTimeoutErr) Unwrap() error { return e.err }
func (e *clientTimeoutErr) Timeout() bool { return true }

// clientTimeoutError names a Client.Timeout expiry as net/http names it for its
// own transports. Behind the capturing round tripper net/http races its timer
// against the cancellation it causes, and the loser is reported as a bare
// "context deadline exceeded" that reads like the caller's own deadline. ctx is
// the caller's context: when it is still live the deadline was the client's.
func clientTimeoutError(ctx context.Context, err error) error {
	if err == nil || ctx.Err() != nil || !errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), clientTimeoutMark) {
		return err
	}
	return &clientTimeoutErr{err: err}
}
