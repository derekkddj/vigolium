package http

import (
	"bytes"
	"context"
	"errors"
	stdhttp "net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/evidence"
)

type captureContextKey struct{}

// Traced request bytes are bounded and scoped to one transport attempt. Selected
// receipts copy them before a chain is closed; errors own no pooled buffers.
type captureContext struct {
	id           string
	at           time.Time
	raw          []byte
	rawUnknown   bool
	rawTruncated bool
	cached       bool
	maxBody      int64 // explicit standard-client capture limit; zero uses MaxBodyRead
	// A request-only carrier has no response bytes; it must never render its
	// internal status-zero holder as an HTTP response. Read errors similarly
	// retain available bytes without claiming a complete response.
	responseMissing bool
	responseFailed  bool
}

// RequestCaptureError preserves the original failure and an immutable, owned
// receipt of the final actual transport attempt. It never owns a ResponseChain,
// body reader, request context, or an earlier redirect exchange. Callers need
// not close anything on the native Execute error path.
//
// Use CaptureFailureEvidence to obtain an independent copy; Unwrap preserves
// errors.Is/errors.As (including context deadlines and transport classification).
type RequestCaptureError struct {
	err              error
	exchange         *evidence.Exchange
	followedRedirect bool
}

func (e *RequestCaptureError) Error() string { return e.err.Error() }
func (e *RequestCaptureError) Unwrap() error { return e.err }

// CaptureFailureEvidence returns an owned copy of the available final-attempt
// receipt, or nil when nothing could be captured. In particular a dial failure
// or untraced failed write cannot certify the intended request. Missing responses
// remain absent bytes, never an internal status-zero response holder.
func CaptureFailureEvidence(err error) *evidence.Exchange {
	var failure *RequestCaptureError
	if errors.As(err, &failure) {
		return failure.exchange.Clone()
	}
	return nil
}

func ownCaptureFailure(err error, x *evidence.Exchange, req *stdhttp.Request) error {
	if err == nil || x == nil || len(x.Request) == 0 && len(x.Response) == 0 {
		return err
	}
	return &RequestCaptureError{err: err, exchange: x, followedRedirect: req != nil && req.Response != nil}
}

// A gate can replace the last send's error with a cancellation during backoff.
// Preserve that cause and only the last attempted send's immutable receipt.
func retainCaptureFailure(err, lastSendErr error) error {
	var current, last *RequestCaptureError
	if errors.As(err, &current) || !errors.As(lastSendErr, &last) {
		return err
	}
	return &RequestCaptureError{err: err, exchange: last.exchange, followedRedirect: last.followedRedirect}
}

func requestOnlyFailureEvidence(req *stdhttp.Request) *evidence.Exchange {
	if req == nil || req.URL == nil {
		return nil
	}
	meta, _ := req.Context().Value(captureContextKey{}).(*captureContext)
	if meta == nil || meta.rawUnknown || len(meta.raw) == 0 {
		return nil
	}
	x := evidence.NewExchange(req.URL.Scheme+"://"+req.URL.Host, emittedRequestTarget(req, meta.raw), meta.raw, nil, evidence.ProvenanceCaptured)
	x.ID, x.CapturedAt = meta.id, meta.at
	if meta.rawTruncated {
		x.RequestState = evidence.StateTruncated
	}
	x.ContentHash = x.Hash()
	return x
}

func emittedRequestTarget(req *stdhttp.Request, raw []byte) string {
	if req == nil || req.URL == nil {
		return ""
	}
	target := req.URL.String()
	if end := bytes.Index(raw, []byte("\r\n")); end >= 0 {
		parts := strings.SplitN(string(raw[:end]), " ", 3)
		if len(parts) == 3 {
			if u, err := url.ParseRequestURI(parts[1]); err == nil {
				target = req.URL.ResolveReference(u).String()
			}
		}
	}
	return target
}

// CaptureEvidence owns the CURRENT request/response before Close or Previous.
// It captures the client's HTTP message boundary: final request headers (including
// auth/cookies), a replayable request body, response headers and the decoded body.
// Transport defaults absent from the final request object leave unknown fidelity.
// It does not claim TLS/HTTP2 wire framing or original compressed/chunked bytes.
// Redirects select the final request, never the original URL paired with its body.
// Historical/external and flattened cached chains have unknown fidelity; drained
// intermediate bodies and size-limited bodies are explicitly not complete.
func CaptureEvidence(chain *httpUtils.ResponseChain) *evidence.Exchange {
	if chain == nil || !chain.Has() {
		return nil
	}
	req := chain.Request()
	var raw []byte
	requestState := evidence.StateMissing
	service, target := "", ""
	var meta *captureContext
	if req != nil {
		meta, _ = req.Context().Value(captureContextKey{}).(*captureContext)
		if req.URL != nil {
			target = req.URL.String()
			service = req.URL.Scheme + "://" + req.URL.Host
		}
		if meta != nil && meta.rawUnknown {
			// The parsed/intended request is not rawhttp's emitted message.
			// Missing bytes are safer than a convincing but fabricated request.
			requestState = evidence.StateMissing
		} else if meta != nil && len(meta.raw) > 0 {
			raw = bytes.Clone(meta.raw)
			requestState = evidence.StateComplete
			// RawBytes may use a different request target than the connection
			// locator. Preserve the emitted target without changing the service.
			target = emittedRequestTarget(req, raw)
			if meta.rawTruncated {
				requestState = evidence.StateTruncated
			}
		} else {
			copyReq := req.Clone(context.Background())
			copyReq.RequestURI = ""
			// net/http always writes HTTP/1.1, irrespective of the input's
			// Proto (redirect requests omit it altogether). This is a message
			// rendering, not a claim about HTTP/2 fallback wire framing.
			copyReq.Proto, copyReq.ProtoMajor, copyReq.ProtoMinor = "HTTP/1.1", 1, 1
			copyReq.Body = nil
			requestState = evidence.StateComplete
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err == nil {
					copyReq.Body = body
					defer body.Close()
				} else {
					requestState = evidence.StateUnknown
				}
			} else if req.ContentLength > 0 || len(req.TransferEncoding) > 0 || req.Body != nil && req.Body != stdhttp.NoBody {
				requestState = evidence.StateUnknown
			}
			// net/http renders Content-Length from the body field, not the
			// potentially stale input Header. Reflect that final known value.
			if copyReq.Header == nil {
				copyReq.Header = make(stdhttp.Header)
			}
			copyReq.Header.Del("Content-Length")
			if len(req.TransferEncoding) == 0 && (req.ContentLength > 0 || req.ContentLength == 0 && (req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH")) {
				copyReq.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
			}
			// A transport can add gzip/connection/framing headers without
			// mutating resp.Request. Do not manufacture those absent defaults
			// and then label the headers complete.
			if req.Method != stdhttp.MethodHead && req.Header.Get("Accept-Encoding") == "" && req.Header.Get("Range") == "" || req.ContentLength < 0 && len(req.TransferEncoding) == 0 {
				requestState = evidence.StateUnknown
			}
			// DumpRequest uses only the copied request; it cannot consume the sent
			// body's closed reader or honour an already-cancelled client context.
			raw, _ = httputil.DumpRequest(copyReq, copyReq.Body != nil)
			if len(raw) == 0 {
				requestState = evidence.StateMissing
			}
		}
	}
	var response []byte
	if meta == nil || !meta.responseMissing {
		response = chain.FullResponseBytes()
	}
	x := evidence.NewExchange(service, target, raw, response, evidence.ProvenanceCaptured)
	x.RequestState = requestState
	if meta == nil || meta.cached {
		x.Provenance = evidence.ProvenanceLegacy
		if meta != nil && meta.cached {
			x.Provenance = evidence.ProvenanceCached
		}
		if len(raw) > 0 {
			x.RequestState = evidence.StateUnknown
		}
		if len(x.Response) > 0 {
			x.ResponseState = evidence.StateUnknown
		}
	} else {
		x.ID, x.CapturedAt = meta.id, meta.at
		if meta.rawUnknown {
			x.RequestState = evidence.StateMissing
		}
	}
	resp := chain.Response()
	noBodyExpected := req != nil && req.Method == stdhttp.MethodHead || resp != nil && (resp.StatusCode == 204 || resp.StatusCode == 304)
	maxBody := MaxBodyRead
	if meta != nil && meta.maxBody > 0 {
		maxBody = meta.maxBody
	}
	if meta != nil && meta.responseMissing {
		x.ResponseState = evidence.StateMissing
	} else if len(response) > 0 && (meta != nil && meta.responseFailed || !noBodyExpected && (int64(len(chain.BodyBytes())) >= maxBody || (resp != nil && resp.ContentLength > int64(len(chain.BodyBytes())) && resp.Header.Get("Content-Encoding") == ""))) {
		x.ResponseState = evidence.StateTruncated
	}
	x.ContentHash = x.Hash()
	return x
}

func stampCapture(resp *stdhttp.Response, req *stdhttp.Request, opts Options) {
	if resp == nil {
		return
	}
	if !opts.RawRequest && resp.Request != nil {
		if meta, _ := resp.Request.Context().Value(captureContextKey{}).(*captureContext); meta != nil {
			return // the actual transport trace is authoritative, not a rebuilt request
		}
	}
	meta := &captureContext{id: uuid.NewString(), at: time.Now().UTC()}
	if resp.Request == nil {
		// A supplied intended request can locate the response, not certify
		// what a transport actually emitted.
		resp.Request = req
		meta.rawUnknown = true
	}
	if opts.RawRequest {
		// rawhttp's builder is a different capture boundary; only RawBytes gives
		// an authoritative emitted request. Never call a reconstructed raw probe
		// complete (particularly with a custom target or duplicate framing).
		meta.raw = bytes.Clone(opts.RawBytes)
		meta.rawUnknown = len(meta.raw) == 0
	}
	if resp.Request != nil {
		resp.Request = resp.Request.WithContext(context.WithValue(resp.Request.Context(), captureContextKey{}, meta))
	}
}
