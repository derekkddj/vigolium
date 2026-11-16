package httpmsg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// HttpRequestResponse is a unified struct containing HTTP request and response.
//
// Design:
//   - Contains HttpRequest (required) and HttpResponse (optional)
//   - Service info is delegated to the request
//   - Provides convenience methods for common operations
type HttpRequestResponse struct {
	request  *HttpRequest
	response *HttpResponse
	// snapshot is captured before analysis transforms/truncation. It is never
	// modified after publication to modules; selection returns an owned copy.
	snapshot *evidence.Exchange
}

// NewHttpRequestResponse creates a new HttpRequestResponse from request and optional response.
func NewHttpRequestResponse(request *HttpRequest, response *HttpResponse) *HttpRequestResponse {
	return &HttpRequestResponse{
		request:  request,
		response: response,
	}
}

// Request returns the HTTP request.
func (h *HttpRequestResponse) Request() *HttpRequest {
	return h.request
}

// Response returns the HTTP response (may be nil).
func (h *HttpRequestResponse) Response() *HttpResponse {
	return h.response
}

// Service returns the HTTP service info (delegated to request).
func (h *HttpRequestResponse) Service() *Service {
	if h.request == nil {
		return nil
	}
	return h.request.Service()
}

// HasResponse returns true if there is an HTTP response.
func (h *HttpRequestResponse) HasResponse() bool {
	return h.response != nil
}

// URL returns the URL by delegating to Request.URL().
func (h *HttpRequestResponse) URL() (*urlutil.URL, error) {
	if h.request == nil {
		return nil, fmt.Errorf("request is nil")
	}
	return h.request.URL()
}

// sharedURL is URL without the per-call copy, for the read-only String()
// callers below. See HttpRequest.sharedURL for what may be done with it.
func (h *HttpRequestResponse) sharedURL() (*urlutil.URL, error) {
	if h.request == nil {
		return nil, fmt.Errorf("request is nil")
	}
	u, _, err := h.request.sharedURL()
	return u, err
}

// Target returns the target URL as a string.
func (h *HttpRequestResponse) Target() string {
	urlx, err := h.sharedURL()
	if err != nil {
		return ""
	}
	return urlx.String()
}

// ID returns a unique identifier for host-based tracking.
// Returns FNV-1a hash of host:port:method for efficient cache key usage.
func (h *HttpRequestResponse) ID() string {
	service := h.Service()
	if service == nil {
		return ""
	}
	method := ""
	if h.request != nil {
		method = h.request.Method()
	}
	hash := fnv.New64a()
	hash.Write([]byte(service.Host()))
	hash.Write([]byte{':'})
	hash.Write([]byte(strconv.Itoa(service.Port())))
	hash.Write([]byte{':'})
	hash.Write([]byte(method))
	return strconv.FormatUint(hash.Sum64(), 16)
}

// GetScanHash returns a unique hash that represents a scan by hashing (URL + templateId).
func (h *HttpRequestResponse) GetScanHash(templateId string) string {
	urlx, err := h.sharedURL()
	if err != nil {
		return ""
	}
	var rawRequest string
	if h.request != nil {
		rawRequest = h.request.ID()
	}
	data := templateId + ":" + urlx.String() + rawRequest
	bin := md5.Sum([]byte(data))
	return string(bin[:])
}

// Clone owns independent mutable request/response messages. The private capture
// receipt is immutable and can be shared; Evidence still returns an owned copy,
// so neither message mutations nor a caller's selection can change that receipt.
func (h *HttpRequestResponse) Clone() *HttpRequestResponse {
	cloned := &HttpRequestResponse{}
	if h.request != nil {
		cloned.request = h.request.Clone()
	}
	if h.response != nil {
		cloned.response = h.response.Clone()
	}
	cloned.snapshot = h.snapshot
	return cloned
}

// HasEvidence checks receipt presence without copying either message. It does
// not validate or select evidence; callers needing bytes must use Evidence.
func (h *HttpRequestResponse) HasEvidence() bool {
	return h != nil && h.snapshot != nil
}

// Evidence returns an owned capture receipt, if the caller captured the exchange
// before handing it to analysis. Absence is unknown, not reconstructed capture.
func (h *HttpRequestResponse) Evidence() *evidence.Exchange {
	if h == nil {
		return nil
	}
	return h.snapshot.Clone()
}

// WithEvidence attaches an owned snapshot without changing either live message.
func (h *HttpRequestResponse) WithEvidence(snapshot *evidence.Exchange) *HttpRequestResponse {
	return &HttpRequestResponse{request: h.request, response: h.response, snapshot: snapshot.Clone()}
}

// WithService sets the service on the request and returns the same HttpRequestResponse.
// This is a mutating method for convenience when building requests.
func (h *HttpRequestResponse) WithService(service *Service) *HttpRequestResponse {
	h.snapshot = nil // a different service is not the captured exchange
	if h.request != nil {
		h.request.mu.Lock()
		if h.request.service != nil && h.request.service.destinationPinned {
			service = pinServiceDestination(service)
		}
		h.request.service = service
		// Invalidate the cached URL since it depends on the service.
		h.request.cachedURL = nil
		h.request.cachedURLParams = nil
		h.request.cachedURLErr = nil
		h.request.urlComputed = false
		h.request.mu.Unlock()
	}
	return h
}

// WithResponse returns a new HttpRequestResponse with the given response.
// This allows setting a response on a request-only HttpRequestResponse.
func (h *HttpRequestResponse) WithResponse(response *HttpResponse) *HttpRequestResponse {
	return &HttpRequestResponse{
		request:  h.request,
		response: response,
	}
}

// BuildRetryableRequest builds a retryablehttp request from the request response.
// Receipt-restored services control the connection URL; Host remains explicit.
// Native request-target normalization is exposed by RequestTargetPolicyFromContext.
// HTTP proxies with a differing Host require a destination-aware transport (e.g.
// proxytarget.Wrap), as in the native Requester; this builder does not own routing.
// Note: This method builds a fresh request every time (no caching).
func (h *HttpRequestResponse) BuildRetryableRequest() (*retryablehttp.Request, error) {
	urlx, err := h.URL()
	if err != nil {
		return nil, fmt.Errorf("failed to get URL: %w", err)
	}
	// URL() already returns this caller's own copy, so it can be handed to
	// retryablehttp (which keeps and may mutate it) without another Clone.
	// The retryable client's default GetBody can return the same reusable
	// reader at its current cursor. Own the submitted bytes and return a fresh
	// reader for each replay/capture, including after the sent body is closed.
	body := bytes.Clone(h.request.Body())
	var bodyReader io.Reader = nil
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := retryablehttp.NewRequestFromURL(h.request.Method(), urlx, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	if len(body) > 0 {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}
	for _, header := range h.request.Headers() {
		req.Header.Add(header.Name, header.Value)
		if strings.EqualFold(header.Name, "Host") {
			// Go transmits the Host header from req.Host, not req.Header["Host"];
			// mirror an explicit/overridden Host here so it actually reaches the
			// wire (host-header-injection probes, captured vhost authority).
			// The dial target stays req.URL.Host, so only the sent Host: changes.
			req.Host = header.Value
		}
	}
	// Preserve the intended absolute target as metadata, never by overwriting
	// RequestURI (net/http rejects client requests with RequestURI set).
	return req.WithContext(withRequestTargetPolicy(req.Context(), h.request.Raw())), nil
}

// BuildRetryableRequestWithContext is BuildRetryableRequest with ctx attached to
// the underlying *http.Request, so cancelling ctx aborts the in-flight request
// (and its retry loop). Like the stdlib, ctx must be non-nil; pass
// context.Background() when there is nothing to cancel against.
func (h *HttpRequestResponse) BuildRetryableRequestWithContext(ctx context.Context) (*retryablehttp.Request, error) {
	req, err := h.BuildRetryableRequest()
	if err != nil {
		return nil, err
	}
	return req.WithContext(withRequestTargetPolicy(ctx, h.request.Raw())), nil
}

// CreateInsertionPoints creates insertion points from the request.
// Convenience method that wraps CreateAllInsertionPoints.
func (h *HttpRequestResponse) CreateInsertionPoints(includeNested bool) ([]InsertionPoint, error) {
	if h.request == nil {
		return nil, fmt.Errorf("request is nil")
	}
	return CreateAllInsertionPoints(h.request.Raw(), includeNested)
}

// PrettyPrint returns a formatted string for display.
func (h *HttpRequestResponse) PrettyPrint() string {
	urlx, err := h.sharedURL()
	if err != nil {
		return ""
	}
	if h.request != nil {
		return fmt.Sprintf("%s [%s]", urlx.String(), h.request.Method())
	}
	return urlx.String()
}

// ============== JSON Serialization ==============

var (
	_ json.Marshaler   = &HttpRequestResponse{}
	_ json.Unmarshaler = &HttpRequestResponse{}
)

// jsonFast is the fastest jsoniter config — no HTML escaping, no sorting of map keys.
var jsonFast = jsoniter.ConfigFastest

// MarshalJSON marshals the request response to JSON.
// Uses jsoniter with shadow structs for single-pass serialization,
// eliminating the previous triple-marshal pattern.
func (h *HttpRequestResponse) MarshalJSON() ([]byte, error) {
	service := h.Service()
	serviceURL := ""
	if service != nil {
		serviceURL = (&url.URL{Scheme: service.Protocol(), Host: net.JoinHostPort(service.Host(), strconv.Itoa(service.Port()))}).String()
	}
	urlx, err := h.sharedURL()
	if err != nil && h.snapshot != nil && h.request != nil && len(h.request.Raw()) == 0 && serviceURL != "" {
		// A response-only receipt has no request target. Keep its request missing,
		// but satisfy the legacy URL envelope with the recorded destination root.
		urlx, err = urlutil.ParseAbsoluteURL(serviceURL+"/", false)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get URL for marshaling: %w", err)
	}

	type requestPayload struct {
		Method  string       `json:"method"`
		Headers []HttpHeader `json:"headers"`
		Raw     []byte       `json:"raw"`
	}
	type responsePayload struct {
		StatusCode int          `json:"status_code"`
		Headers    []HttpHeader `json:"headers"`
		Raw        string       `json:"raw"` // Legacy text view, not authoritative bytes.
		RawBase64  []byte       `json:"raw_base64"`
		// The body is not serialized separately: RawBase64 contains it verbatim.
		// Keep Raw for older readers, but new readers must prefer RawBase64 since
		// JSON strings cannot represent arbitrary non-UTF-8 response bytes.
	}
	type envelope struct {
		URL      string             `json:"url"`
		Service  string             `json:"service"`
		Request  requestPayload     `json:"request"`
		Response *responsePayload   `json:"response,omitempty"`
		Evidence *evidence.Exchange `json:"evidence,omitempty"`
	}

	snapshot := h.Evidence()
	if snapshot != nil {
		if err := snapshot.Validate(); err != nil {
			return nil, err
		}
	}
	env := envelope{
		URL:      urlx.String(),
		Service:  serviceURL,
		Evidence: snapshot,
		Request: requestPayload{
			Method:  h.request.Method(),
			Headers: h.request.Headers(),
			Raw:     h.request.Raw(),
		},
	}

	if h.response != nil {
		env.Response = &responsePayload{
			StatusCode: h.response.StatusCode(),
			Headers:    h.response.Headers(),
			Raw:        strings.ToValidUTF8(string(h.response.Raw()), "\uFFFD"),
			RawBase64:  h.response.Raw(),
		}
	}

	return jsonFast.Marshal(env)
}

// UnmarshalJSON restores authoritative raw bytes and an optional capture receipt.
// Older payloads containing only a response raw string remain readable, but the
// absence of a receipt must never be promoted to captured evidence.
func (h *HttpRequestResponse) UnmarshalJSON(data []byte) error {
	var env struct {
		URL     *string `json:"url"`
		Service string  `json:"service"`
		Request *struct {
			Raw []byte `json:"raw"`
		} `json:"request"`
		Response *struct {
			Raw       string          `json:"raw"`
			RawBase64 json.RawMessage `json:"raw_base64"`
		} `json:"response"`
		Evidence *evidence.Exchange `json:"evidence"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	if env.URL == nil {
		return fmt.Errorf("missing url in request response")
	}
	serviceURL := env.Service
	if serviceURL == "" {
		serviceURL = *env.URL // Legacy payloads stored the destination only in URL.
	}
	service, err := parseEvidenceServiceURL(serviceURL)
	if err != nil {
		return err
	}
	if env.Evidence != nil {
		if err := env.Evidence.Validate(); err != nil {
			return err
		}
	}

	if env.Service != "" || env.Evidence != nil {
		// New envelopes explicitly separate destination from request/display URL.
		// Legacy URL-only ingestion keeps its absolute-target inference contract.
		service = pinServiceDestination(service)
	}

	// Decode into a fresh value so reusing a receiver cannot retain a stale
	// response or capture receipt, and malformed input cannot partially replace it.
	decoded := HttpRequestResponse{snapshot: env.Evidence.Clone()}
	if env.Request != nil {
		decoded.request = NewHttpRequestWithService(service, env.Request.Raw)
	}
	if env.Response != nil {
		raw := []byte(env.Response.Raw)
		if len(env.Response.RawBase64) != 0 {
			// Presence, not length of the decoded bytes, selects the authoritative
			// field. Empty/null bytes must not fall back to a legacy text preview.
			if err := json.Unmarshal(env.Response.RawBase64, &raw); err != nil {
				return fmt.Errorf("invalid response raw_base64: %w", err)
			}
		}
		decoded.response = NewHttpResponse(raw)
	}
	*h = decoded
	return nil
}

// MarshalString marshals to JSON string.
func (h *HttpRequestResponse) MarshalString() (string, error) {
	b, err := h.marshalToBuffer()
	return b.String(), err
}

// MustMarshalString marshals to JSON string (ignores error).
func (h *HttpRequestResponse) MustMarshalString() string {
	marshaled, _ := h.MarshalString()
	return marshaled
}

// MarshalBytes marshals to JSON bytes.
func (h *HttpRequestResponse) MarshalBytes() ([]byte, error) {
	b, err := h.marshalToBuffer()
	return b.Bytes(), err
}

// MustMarshalBytes marshals to JSON bytes (ignores error).
func (h *HttpRequestResponse) MustMarshalBytes() []byte {
	marshaled, _ := h.MarshalBytes()
	return marshaled
}

func (h *HttpRequestResponse) marshalToBuffer() (bytes.Buffer, error) {
	var b bytes.Buffer
	err := jsoniter.NewEncoder(&b).Encode(h)
	return b, err
}

// ============== Factory Functions ==============

// FromEvidenceExchange restores an owned exchange without repairing or reconciling
// either message. Declared Content-Length and the actual bytes may intentionally
// disagree; the capture receipt, not a parser, is authoritative.
//
// Service is the recorded destination, independent of the finding/selection URL.
// Only producer-supplied receipts without a service may derive it from their URL.
func FromEvidenceExchange(x *evidence.Exchange) (*HttpRequestResponse, error) {
	if err := x.Validate(); err != nil {
		return nil, err
	}
	serviceURL := x.Service
	if serviceURL == "" && x.Provenance == evidence.ProvenanceSupplied {
		serviceURL = x.URL
	}
	service, err := parseEvidenceServiceURL(serviceURL)
	if err != nil {
		return nil, fmt.Errorf("invalid evidence service: %w", err)
	}
	var response *HttpResponse
	if len(x.Response) != 0 {
		response = NewHttpResponse(bytes.Clone(x.Response))
	}
	return &HttpRequestResponse{
		request:  NewHttpRequestWithService(pinServiceDestination(service), bytes.Clone(x.Request)),
		response: response,
		snapshot: x.Clone(),
	}, nil
}

// parseEvidenceServiceURL validates a destination with net/url instead of the
// permissive legacy service parser. Explicit ports must be numeric and in range;
// an absent port defaults to the HTTP(S) scheme's port. Hostname handles IPv6.
func parseEvidenceServiceURL(rawURL string) (*Service, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid service URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return nil, fmt.Errorf("service URL must have an http/https scheme and host without user information")
	}
	port := GetDefaultPort(u.Scheme)
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid service port %q", p)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("service URL has an empty explicit port")
	}
	// net/url permits an unbracketed IPv6 authority; require the unambiguous URL
	// form so its final address component cannot masquerade as a port.
	if strings.Contains(u.Hostname(), ":") && !strings.HasPrefix(u.Host, "[") {
		return nil, fmt.Errorf("IPv6 service host must be bracketed")
	}
	return NewService(u.Hostname(), port, u.Scheme)
}

// NewRequestResponseRaw wraps already-built raw request bytes and a known service
// into an HttpRequestResponse WITHOUT re-parsing them. It is the fast-path
// replacement for the `ParseRawRequest(string(builtBytes)).WithService(svc)`
// idiom on the per-payload hot path: the raw produced by InsertionPoint.BuildRequest
// / SetMethod / AddHeader / SetPath / SetBody is already well-formed, so the
// textproto re-parse, the throwaway Service construction, and the []byte→string→
// []byte round-trip that ParseRawRequest performs are pure overhead. The request
// parses its fields lazily (HttpRequest.ensureParsed) only if a caller reads them.
//
// Use this only with TRUSTED, internally-built raw bytes. For untrusted external
// input that must be validated, use ParseRawRequest (it returns a parse error).
func NewRequestResponseRaw(raw []byte, service *Service) *HttpRequestResponse {
	return NewHttpRequestResponse(NewHttpRequestWithService(service, raw), nil)
}

// ParseRawRequest parses a raw HTTP request from a string.
// Note: Response field is optional and should be added manually if needed.
func ParseRawRequest(raw string) (rr *HttpRequestResponse, err error) {
	defer func() {
		// panic handle (recover from panic)
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	protoReader := textproto.NewReader(bufio.NewReader(strings.NewReader(raw)))
	methodLine, err := protoReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read method line: %w", err)
	}
	rr = &HttpRequestResponse{
		request: &HttpRequest{},
	}
	/// must contain at least 3 parts
	parts := strings.Split(methodLine, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid method line: %s", methodLine)
	}

	// parse relative url to determine scheme (http/https)
	urlx, err := urlutil.ParseRawRelativePath(parts[1], true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	// parse host line
	hostLine, err := protoReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read host line: %w", err)
	}
	sep := strings.Index(hostLine, ":")
	if sep <= 0 || sep >= len(hostLine)-1 {
		return nil, fmt.Errorf("invalid host line: %s", hostLine)
	}
	hostValue := hostLine[sep+2:]

	// Build raw request with all headers, with the body reconciled against the
	// Content-Length the request declares. ParseRawRequest is the designated
	// parser for UNTRUSTED external bytes (NewRequestResponseRaw is the trusted
	// fast path for raws this process built), and external raw requests are
	// exactly where the two disagree — see declared_body.go.
	rr.request.raw = ReconcileDeclaredBody([]byte(raw))

	// Populate Service from host and URL scheme.
	// Raw HTTP request lines use origin-form (no scheme), so we infer the scheme
	// in priority order: an explicit scheme on the request line (absolute-form) >
	// a well-known Host port (80/443) > a same-origin Origin/Referer header > the
	// https default. The default is https because modern web is TLS by default;
	// callers that need http explicitly can still pass it via the URL field or
	// override the service with WithService.
	if hostValue != "" {
		protocol := "https"
		schemeKnown := false
		portExplicit := false
		port := 0

		// Absolute-form request lines (e.g. CONNECT, proxy form) may carry a scheme.
		switch urlx.Scheme {
		case "http":
			protocol, schemeKnown = "http", true
		case "https":
			protocol, schemeKnown = "https", true
		}
		// Extract port from Host header value (e.g. "127.0.0.1:3000").
		if h, p, splitErr := net.SplitHostPort(hostValue); splitErr == nil {
			hostValue = h
			if parsed := parsePort(p); parsed > 0 {
				port, portExplicit = parsed, true
				// Infer scheme from a well-known port only when none was explicit.
				if !schemeKnown {
					switch parsed {
					case 80:
						protocol, schemeKnown = "http", true
					case 443:
						protocol, schemeKnown = "https", true
					}
				}
			}
		}
		// When neither the request line nor a well-known port pins the scheme,
		// fall back to the scheme declared by a same-origin Origin/Referer header.
		// Browser/proxy-captured requests to an http service on a non-standard port
		// (e.g. "Host: localhost:3000" with "Referer: http://localhost:3000/")
		// would otherwise be silently upgraded to https by the default below.
		if !schemeKnown {
			// Thread the already-computed target port (from the Host header, 0 when
			// none) so a same-host Origin/Referer on a DIFFERENT port is not treated
			// as same-origin and cannot flip the scheme (e.g. a :3000 frontend Origin
			// on a request to an :8443 API must not infer http for the TLS service).
			if s, _, ok := OriginRefererScheme(raw, hostValue, port); ok {
				protocol = s
			}
		}
		// Also try the port from the URL path (absolute-form lines like CONNECT).
		if urlPort := urlx.Port(); urlPort != "" {
			if parsed := parsePort(urlPort); parsed > 0 {
				port, portExplicit = parsed, true
			}
		}
		// Default the port from the resolved scheme when the Host carried none.
		if !portExplicit {
			if protocol == "http" {
				port = 80
			} else {
				port = 443
			}
		}
		service, _ := NewService(hostValue, port, protocol)
		rr.request.service = service
	}

	return rr, nil
}

// OriginRefererScheme returns the URL scheme ("http" or "https") declared by the
// request's Origin or Referer header, but only when that header names the same
// host — and, when targetPort > 0, the same port — we are about to connect to. It
// lets raw requests captured from a browser/proxy keep their real scheme when the
// request line is origin-form (no scheme) and the port is non-standard — e.g. an
// http service on :3000. A cross-origin Origin/Referer (a different host, or a
// different port when targetPort is known, as in a CORS request or an external
// referrer) is ignored so it cannot mislead scheme inference; Origin is preferred
// over Referer as it is the exact origin the browser attached. host must be the
// bare hostname (no port); targetPort is the port being connected to (0 when
// unknown, which falls back to host-only matching). header names which header
// supplied the scheme ("Origin"/"Referer"). Returns ok=false when neither header
// yields a same-origin http/https scheme.
func OriginRefererScheme(raw, host string, targetPort int) (scheme, header string, ok bool) {
	if host == "" {
		return "", "", false
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	refererScheme := ""
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first { // request line
			first = false
			continue
		}
		if line == "" { // blank line terminates the header block
			break
		}
		name, value, cut := strings.Cut(line, ":")
		if !cut {
			continue
		}
		if strings.EqualFold(name, "Origin") {
			if s := sameHostScheme(value, host, targetPort); s != "" {
				return s, "Origin", true
			}
		} else if refererScheme == "" && strings.EqualFold(name, "Referer") {
			refererScheme = sameHostScheme(value, host, targetPort)
		}
	}
	if refererScheme != "" {
		return refererScheme, "Referer", true
	}
	return "", "", false
}

// sameHostScheme parses an absolute URL (an Origin or Referer value) and returns
// its scheme only when it is http/https and its hostname case-insensitively
// equals host. When targetPort > 0 the URL's authority port (an empty port
// normalizes to the scheme default 80/443) must also equal targetPort — this
// stops a same-host, different-port Origin/Referer from being treated as
// same-origin. Returns "" otherwise (parse failure, opaque origin, non-http(s)
// scheme, a cross-origin host, or a cross-port authority when targetPort is set).
func sameHostScheme(rawURL, host string, targetPort int) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if !strings.EqualFold(u.Hostname(), host) {
		return ""
	}
	if targetPort > 0 && originURLPort(u) != targetPort {
		return ""
	}
	return u.Scheme
}

// originURLPort returns the authority port of u, normalizing an empty port to the
// scheme's default (80 for http, 443 for https; 443 for any other scheme).
func originURLPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		return parsePort(p)
	}
	if dp := GetDefaultPort(u.Scheme); dp > 0 {
		return dp
	}
	return 443
}

// ParseRawRequestWithURL parses a raw HTTP request with explicit URL override.
func ParseRawRequestWithURL(raw, url string) (*HttpRequestResponse, error) {
	rr, err := ParseRawRequest(raw)
	if err != nil {
		return nil, err
	}
	urlx, err := urlutil.ParseAbsoluteURL(url, false)
	if err != nil {
		return nil, err
	}

	// Update Service with the overridden URL
	if rr.request != nil {
		port := 80
		protocol := "http"
		if urlx.Scheme == "https" {
			protocol = "https"
			port = 443
		}
		urlPort := urlx.Port()
		if urlPort != "" {
			port = parsePort(urlPort)
		}
		service, _ := NewService(urlx.Host, port, protocol)
		rr.request.service = service
	}

	return rr, nil
}

// GetRawRequestFromURL creates a basic GET request from a URL.
// Default browser headers will be applied by the HTTP client at request time.
func GetRawRequestFromURL(url string) (*HttpRequestResponse, error) {
	urlx, err := urlutil.ParseAbsoluteURL(url, false)
	if err != nil {
		return nil, err
	}
	raw := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		escapedRequestTarget(urlx),
		urlx.Host,
	)
	rr, err := ParseRawRequest(raw)
	if err != nil {
		return nil, err
	}

	// Update Service with the correct URL
	if rr.request != nil {
		port := 80
		protocol := "http"
		if urlx.Scheme == "https" {
			protocol = "https"
			port = 443
		}
		urlPort := urlx.Port()
		if urlPort != "" {
			port = parsePort(urlPort)
		}
		service, _ := NewService(urlx.Host, port, protocol)
		rr.request.service = service
	}

	return rr, nil
}

// GetRawRequestFromURLWithMethod creates a request from a URL while preserving
// the discovered HTTP method, request headers, and body. This is the
// method/body-aware counterpart to GetRawRequestFromURL: it lets non-GET
// discoveries (form POSTs, JS-derived API calls) be imported without being
// flattened to a bodyless GET, which would silently lose API and form coverage.
//
// When method is empty/GET and body is empty it delegates to
// GetRawRequestFromURL for identical behavior. Header values containing CR/LF
// are dropped to avoid request smuggling from malformed stored headers; Host and
// Content-Length are always managed here (never taken from the stored map).
func GetRawRequestFromURLWithMethod(rawURL, method string, headers map[string]string, body []byte) (*HttpRequestResponse, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if (method == "" || method == "GET") && len(body) == 0 {
		return GetRawRequestFromURL(rawURL)
	}
	if method == "" {
		method = "GET"
	}

	urlx, err := urlutil.ParseAbsoluteURL(rawURL, false)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, escapedRequestTarget(urlx))
	fmt.Fprintf(&b, "Host: %s\r\n", urlx.Host)

	// Emit stored headers deterministically, skipping ones we manage (Host is set
	// above; Content-Length is derived from body) and any with control chars.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		switch http.CanonicalHeaderKey(k) {
		case "Host", "Content-Length":
			continue
		}
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(headers[k], "\r\n") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, headers[k])
	}

	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}

	// The raw is internally built and trusted, so skip the ParseRawRequest
	// re-parse + throwaway Service and wrap it directly with the correct service.
	port := 80
	protocol := "http"
	if urlx.Scheme == "https" {
		protocol = "https"
		port = 443
	}
	if urlPort := urlx.Port(); urlPort != "" {
		port = parsePort(urlPort)
	}
	service, _ := NewService(urlx.Host, port, protocol)
	return NewRequestResponseRaw([]byte(b.String()), service), nil
}

// FromSentRequest renders an http.Request that has ALREADY been sent into raw
// request bytes, paired with its Service.
//
// Use it instead of FromStdRequest whenever the request's round trip is over.
// FromStdRequest calls httputil.DumpRequestOut, which renders the wire bytes by
// running the request through a dummy transport — a real round trip that honours
// the request's context. http.Client cancels that context when the response body
// closes, so on a completed request DumpRequestOut fails with "context canceled"
// and the caller silently gets nothing. Walking a followed redirect chain is the
// case that exposed this. Rendering directly is also cheaper: no round trip.
//
// The body is deliberately not rendered. A sent request's body has already been
// consumed, and Go drops it entirely when following a 301/302/303, so there is
// nothing to recover and nothing to claim. Header values containing CR/LF are
// dropped for the same reason GetRawRequestFromURLWithMethod drops them: a
// stored header must not be able to smuggle a second request. Host is taken from
// the request rather than the header map, and header names are emitted in sorted
// order so the same request renders the same bytes every time — the raw request
// is hashed into the record's identity, and Go's header map iteration order is
// random.
func FromSentRequest(req *http.Request) (*HttpRequestResponse, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request is nil")
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return nil, fmt.Errorf("request has no host")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	target := req.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}

	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if http.CanonicalHeaderKey(name) == "Host" || strings.ContainsAny(name, "\r\n") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.Grow(len(method) + len(target) + len(proto) + len(host) + 64 + 48*len(names))
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(target)
	b.WriteByte(' ')
	b.WriteString(proto)
	b.WriteString("\r\n")
	b.WriteString("Host: ")
	b.WriteString(host)
	b.WriteString("\r\n")
	for _, name := range names {
		for _, v := range req.Header[name] {
			if strings.ContainsAny(v, "\r\n") {
				continue
			}
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")

	return NewRequestResponseRaw([]byte(b.String()), serviceForURL(req.URL)), nil
}

// serviceForURL derives the Service (host, effective port, scheme) for a parsed
// URL: the scheme's default port unless an explicit one is present. Uses
// Hostname()/Port() rather than splitting on ":" so an IPv6 literal survives.
func serviceForURL(u *url.URL) *Service {
	isHTTPS := u.Scheme == "https"
	port := 80
	if isHTTPS {
		port = 443
	}
	if p := parsePort(u.Port()); p > 0 {
		port = p
	}
	return NewServiceSecure(u.Hostname(), port, isHTTPS)
}

// FromStdRequest creates HttpRequestResponse from a standard http.Request.
func FromStdRequest(req *http.Request) (*HttpRequestResponse, error) {
	// Check if original request has User-Agent BEFORE dumping
	// (DumpRequestOut auto-adds "User-Agent: Go-http-client/1.1")
	hasOriginalUA := req.Header.Get("User-Agent") != ""

	// DumpRequestOut will automatically add the scheme and host to the request
	dumpRequest, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}
	rr, err := ParseRawRequest(string(dumpRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw request: %w", err)
	}

	// Remove Go's auto-added User-Agent if original didn't have one
	if !hasOriginalUA && rr.request != nil {
		rr.request = rr.request.WithRemovedHeader("User-Agent")
	}

	// Update Service with correct scheme and port from original request URL
	if rr.request != nil && req.URL != nil {
		port := 80
		isHTTPS := req.URL.Scheme == "https"
		if isHTTPS {
			port = 443
		}
		// Get port from original URL (not from parsed service which may be wrong)
		if urlPort := req.URL.Port(); urlPort != "" {
			port = parsePort(urlPort)
		}
		host := req.URL.Hostname()
		rr.request.service = NewServiceSecure(host, port, isHTTPS)
	}

	return rr, nil
}
