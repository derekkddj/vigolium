package vigtool

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/replay"
)

const (
	// sendRawPerRunCap bounds total raw sockets the agent can open in one
	// run. Mirrors replay_request's ceiling — high enough to actually probe
	// a desync surface, low enough that a runaway loop can't hammer a host.
	sendRawPerRunCap = 200

	sendRawConnectTimeout = 10 * time.Second
	sendRawReadTimeout    = 10 * time.Second
	sendRawReadCapBytes   = 64 * 1024
	sendRawReadCapMax     = 1 * 1024 * 1024
)

// NewSendRawHTTPTool returns the send_raw_http tool — writes exact bytes to a
// TCP/TLS socket with zero net/http normalisation, so the agent can express
// request smuggling / desync / CRLF / malformed-request attacks that
// web_fetch and replay_request structurally cannot. Destinations are
// hard-blocked to the run's scope: an autonomous agent putting arbitrary
// bytes on an arbitrary socket is the most dangerous primitive in the
// toolkit, so it stays anchored to what the operator authorised.
func NewSendRawHTTPTool(ctx *ScanContext) tool.Tool {
	return &sendRawHTTPTool{ctx: ctx}
}

type sendRawHTTPTool struct {
	tool.HTTPReceiptStore
	ctx      *ScanContext
	totalRun atomic.Int64
	// dial is a deterministic socket test seam; production uses net.Dialer.
	dial         func(context.Context, string, string) (net.Conn, error)
	transcriptMu sync.Mutex
	transcripts  map[string]*RawHTTPTranscript
}

type RawHTTPTranscriptProvider interface {
	SelectRawHTTPTranscript(ref string) (*RawHTTPTranscript, error)
}

// RawHTTPTranscript describes an execution, not a fabricated HTTP exchange.
// Writes and idle-read windows have independent selectable receipts. A read
// window can contain zero, one, or several responses to either write; without
// message framing, response attribution MUST remain unknown.
type RawHTTPTranscript struct {
	ID                  string                `json:"id"`
	Ref                 string                `json:"ref"`
	Boundary            string                `json:"boundary"`
	ResponseAttribution evidence.State        `json:"response_attribution"`
	Writes              []RawHTTPWriteReceipt `json:"writes"`
	Reads               []RawHTTPReadReceipt  `json:"reads"`
}

type RawHTTPWriteReceipt struct {
	Phase         int `json:"phase"`
	IntendedBytes int `json:"intended_bytes"`
	SentBytes     int `json:"sent_bytes"`
	// Complete means the entire intended slice was accepted by conn.Write at
	// the application boundary, not HTTP framing or proof of server processing.
	State   evidence.State           `json:"state"`
	Receipt tool.HTTPReceiptManifest `json:"receipt"`
}

type RawHTTPReadReceipt struct {
	Window        string `json:"window"`
	BytesRead     int    `json:"bytes_read"`
	RetainedBytes int    `json:"retained_bytes"`
	// State describes this stream window, not a paired HTTP response. The
	// nonempty selected receipt keeps ResponseState unknown unless truncated.
	State       evidence.State           `json:"capture_state"`
	Termination string                   `json:"termination"`
	Error       string                   `json:"error,omitempty"`
	Receipt     tool.HTTPReceiptManifest `json:"receipt"`
}

func cloneRawHTTPTranscript(t *RawHTTPTranscript) *RawHTTPTranscript {
	copy := *t
	copy.Writes = append([]RawHTTPWriteReceipt(nil), t.Writes...)
	copy.Reads = append([]RawHTTPReadReceipt(nil), t.Reads...)
	return &copy
}

// SelectRawHTTPTranscript selects byte-free metadata; select each receipt ref
// through HTTPReceiptProvider to obtain owned bytes. Handles expire with this
// tool instance and never resolve by destination or intended-request text.
func (s *sendRawHTTPTool) SelectRawHTTPTranscript(ref string) (*RawHTTPTranscript, error) {
	if !strings.HasPrefix(ref, "raw-http-transcript:") {
		return nil, fmt.Errorf("invalid raw HTTP transcript ref")
	}
	s.transcriptMu.Lock()
	t := s.transcripts[strings.TrimPrefix(ref, "raw-http-transcript:")]
	if t == nil {
		s.transcriptMu.Unlock()
		return nil, fmt.Errorf("raw HTTP transcript unavailable in this tool instance")
	}
	selected := cloneRawHTTPTranscript(t)
	s.transcriptMu.Unlock()
	s.refreshRawHTTPTranscript(selected)
	return selected, nil
}

func (s *sendRawHTTPTool) refreshRawHTTPTranscript(t *RawHTTPTranscript) {
	for i := range t.Writes {
		t.Writes[i].Receipt = s.RefreshHTTPReceiptAvailability(t.Writes[i].Receipt)
	}
	for i := range t.Reads {
		t.Reads[i].Receipt = s.RefreshHTTPReceiptAvailability(t.Reads[i].Receipt)
	}
}

func (*sendRawHTTPTool) Name() string     { return "send_raw_http" }
func (*sendRawHTTPTool) Label() string    { return "Send raw HTTP" }
func (*sendRawHTTPTool) Category() string { return tool.CategoryVigolium }
func (*sendRawHTTPTool) IsReadOnly() bool { return false }
func (*sendRawHTTPTool) Description() string {
	return "Write exact bytes to a TCP/TLS socket with NO net/http normalisation — for request " +
		"smuggling, HTTP desync, CRLF/header injection, and malformed-request testing that web_fetch " +
		"and replay_request cannot express. Supply the full request line + headers + body verbatim " +
		"(use \\r\\n line endings). Optionally send a second request on the SAME connection to confirm " +
		"desync. Returned sent counts/echoes describe actual socket writes; intended previews are separate. " +
		"Selectable execution-scoped transcript receipts preserve each write and read window independently; " +
		"response attribution remains unknown without HTTP framing, especially for pipelines. Nothing is " +
		"persisted as a fabricated HTTP pair. Destinations are hard-blocked to the run's scope. Capped at 200 sends per run."
}

func (*sendRawHTTPTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target": map[string]any{
				"type":        "string",
				"description": "Destination: scheme://host[:port] (e.g. https://app.example.com or http://app.example.com:8080). Must be in scope — out-of-scope hosts are rejected.",
			},
			"raw_request": map[string]any{
				"type":        "string",
				"description": "Exact request bytes. Include the request line, headers, blank line, and body. Use \\r\\n line endings. Sent verbatim — no header/Content-Length fixup.",
			},
			"second_request": map[string]any{
				"type":        "string",
				"description": "Optional second request sent on the SAME connection. Use to probe smuggling/desync; read windows are not automatically attributable to a particular request.",
			},
			"pipeline": map[string]any{
				"type":        "boolean",
				"description": "When true and second_request is set, write both requests back-to-back before reading (classic CL.TE/TE.CL pipelining). Default false: read an idle-delimited window, then send the second. Response attribution remains unknown.",
			},
			"tls": map[string]any{
				"type":        "boolean",
				"description": "Force TLS on/off. Default: inferred from scheme (https) or port (443).",
			},
			"tls_sni": map[string]any{
				"type":        "string",
				"description": "Override the TLS SNI / ServerName. Default: target host. Certificate verification is always skipped (testing tool).",
			},
			"connect_timeout_ms": map[string]any{
				"type":        "integer",
				"description": "TCP/TLS connect timeout in ms. Default 10000.",
			},
			"read_timeout_ms": map[string]any{
				"type":        "integer",
				"description": "Idle read timeout in ms — reading stops this long after the last byte. Default 10000.",
			},
			"read_cap_bytes": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max response bytes retained per read window. Actual reads may return more bytes, which are counted and flagged as omitted. Default %d, max %d.", sendRawReadCapBytes, sendRawReadCapMax),
			},
			"normalize_newlines": map[string]any{
				"type":        "boolean",
				"description": "Convenience: rewrite all line endings to \\r\\n before sending. Default false (exact bytes — required for most desync payloads).",
			},
		},
		"required": []string{"target", "raw_request"},
	}
}

func (s *sendRawHTTPTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if cur := s.totalRun.Load(); cur >= sendRawPerRunCap {
		return tool.Result{
			Content: fmt.Sprintf("send_raw_http rate-limited: %d sends this run (cap=%d). "+
				"If you still need to probe, halt and resume with a fresh run.", cur, sendRawPerRunCap),
			IsError: true,
		}, nil
	}

	target := argsString(args, "target")
	raw := stringArg(args, "raw_request")
	if target == "" || raw == "" {
		return tool.Result{Content: "send_raw_http: 'target' and 'raw_request' are both required", IsError: true}, nil
	}

	host, port, useTLS, perr := parseTarget(target, args)
	if perr != nil {
		return tool.Result{Content: "send_raw_http: " + perr.Error(), IsError: true}, nil
	}

	allowed := s.allowedHosts()
	if !hostInScope(host, allowed) {
		return tool.Result{
			Content: fmt.Sprintf(
				"send_raw_http: host %q is out of scope and was NOT sent. send_raw_http hard-blocks "+
					"out-of-scope destinations. In-scope hosts: [%s]. If this host is legitimately part "+
					"of the engagement, it must be added to the run's scope by the operator.",
				host, strings.Join(allowed, ", ")),
			IsError: true,
		}, nil
	}

	if argsBool(args, "normalize_newlines") {
		raw = normalizeCRLF(raw)
	}
	second := stringArg(args, "second_request")
	if second != "" && argsBool(args, "normalize_newlines") {
		second = normalizeCRLF(second)
	}

	connectTO := durationMs(args, "connect_timeout_ms", sendRawConnectTimeout)
	readTO := durationMs(args, "read_timeout_ms", sendRawReadTimeout)
	readCap := argsInt(args, "read_cap_bytes")
	if readCap <= 0 {
		readCap = sendRawReadCapBytes
	}
	if readCap > sendRawReadCapMax {
		readCap = sendRawReadCapMax
	}

	s.totalRun.Add(1)

	out := s.exchange(ctx, host, port, useTLS, sniFor(args, host), []byte(raw), []byte(second),
		argsBool(args, "pipeline"), connectTO, readTO, readCap)

	body, _ := json.Marshal(out)
	details := map[string]any{
		"target":             fmt.Sprintf("%s:%d", host, port),
		"response_bytes":     out.ResponseBytesTotal,
		"conn_closed_early":  out.ConnClosedEarly,
		"two_request":        second != "",
		"sent_bytes":         out.SentBytes,
		"intended_bytes":     out.IntendedBytes,
		"transcript":         out.Transcript,
		"persisted":          false,
		"persistence_status": out.PersistenceStatus,
	}
	if out.Error != "" {
		details["error"] = out.Error
	}
	return tool.Result{Content: string(body), Details: details}, nil
}

type rawExchangeResult struct {
	Target                         string             `json:"target"`
	TLS                            bool               `json:"tls"`
	SentBytes                      int                `json:"sent_bytes"` // sum of actual conn.Write n, not intended sizes
	SentEcho                       string             `json:"sent_echo"`  // actual first write only
	SentTruncated                  bool               `json:"sent_echo_truncated,omitempty"`
	SecondSentBytes                int                `json:"second_sent_bytes"`
	SecondSentEcho                 string             `json:"second_sent_echo,omitempty"`
	SecondSentTruncated            bool               `json:"second_sent_echo_truncated,omitempty"`
	IntendedBytes                  int                `json:"intended_bytes"`
	IntendedRequest                string             `json:"intended_request"`
	IntendedRequestTruncated       bool               `json:"intended_request_truncated,omitempty"`
	IntendedSecondRequest          string             `json:"intended_second_request,omitempty"`
	IntendedSecondRequestTruncated bool               `json:"intended_second_request_truncated,omitempty"`
	Response                       string             `json:"response"`
	ResponseTruncated              bool               `json:"response_truncated,omitempty"`
	ResponseBytesTotal             int                `json:"response_bytes_total"`      // retained first/shared read window (legacy)
	ResponseBytesReadTotal         int                `json:"response_bytes_read_total"` // actual reads, including cap omissions
	SecondResponse                 string             `json:"second_response,omitempty"`
	SecondResponseBytes            int                `json:"second_response_bytes,omitempty"`
	SecondResponseTruncated        bool               `json:"second_response_truncated,omitempty"`
	Transcript                     *RawHTTPTranscript `json:"transcript"`
	Persisted                      bool               `json:"persisted"`
	PersistenceStatus              string             `json:"persistence_status"`
	ReceiptError                   string             `json:"receipt_error,omitempty"`
	ElapsedMs                      int64              `json:"elapsed_ms"`
	ConnClosedEarly                bool               `json:"conn_closed_early"`
	Error                          string             `json:"error,omitempty"`
}

// exchange dials the socket, writes the exact bytes, and reads the raw
// response(s). Network errors land in result.Error (not a Go error) so the
// model always gets a structured reply it can reason about.
func (s *sendRawHTTPTool) exchange(ctx context.Context, host string, port int, useTLS bool, sni string,
	req, second []byte, pipeline bool, connectTO, readTO time.Duration, readCap int) *rawExchangeResult {

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	service := scheme + "://" + addr
	tid := uuid.NewString()
	transcript := &RawHTTPTranscript{ID: tid, Ref: "raw-http-transcript:" + tid, Boundary: "socket_application_bytes", ResponseAttribution: evidence.StateUnknown,
		Writes: []RawHTTPWriteReceipt{{Phase: 1, IntendedBytes: len(req), State: evidence.StateMissing}}, Reads: []RawHTTPReadReceipt{}}
	if len(second) > 0 {
		transcript.Writes = append(transcript.Writes, RawHTTPWriteReceipt{Phase: 2, IntendedBytes: len(second), State: evidence.StateMissing})
	}
	res := &rawExchangeResult{Target: addr, TLS: useTLS, IntendedBytes: len(req) + len(second), Transcript: transcript, PersistenceStatus: "execution_scoped_only"}
	res.IntendedRequest, res.IntendedRequestTruncated = clipBytes(req, replay.DefaultExcerptCap)
	res.IntendedSecondRequest, res.IntendedSecondRequestTruncated = clipBytes(second, replay.DefaultExcerptCap)
	written := make([][]byte, len(transcript.Writes))
	start := time.Now()
	defer func() {
		res.ElapsedMs = time.Since(start).Milliseconds()
		for i := range transcript.Writes {
			x := evidence.NewExchange(service, service, written[i], nil, evidence.ProvenanceCaptured)
			x.RequestState = transcript.Writes[i].State
			x.ContentHash = x.Hash()
			manifest, err := s.RetainHTTPReceipt(x, transcript.Boundary)
			transcript.Writes[i].Receipt = manifest
			if err != nil {
				res.ReceiptError = err.Error()
			}
		}
		// Read receipts were retained before writes. Large writes or concurrent
		// executions may have evicted them; never publish stale availability.
		s.refreshRawHTTPTranscript(transcript)
		s.transcriptMu.Lock()
		defer s.transcriptMu.Unlock()
		if s.transcripts == nil {
			s.transcripts = make(map[string]*RawHTTPTranscript)
		}
		if len(s.transcripts) >= sendRawPerRunCap {
			for id := range s.transcripts {
				delete(s.transcripts, id)
				break
			}
		}
		s.transcripts[tid] = cloneRawHTTPTranscript(transcript)
	}()

	d := net.Dialer{Timeout: connectTO}
	dial := s.dial
	if dial == nil {
		dial = d.DialContext
	}
	rawConn, err := dial(ctx, "tcp", addr)
	if err != nil {
		res.Error = fmt.Sprintf("dial %s: %v", addr, err)
		return res
	}
	conn := net.Conn(rawConn)
	defer func() { _ = conn.Close() }()

	if useTLS {
		tconn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // testing tool: target certs are often self-signed/invalid by design
			ServerName:         sni,
		})
		hsCtx, cancel := context.WithTimeout(ctx, connectTO)
		defer cancel()
		if err := tconn.HandshakeContext(hsCtx); err != nil {
			res.Error = fmt.Sprintf("tls handshake %s: %v", addr, err)
			return res
		}
		conn = tconn
	}

	write := func(i int, b []byte) error {
		if len(b) == 0 {
			return nil
		}
		_ = conn.SetWriteDeadline(time.Now().Add(connectTO))
		n, werr := conn.Write(b)
		if n < 0 || n > len(b) {
			return fmt.Errorf("socket returned invalid written-byte count")
		}
		written[i] = bytes.Clone(b[:n])
		transcript.Writes[i].SentBytes = n
		if n == len(b) {
			transcript.Writes[i].State = evidence.StateComplete
		} else if n > 0 {
			transcript.Writes[i].State = evidence.StateTruncated
		}
		res.SentBytes += n
		if i == 0 {
			res.SentEcho, res.SentTruncated = clipBytes(written[i], replay.DefaultExcerptCap)
		} else {
			res.SecondSentBytes = n
			res.SecondSentEcho, res.SecondSentTruncated = clipBytes(written[i], replay.DefaultExcerptCap)
		}
		if werr == nil && n < len(b) {
			werr = io.ErrShortWrite
		}
		return werr
	}
	captureRead := func(window string) rawReadResult {
		read := readRaw(conn, readTO, readCap)
		// These bytes are an unparsed read window, not an established counterpart
		// to either write. EOF completes a stream window, not HTTP attribution.
		x := evidence.NewExchange(service, service, nil, read.Bytes, evidence.ProvenanceCaptured)
		if len(read.Bytes) > 0 {
			x.ResponseState = evidence.StateUnknown
			if read.Truncated {
				x.ResponseState = evidence.StateTruncated
			}
		}
		x.ContentHash = x.Hash()
		manifest, err := s.RetainHTTPReceipt(x, transcript.Boundary)
		if err != nil {
			res.ReceiptError = err.Error()
		}
		transcript.Reads = append(transcript.Reads, RawHTTPReadReceipt{Window: window, BytesRead: read.BytesRead, RetainedBytes: len(read.Bytes),
			State: read.State, Termination: read.Termination, Error: read.Error, Receipt: manifest})
		res.ResponseBytesReadTotal += read.BytesRead
		return read
	}

	if pipeline && len(second) > 0 {
		// Write both before reading — CL.TE / TE.CL pipelining.
		if err := write(0, req); err != nil {
			res.Error = fmt.Sprintf("write request 1: %v", err)
			return res
		}
		if err := write(1, second); err != nil {
			res.Error = fmt.Sprintf("write request 2: %v", err)
			return res
		}
		read := captureRead("pipeline_read")
		res.Response = string(read.Bytes)
		res.ResponseTruncated = read.Truncated
		res.ResponseBytesTotal = len(read.Bytes)
		res.ConnClosedEarly = read.Closed
		return res
	}

	if err := write(0, req); err != nil {
		res.Error = fmt.Sprintf("write request: %v", err)
		return res
	}
	read := captureRead("first_read")
	res.Response = string(read.Bytes)
	res.ResponseTruncated = read.Truncated
	res.ResponseBytesTotal = len(read.Bytes)
	res.ConnClosedEarly = read.Closed

	if len(second) > 0 {
		if read.Closed {
			res.Error = "connection closed before second request could be sent (no keep-alive)"
			return res
		}
		if err := write(1, second); err != nil {
			res.Error = fmt.Sprintf("write request 2: %v", err)
			return res
		}
		read2 := captureRead("second_read")
		res.SecondResponse = string(read2.Bytes)
		res.SecondResponseBytes = len(read2.Bytes)
		res.SecondResponseTruncated = read2.Truncated
		res.ConnClosedEarly = read2.Closed
	}
	return res
}

type rawReadResult struct {
	Bytes       []byte
	BytesRead   int
	Closed      bool
	Truncated   bool
	State       evidence.State
	Termination string
	Error       string
}

// readRaw preserves the existing read sizes/deadlines and does not add reads to
// test completeness. Counts include bytes Read returned but the cap omitted.
// An idle deadline is unknown completeness, not EOF; reaching a cap without EOF
// is truncated. HTTP response attribution is intentionally handled separately.
func readRaw(conn net.Conn, idle time.Duration, limit int) rawReadResult {
	out := rawReadResult{State: evidence.StateMissing}
	buf := make([]byte, 16*1024)
	for len(out.Bytes) < limit {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, err := conn.Read(buf)
		if n > 0 {
			out.BytesRead += n
			room := limit - len(out.Bytes)
			keep := n
			if keep > room {
				keep = room
				out.Truncated = true
			}
			out.Bytes = append(out.Bytes, buf[:keep]...)
			out.State = evidence.StateUnknown
		}
		if err != nil {
			var ne net.Error
			switch {
			case errors.As(err, &ne) && ne.Timeout():
				out.Termination = "idle_timeout"
			case errors.Is(err, io.EOF):
				out.Termination, out.Closed = "eof", true
				if len(out.Bytes) > 0 {
					out.State = evidence.StateComplete // complete window, NOT paired HTTP
				}
			default:
				out.Termination, out.Closed, out.Error = "read_error", true, err.Error()
			}
			if out.Truncated {
				out.State = evidence.StateTruncated
			}
			return out
		}
	}
	out.Termination, out.Truncated, out.State = "cap", true, evidence.StateTruncated
	return out
}

// allowedHosts derives the in-scope host allowlist from the run's primary
// target plus any host-like scope entries. Empty means "block everything" —
// raw-send without an authorised network target is meaningless anyway.
func (s *sendRawHTTPTool) allowedHosts() []string {
	if s.ctx == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	add(hostOf(s.ctx.Target))
	for _, sc := range s.ctx.Scope {
		add(hostOf(sc))
	}
	return out
}

// hostOf extracts a bare hostname from a URL, host:port, or bare-host string.
// Returns "" for entries that aren't host-like (free-text scope notes).
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// Reject obvious non-host tokens (paths, sentences, globs).
	if strings.ContainsAny(s, " \t/\\*?") {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(s)
}

func hostInScope(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if host == a {
			return true
		}
	}
	return false
}

// parseTarget resolves host, port, and TLS from the target string + optional
// overrides. Accepts scheme://host[:port], host:port, or bare host.
func parseTarget(target string, args map[string]any) (host string, port int, useTLS bool, err error) {
	t := strings.TrimSpace(target)
	var scheme string
	if strings.Contains(t, "://") {
		u, perr := url.Parse(t)
		if perr != nil || u.Hostname() == "" {
			return "", 0, false, fmt.Errorf("invalid target URL %q", target)
		}
		scheme = strings.ToLower(u.Scheme)
		host = u.Hostname()
		if p := u.Port(); p != "" {
			_, _ = fmt.Sscanf(p, "%d", &port)
		}
	} else if h, p, serr := net.SplitHostPort(t); serr == nil {
		host = h
		_, _ = fmt.Sscanf(p, "%d", &port)
	} else {
		host = t
	}
	if host == "" {
		return "", 0, false, fmt.Errorf("could not determine host from %q", target)
	}

	switch scheme {
	case "https":
		useTLS = true
	case "http":
		useTLS = false
	default:
		useTLS = port == 443
	}
	if v, ok := args["tls"].(bool); ok {
		useTLS = v
	}
	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}
	return host, port, useTLS, nil
}

func sniFor(args map[string]any, host string) string {
	if v := argsString(args, "tls_sni"); v != "" {
		return v
	}
	return host
}

// stringArg reads a string without trimming — raw_request / second_request
// must preserve leading/trailing whitespace and exact line endings.
func stringArg(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

func durationMs(args map[string]any, key string, def time.Duration) time.Duration {
	if v := argsInt(args, key); v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return def
}

// normalizeCRLF rewrites all line endings to \r\n. Convenience only — most
// desync payloads need exact bytes and must not use this.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
