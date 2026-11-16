package tool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	vhttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// ---------- web_fetch ----------
//
// Dual-mode:
//   - Default: plain HTTP(S) GET/POST via net/http. Fast, no browser.
//   - mode="browser": drives Chromium via spitolas (CDP) for JS-rendered
//     pages, SPAs, login-gated content. Spawns a fresh headless browser,
//     navigates, optionally waits for a selector, then returns the
//     post-render DOM. When the tool is wired with a capture sink, every
//     XHR/fetch the page issues during render is persisted as an
//     http_record (source="web-fetch-browser") so query_records sees the
//     real network surface, not just the document.
//
// The tool keeps a single schema so the model doesn't have to choose two
// different tools — it decides per-call via the `mode` parameter.

// HTTPReceiptProvider selects exact captured bytes, never a URL/request-summary
// fallback. Refs are local to the producing tool instance and may expire when
// its bounded store evicts them. Selection returns an owned copy for evidence.Select.
type HTTPReceiptProvider interface {
	SelectHTTPReceipt(ref string) (*evidence.Exchange, error)
}

// HTTPReceiptManifest is deliberately byte-free so tool results remain bounded.
// Available describes retention at return time, not durable DB persistence.
type HTTPReceiptManifest struct {
	ID            string              `json:"id,omitempty"`
	Ref           string              `json:"ref,omitempty"`
	Boundary      string              `json:"boundary"`
	Available     bool                `json:"available"`
	Availability  string              `json:"availability"`
	RequestBytes  int                 `json:"request_bytes"`
	ResponseBytes int                 `json:"response_bytes"`
	RequestState  evidence.State      `json:"request_state"`
	ResponseState evidence.State      `json:"response_state"`
	Provenance    evidence.Provenance `json:"provenance,omitempty"`
	ContentHash   string              `json:"content_hash,omitempty"`
}

// HTTPReceiptStore has no network/filesystem effects. Its zero value is ready
// for use; bounded retention is shared by HTTP tools without a process-global
// cross-run cache. Existing identities cannot be replaced with changed bytes.
type HTTPReceiptStore struct {
	mu       sync.Mutex
	receipts map[string]*evidence.Exchange
	order    []string
	bytes    int
}

const httpReceiptMaxBytes = 32 * 1024 * 1024
const httpReceiptMaxEntries = 256

// The opaque ref binds identity, bytes/states, and capture time. If a caller
// reintroduces an evicted ID with changed content, an old ref must still fail
// selection rather than silently resolving to a different exchange.
func httpReceiptRef(x *evidence.Exchange) string {
	hash := sha256.Sum256([]byte(x.ID + "\x00" + x.ContentHash + "\x00" + x.CapturedAt.UTC().Format(time.RFC3339Nano)))
	return "http-receipt:" + hex.EncodeToString(hash[:])
}

func (s *HTTPReceiptStore) RetainHTTPReceipt(x *evidence.Exchange, boundary string) (HTTPReceiptManifest, error) {
	manifest := HTTPReceiptManifest{Boundary: boundary, Availability: "missing_capture", RequestState: evidence.StateMissing, ResponseState: evidence.StateMissing}
	if x == nil {
		return manifest, nil
	}
	manifest.ID, manifest.Ref = x.ID, httpReceiptRef(x)
	manifest.RequestBytes, manifest.ResponseBytes = len(x.Request), len(x.Response)
	manifest.RequestState, manifest.ResponseState = x.RequestState, x.ResponseState
	manifest.Provenance, manifest.ContentHash = x.Provenance, x.ContentHash
	if err := x.Validate(); err != nil {
		manifest.Availability = "invalid_capture"
		return manifest, err
	}
	size := len(x.Request) + len(x.Response)
	if size > httpReceiptMaxBytes {
		manifest.Availability = "retention_limit"
		return manifest, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.receipts {
		if existing.ID == x.ID && (existing.ContentHash != x.ContentHash || !existing.CapturedAt.Equal(x.CapturedAt)) {
			manifest.Availability = "identity_conflict"
			return manifest, fmt.Errorf("HTTP receipt identity changed")
		}
	}
	if s.receipts[manifest.Ref] == nil {
		if s.receipts == nil {
			s.receipts = make(map[string]*evidence.Exchange)
		}
		for len(s.order) >= httpReceiptMaxEntries || s.bytes+size > httpReceiptMaxBytes {
			id := s.order[0]
			s.order = s.order[1:]
			old := s.receipts[id]
			s.bytes -= len(old.Request) + len(old.Response)
			delete(s.receipts, id)
		}
		s.receipts[manifest.Ref] = x.Clone()
		s.order = append(s.order, manifest.Ref)
		s.bytes += size
	}
	manifest.Available, manifest.Availability = true, "execution_scoped"
	return manifest, nil
}

func (s *HTTPReceiptStore) HTTPReceiptAvailable(ref string) bool {
	if !strings.HasPrefix(ref, "http-receipt:") {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receipts[ref] != nil
}

// RefreshHTTPReceiptAvailability updates a retained manifest after another
// receipt may have evicted it. It does not turn a rejected capture into a ref to
// different bytes with the same ID. Selection itself remains authoritative.
func (s *HTTPReceiptStore) RefreshHTTPReceiptAvailability(manifest HTTPReceiptManifest) HTTPReceiptManifest {
	if manifest.Available && !s.HTTPReceiptAvailable(manifest.Ref) {
		manifest.Available, manifest.Availability = false, "expired"
	}
	return manifest
}

func (s *HTTPReceiptStore) SelectHTTPReceipt(ref string) (*evidence.Exchange, error) {
	if !strings.HasPrefix(ref, "http-receipt:") {
		return nil, fmt.Errorf("invalid HTTP receipt ref")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	x := s.receipts[ref]
	if x == nil {
		return nil, fmt.Errorf("HTTP receipt unavailable or expired in this tool instance")
	}
	return x.Clone(), nil
}

type webFetchTool struct {
	HTTPReceiptStore
	client *http.Client

	// captureSink + captureProject enable record persistence under source=
	// "web-fetch" / "web-fetch-browser". HTTP mode saves only complete captured
	// exchanges; partial receipts stay execution-scoped. Nil sink disables
	// persistence, not HTTP receipt capture.
	captureSink    spitolas.CaptureSink
	captureProject string

	// probe renders browser mode; nil means spitolas.ProbeURL. Overridable so
	// tests don't spawn real browsers.
	probe func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)

	// readOnly restricts the tool to safe methods (GET/HEAD) in http mode and
	// refuses browser mode, which executes page script with side effects the
	// tool cannot bound. Only this variant may claim IsReadOnly.
	readOnly bool
}

// NewWebFetch returns the no-persistence variant. Used by TUI chat, tests, and
// other callers that don't have a database wired. It still accepts mutating
// methods and browser mode, so it is not read-only — see NewWebFetchReadOnly.
func NewWebFetch() Tool {
	return &webFetchTool{client: &http.Client{Timeout: 30 * time.Second}}
}

// NewWebFetchReadOnly returns the genuinely read-only variant: GET/HEAD over
// plain HTTP, no browser mode, no persistence. Anything else is refused with an
// error result naming the restriction. Registered by RegisterReadOnlyBuiltins
// so strictly read-only contexts cannot issue state-changing requests.
func NewWebFetchReadOnly() Tool {
	return &webFetchTool{client: &http.Client{Timeout: 30 * time.Second}, readOnly: true}
}

// NewWebFetchWithCapture wires a CaptureSink to persist complete HTTP captures
// and browser network traffic to the project DB. Records appear in query_records
// under source="web-fetch" (HTTP mode) or "web-fetch-browser" (browser traffic).
// Pass nil sink or empty projectUUID to disable persistence; HTTP receipts remain
// available through HTTPReceiptProvider.
func NewWebFetchWithCapture(sink spitolas.CaptureSink, projectUUID string) Tool {
	if sink == nil || projectUUID == "" {
		return NewWebFetch()
	}
	return &webFetchTool{
		client:         &http.Client{Timeout: 30 * time.Second},
		captureSink:    sink,
		captureProject: projectUUID,
	}
}

func (*webFetchTool) Name() string     { return "web_fetch" }
func (*webFetchTool) Label() string    { return "Fetch URL" }
func (*webFetchTool) Category() string { return CategoryBuiltin }

// IsReadOnly gates whether the engine may fan this tool out concurrently with
// other read-only calls, and the contract is "no observable side effects"
// (tool.go). The general tool accepts state-changing methods and browser mode
// (page script runs), and the capture variant also writes http_records, so it
// is never read-only — whether a database happens to be wired does not change
// what a request can do to the target. Only NewWebFetchReadOnly qualifies.
func (w *webFetchTool) IsReadOnly() bool { return w.readOnly }
func (w *webFetchTool) Description() string {
	if w.readOnly {
		return "Fetch a URL with a read-only HTTP request (GET or HEAD only; no browser mode, nothing persisted). Returns the raw response."
	}
	return "Fetch a URL. Default mode is plain HTTP (fast, returns response and a selectable execution receipt). When persistence is enabled, only a complete captured exchange becomes a record; check Details.persisted, persistence_status and receipt availability. Details.record_uuid is returned only after a successful save. Set mode='browser' to render via headless Chromium (handles JS SPAs, client-side routing) — its XHR/fetch traffic can also be persisted as multiple http_records. Use browser mode when the initial HTTP response is empty or missing content that clearly depends on JavaScript; check its capture receipt and call query_records with the target hostname to enumerate saved records."
}
func (w *webFetchTool) Schema() map[string]any {
	modes := []string{"http", "browser"}
	modeDesc := "'http' = HTTP request with an execution receipt (fast, a record only when capture is complete and persistence succeeds); 'browser' = render with headless Chromium via CDP (also captures XHR/fetch issued during render)."
	method := map[string]any{"type": "string", "default": "GET", "description": "HTTP method (http mode only)."}
	if w.readOnly {
		modes = []string{"http"}
		modeDesc = "'http' only — this variant is read-only."
		method["enum"] = readOnlyMethods
		method["description"] = "HTTP method: GET or HEAD only (read-only variant)."
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{"type": "string", "description": "HTTP or HTTPS URL."},
			"mode": map[string]any{
				"type":        "string",
				"enum":        modes,
				"description": modeDesc,
				"default":     "http",
			},
			"method":  method,
			"headers": map[string]any{"type": "object", "description": "Extra request headers (http mode only)."},
			"body":    map[string]any{"type": "string", "description": "Request body (http mode only)."},
			"max_bytes": map[string]any{
				"type":        "integer",
				"description": "Truncate response body after N bytes. Default 512000.",
				"default":     512000,
			},
			"wait_selector": map[string]any{
				"type":        "string",
				"description": "(browser mode) CSS selector to wait for before grabbing HTML.",
			},
			"wait_ms": map[string]any{
				"type":        "integer",
				"description": "(browser mode) Extra ms to wait after load. Default 1500.",
				"default":     1500,
			},
		},
		"required": []string{"url"},
	}
}

func (w *webFetchTool) Execute(ctx context.Context, args map[string]any, onUpdate UpdateFn) (Result, error) {
	url, _ := args["url"].(string)
	if url == "" {
		return Result{
			Content: "web_fetch: 'url' is required - an absolute http(s) URL to request, e.g. {\"url\": \"https://host/path\"}. " +
				"To search traffic vigolium has already captured use query_records; for findings use list_findings.",
			IsError: true,
		}, nil
	}
	mode, _ := args["mode"].(string)
	if mode == "" {
		mode = "http"
	}
	if w.readOnly {
		if msg := readOnlyViolation(mode, args); msg != "" {
			return Result{Content: msg, IsError: true}, nil
		}
	}

	switch mode {
	case "browser":
		return w.executeBrowser(ctx, url, args)
	case "http":
		return w.executeHTTP(ctx, url, args)
	default:
		// Falling through to plain HTTP for an unrecognized mode is worse
		// than an error: the model asked for a rendered page, got the raw
		// document with no warning, and concludes the page has no
		// JS-rendered content.
		return Result{
			Content: fmt.Sprintf("web_fetch: unknown mode %q - use 'http' (raw request) or 'browser' (render with headless Chromium).", mode),
			IsError: true,
		}, nil
	}
}

// readOnlyMethods are the only methods the read-only variant sends: safe by
// HTTP semantics, so a fan-out of them cannot change target state.
var readOnlyMethods = []string{"GET", "HEAD"}

// readOnlyViolation names why a call cannot run on the read-only variant, or
// returns "" when it can.
func readOnlyViolation(mode string, args map[string]any) string {
	if mode == "browser" {
		return "web_fetch (read-only): mode='browser' is not available here — rendering runs page script, which can change application state. Use a plain GET."
	}
	method, _ := args["method"].(string)
	if method == "" {
		return ""
	}
	if !slices.Contains(readOnlyMethods, strings.ToUpper(method)) {
		return fmt.Sprintf("web_fetch (read-only): method %q is not allowed — only GET and HEAD can be sent from this context.", method)
	}
	return ""
}

func (w *webFetchTool) executeHTTP(ctx context.Context, url string, args map[string]any) (result Result, err error) {
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)

	var bodyReader io.Reader
	if bodyStr, ok := args["body"].(string); ok && bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return Result{Content: fmt.Sprintf("bad request: %v", err), IsError: true}, nil
	}
	req.Header.Set("User-Agent", "olium/0.1 (+https://vigolium.com)")
	if headers, ok := args["headers"].(map[string]any); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	maxBytes := int64(512_000)
	if v, ok := args["max_bytes"].(float64); ok && int64(v) > 0 {
		maxBytes = int64(v)
	}

	// Preserve the existing one-byte sentinel read, but capture the transport's
	// emitted request and decoded response before Close. No manual dump of an
	// intended request can certify its defaults, body, authority or redirect hop.
	chain, fetchErr := vhttp.DoCaptured(w.client, req, maxBytes+1)
	var x *evidence.Exchange
	if chain != nil {
		defer chain.Close()
		x = vhttp.CaptureEvidence(chain)
	}
	manifest, receiptErr := w.RetainHTTPReceipt(x, "http_client_message")
	details := map[string]any{"mode": "http", "receipt": manifest, "persisted": false,
		"response_body_limit_bytes": maxBytes + 1, "display_body_limit_bytes": maxBytes}
	defer func() {
		details["receipt"] = w.RefreshHTTPReceiptAvailability(manifest)
		// Details also serve the UI, but model history consumes Content. Keep the
		// legacy response view and append only a byte-free execution manifest.
		receiptJSON, _ := json.Marshal(details)
		result.Content += "\n\n[HTTP execution receipt]\n" + string(receiptJSON)
	}()
	if chain != nil {
		details["response_body_bytes_retained"] = len(chain.BodyBytes())
	}
	details["response_capture_state"] = manifest.ResponseState
	details["response_body_complete"] = manifest.ResponseState == evidence.StateComplete
	// Unknown/missing capture cannot certify whether any body was omitted.
	switch manifest.ResponseState {
	case evidence.StateComplete:
		details["response_body_omitted"] = false
	case evidence.StateTruncated:
		details["response_body_omitted"] = true
	}
	if receiptErr != nil {
		details["receipt_error"] = receiptErr.Error()
	}
	if fetchErr != nil {
		details["execution_error"] = fetchErr.Error()
		w.addHTTPPersistenceDetails(ctx, x, details)
		return Result{Content: fmt.Sprintf("request failed: %v", fetchErr), IsError: true, Details: details}, nil
	}
	if chain == nil || chain.Response() == nil {
		details["execution_error"] = "request completed without a captured response"
		w.addHTTPPersistenceDetails(ctx, x, details)
		return Result{Content: "request completed without a captured response", IsError: true, Details: details}, nil
	}
	resp := chain.Response()
	raw := chain.BodyBytes()
	truncated := int64(len(raw)) > maxBytes
	if truncated {
		raw = raw[:maxBytes]
	}
	var out strings.Builder
	fmt.Fprintf(&out, "HTTP/%d %s\n", resp.StatusCode, resp.Status)
	for k, vs := range resp.Header {
		fmt.Fprintf(&out, "%s: %s\n", k, strings.Join(vs, ", "))
	}
	out.WriteString("\n")
	out.Write(raw)
	if truncated {
		fmt.Fprintf(&out, "\n\n[truncated at %d bytes]", maxBytes)
	}

	details["status"] = resp.StatusCode
	details["content_type"] = resp.Header.Get("Content-Type")
	details["bytes"] = len(raw)
	details["truncated"] = truncated

	// The client follows redirects, so resp answers the LAST hop's request, not
	// req. The record pairs the response with the request that produced it.
	final := req
	if resp.Request != nil {
		final = resp.Request
	}
	if hops := redirectHops(resp); hops > 0 {
		details["redirect_chain"] = map[string]any{
			"hops":         hops,
			"original_url": req.URL.String(),
			"final_url":    final.URL.String(),
		}
		if x == nil || x.RequestState != evidence.StateComplete {
			details["body_omitted"] = "capture_unavailable"
		}
	}

	// Persist for downstream tools (query_records, inspect_record,
	// replay_request). Capture failures are non-fatal — the model still
	// gets the body even if persistence breaks — but they are reported, so
	// the model is never told a record exists that does not.
	w.addHTTPPersistenceDetails(ctx, x, details)

	return Result{
		Content: out.String(),
		Details: details,
	}, nil
}

// redirectHops counts the redirects the client followed to produce resp: each
// hop's request links to the response that redirected it.
func redirectHops(resp *http.Response) int {
	n := 0
	for r := resp.Request; r != nil && r.Response != nil; r = r.Response.Request {
		n++
	}
	return n
}

// Partial/missing receipts remain selectable in the execution store, but must
// not masquerade as complete HTTP records. A sink failure does not retry the
// completed request and is surfaced independently from execution success.
func (w *webFetchTool) addHTTPPersistenceDetails(ctx context.Context, x *evidence.Exchange, details map[string]any) {
	details["persisted"] = false
	if w.captureSink == nil || w.captureProject == "" {
		details["persistence_status"] = "disabled"
		return
	}
	id, err := w.persistHTTPFetch(ctx, x)
	if err != nil {
		details["persistence_status"] = "failed"
		if x == nil || x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete {
			details["persistence_status"] = "capture_unavailable"
		}
		details["persist_error"] = err.Error()
	} else {
		details["persisted"] = true
		details["persistence_status"] = "saved"
		details["record_uuid"] = id
	}
}

func (w *webFetchTool) persistHTTPFetch(ctx context.Context, x *evidence.Exchange) (string, error) {
	if x == nil || x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete {
		return "", fmt.Errorf("no complete captured HTTP exchange; partial receipt is execution-scoped only")
	}
	rr, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		return "", err
	}
	id, err := w.captureSink.SaveRecord(ctx, rr, "web-fetch", w.captureProject)
	if err == nil && id == "" {
		err = fmt.Errorf("capture sink returned no record UUID")
	}
	return id, err
}

// readinessDetails renders a probe's wait_selector outcome as tool-result
// details; empty when no selector was waited for.
func readinessDetails(res *spitolas.ProbeResult) map[string]any {
	if res.Readiness == "" {
		return nil
	}
	d := map[string]any{"readiness": res.Readiness}
	if res.ReadinessDetail != "" {
		d["readiness_detail"] = res.ReadinessDetail
	}
	return d
}

// captureDetails renders a capture receipt as tool-result details.
func captureDetails(rc spitolas.CaptureReceipt) map[string]any {
	d := map[string]any{
		"records_persisted": rc.Persisted,
		"records_failed":    rc.Lost(),
		"capture_complete":  rc.Enabled && rc.Clean(),
		"bodies_retained":   rc.BodiesRetained,
	}
	if rc.Err != "" {
		d["capture_error"] = rc.Err
	}
	return d
}

// captureSummary is the one-line capture account appended to a tool's text.
func captureSummary(rc spitolas.CaptureReceipt, source string) string {
	if !rc.Enabled {
		msg := "not running, nothing persisted"
		if rc.Err != "" {
			msg += " (" + rc.Err + ")"
		}
		return msg
	}
	msg := fmt.Sprintf("%d record(s) persisted under source='%s'", rc.Persisted, source)
	if lost := rc.Lost(); lost > 0 {
		msg += fmt.Sprintf(", %d lost", lost)
	}
	if !rc.Clean() {
		msg += " — capture incomplete"
	}
	if rc.Persisted > 0 {
		msg += "; use query_records to enumerate"
	}
	return msg
}

// executeBrowser drives spitolas (Chromium via CDP) for JS-rendered pages.
// Spitolas does what agent-browser used to: navigate, wait, grab the
// post-JS DOM. The big win over agent-browser is CDP-level network capture
// — every XHR/fetch the page issues during render is persisted, not just
// the final document. When the tool is wired with a capture sink, those
// requests land in query_records under source="web-fetch-browser" with no
// extra plumbing.
func (w *webFetchTool) executeBrowser(ctx context.Context, url string, args map[string]any) (Result, error) {
	maxBytes := int64(512_000)
	if v, ok := args["max_bytes"].(float64); ok && int64(v) > 0 {
		maxBytes = int64(v)
	}
	waitMS := 1500
	if v, ok := args["wait_ms"].(float64); ok && int(v) > 0 {
		waitMS = int(v)
	}
	waitSel, _ := args["wait_selector"].(string)

	cfg := spitolas.ProbeConfig{
		URL:          url,
		WaitSelector: waitSel,
		WaitExtra:    time.Duration(waitMS) * time.Millisecond,
		NavTimeout:   45 * time.Second,
		CollectHTML:  true,
	}
	// When wired, pump every XHR/fetch the browser issues straight into
	// the project DB. Source is distinct from browser_probe so the agent
	// can tell which tool surfaced the traffic.
	if w.captureSink != nil && w.captureProject != "" {
		cfg.CaptureSink = w.captureSink
		cfg.CaptureProjectUUID = w.captureProject
		cfg.CaptureSource = spitolas.CaptureSourceWebFetchBrowser
		// The records are promised to query_records/replay_request, which need
		// the response, not just the request line.
		cfg.CaptureBodies = true
	}

	probe := w.probe
	if probe == nil {
		probe = spitolas.ProbeURL
	}
	res, err := probe(ctx, cfg)
	if err != nil {
		// Render the partial result if spitolas got us a final URL despite
		// the error — useful when navigation fails late (e.g. JS errors).
		msg := fmt.Sprintf("browser fetch failed: %v", err)
		if res != nil && res.FinalURL != "" {
			msg += fmt.Sprintf(" (final_url=%s)", res.FinalURL)
		}
		return Result{Content: msg, IsError: true}, nil
	}

	html := res.HTML
	truncated := false
	if int64(len(html)) > maxBytes {
		html = html[:maxBytes] + fmt.Sprintf("\n\n[truncated at %d bytes]", maxBytes)
		truncated = true
	}

	var out strings.Builder
	fmt.Fprintf(&out, "URL: %s\nTitle: %s\n", res.FinalURL, res.Title)
	if res.ReadinessFailed {
		// The page was sampled without its readiness condition: say so before
		// the HTML, so it is not read as the fully rendered page.
		fmt.Fprintf(&out, "Readiness: %s — %s; the HTML below may be incomplete.\n", res.Readiness, res.ReadinessDetail)
	}
	out.WriteString("\n")
	out.WriteString(html)

	details := map[string]any{
		"mode":      "browser",
		"url":       res.FinalURL,
		"title":     res.Title,
		"bytes":     len(res.HTML),
		"truncated": truncated,
	}
	if len(res.Dialogs) > 0 {
		details["dialogs"] = len(res.Dialogs)
	}
	maps.Copy(details, readinessDetails(res))
	// CDP capture writes many records per page (one per XHR), so there is no
	// single record_uuid as in HTTP mode. What is reported comes from the
	// capture receipt — what the writer confirmed after it drained — never
	// from the fact that a sink was configured.
	if cfg.CaptureSink != nil {
		maps.Copy(details, captureDetails(res.Capture))
		fmt.Fprintf(&out, "\n\n[capture: %s]", captureSummary(res.Capture, spitolas.CaptureSourceWebFetchBrowser))
	}

	return Result{
		Content: out.String(),
		Details: details,
	}, nil
}
