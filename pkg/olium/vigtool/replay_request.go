package vigtool

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	gohttp "net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/replay"
	"golang.org/x/net/publicsuffix"
)

// replayRecordSource is the fallback for captures without an original record.
// Versioned replays preserve the original record's source and input lineage.
const replayRecordSource = "olium-replay"

const (
	// replayPerRunCap bounds total mutations the agent can fire in a single
	// autopilot session. High enough to actually test an attack surface,
	// low enough that a runaway loop doesn't hammer a target.
	replayPerRunCap = 200

	// replayPerRecordCap bounds mutations against a single record. Stops the
	// agent from re-firing 100 payloads at one endpoint when the response
	// pattern is already clear after a handful.
	replayPerRecordCap = 30

	// replayHTTPTimeout is the per-request wall-clock budget. Generous so a
	// slow target doesn't murder the loop, but bounded so a hung connection
	// doesn't either.
	replayHTTPTimeout = 25 * time.Second
)

// NewReplayRequestTool returns the replay_request tool — sends a mutated
// version of a stored HTTP record and reports a baseline-vs-replay diff so
// the agent can judge whether a payload triggered anything interesting.
func NewReplayRequestTool(ctx *SessionsContext) tool.Tool {
	return &replayRequestTool{ctx: ctx}
}

type replayRequestTool struct {
	tool.HTTPReceiptStore
	// doReplay is a test seam; production always uses the shared replay engine.
	doReplay  func(context.Context, replay.Options) (*replay.Result, error)
	ctx       *SessionsContext
	totalRun  atomic.Int64
	perRecMu  sync.Mutex
	perRecord map[string]int

	// Shared client + cookie jar across all replays in this autopilot run.
	// Cookies set by one response are visible to the next call so multi-step
	// auth flows (login → CSRF cookie → action) work without the model
	// manually threading them. Lazy-init under clientOnce so the cost is
	// only paid when replay_request actually fires.
	clientOnce sync.Once
	client     *gohttp.Client
}

func (*replayRequestTool) Name() string     { return "replay_request" }
func (*replayRequestTool) Label() string    { return "Replay HTTP request" }
func (*replayRequestTool) Category() string { return tool.CategoryVigolium }
func (*replayRequestTool) IsReadOnly() bool { return false }
func (*replayRequestTool) Description() string {
	return "Take a stored HTTP record, mutate one or more insertion points with custom payloads, " +
		"send the result, and return a baseline-vs-replay diff (status, length, content-hash, " +
		"payload reflection, response-time delta). Use this to confirm attacks suggested by " +
		"inspect_record — pull payloads from attack_kit or compose your own. Optionally pass an " +
		"auth_session name to fold in cookies/headers from list_auth_sessions. Cookies set by one " +
		"replay persist to the next (multi-step auth flows work). Honours HTTP_PROXY / HTTPS_PROXY " +
		"env vars so the operator can route replays through Burp. A complete captured sent exchange " +
		"is saved as an immutable record version preserving input lineage; its UUID is returned as " +
		"'replay_record_uuid'. Check persisted/persistence_status before linking it via report_finding " +
		"record_uuids. Partial/missing captures are reported honestly through execution receipt refs; " +
		"mutated_request is an intended preview, not proof of bytes sent. " +
		"Capped at 30 calls per record and 200 per run to prevent runaway loops."
}

func (*replayRequestTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"record_uuid": map[string]any{
				"type":        "string",
				"description": "UUID of the record to base the replay on (from query_records / inspect_record). A unique prefix works too - the first 8 characters are enough.",
			},
			"mutations": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name": map[string]any{
							"type":        "string",
							"description": "Insertion-point name (parameter or header name). Match against inspect_record output.",
						},
						"type": map[string]any{
							"type":        "string",
							"description": "Optional insertion-point type to disambiguate (e.g. 'URL_PARAM', 'HEADER', 'JSON_PARAM'). Useful when the same name appears in multiple positions.",
						},
						"payload": map[string]any{
							"type":        "string",
							"description": "Payload to inject. Required.",
						},
					},
					"required": []string{"name", "payload"},
				},
				"description": "Insertion-point mutations to apply. Mutually exclusive with raw_request.",
			},
			"raw_request": map[string]any{
				"type":        "string",
				"description": "Optional fully-formed raw HTTP request supplied to the replay engine. Mutually exclusive with mutations. Overlays, transport defaults and redirects may change the actual sent request; select its execution receipt for evidence, not this intended input.",
			},
			"auth_session": map[string]any{
				"type":        "string",
				"description": "Optional auth session name (from list_auth_sessions). When set, headers from that session are merged into the replay request, overriding the originals.",
			},
			"extra_headers": map[string]any{
				"type":        "object",
				"description": "Extra request headers to add/override (object of string→string).",
			},
			"no_redirects": map[string]any{
				"type":        "boolean",
				"description": "If true, do not follow redirects. Default false.",
			},
		},
		"required": []string{"record_uuid"},
	}
}

func (r *replayRequestTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if res, ok := requireRepo(r.ctx.repo(), "replay_request"); !ok {
		return res, nil
	}

	if cur := r.totalRun.Load(); cur >= replayPerRunCap {
		return tool.Result{
			Content: fmt.Sprintf(
				"replay_request rate-limited: %d replays this run (cap=%d). "+
					"If you still need to validate, halt and resume with a fresh run.",
				cur, replayPerRunCap),
			IsError: true,
		}, nil
	}

	uuid := argsString(args, "record_uuid")
	if uuid == "" {
		return tool.Result{Content: "replay_request: 'record_uuid' is required", IsError: true}, nil
	}

	rec, err := resolveRecordInProject(ctx, r.ctx.Repo, uuid, r.ctx.ProjectUUID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// An ambiguous prefix names its candidates; surface that verbatim.
		return tool.Result{Content: "replay_request: " + err.Error(), IsError: true}, nil
	}
	if errors.Is(err, sql.ErrNoRows) || rec == nil {
		return tool.Result{
			Content: fmt.Sprintf("replay_request: no record with uuid %q. Use query_records to discover valid UUIDs first — don't guess.", uuid),
			IsError: true,
		}, nil
	}
	if err != nil {
		return tool.Result{Content: fmt.Sprintf("replay_request: %v", err), IsError: true}, nil
	}
	if rec.ProjectUUID != effectiveRecordProjectUUID(r.ctx.ProjectUUID) {
		return tool.Result{
			Content: fmt.Sprintf("replay_request: record %q does not belong to the current project", uuid),
			IsError: true,
		}, nil
	}

	if cur := r.perRecordCount(uuid); cur >= replayPerRecordCap {
		return tool.Result{
			Content: fmt.Sprintf("replay_request: %d replays already against record %s (cap=%d). "+
				"Pick a different record or vary the payload class.", cur, uuid, replayPerRecordCap),
			IsError: true,
		}, nil
	}

	mutations, mutErr := parseMutations(args["mutations"])
	if mutErr != nil {
		return tool.Result{Content: "replay_request: " + mutErr.Error(), IsError: true}, nil
	}
	rawOverride := argsString(args, "raw_request")
	if rawOverride == "" && len(mutations) == 0 {
		return tool.Result{
			Content: "replay_request: provide either 'mutations' or 'raw_request'",
			IsError: true,
		}, nil
	}
	if rawOverride != "" && len(mutations) > 0 {
		return tool.Result{
			Content: "replay_request: 'mutations' and 'raw_request' are mutually exclusive",
			IsError: true,
		}, nil
	}

	overlay := map[string]string{}
	if name := argsString(args, "auth_session"); name != "" {
		hdrs, err := r.lookupAuthHeaders(ctx, rec.Hostname, name)
		if err != nil {
			return tool.Result{Content: fmt.Sprintf("replay_request: auth_session %q: %v", name, err), IsError: true}, nil
		}
		for k, v := range hdrs {
			overlay[k] = v
		}
	}
	if extra, ok := args["extra_headers"].(map[string]any); ok {
		for k, v := range extra {
			if s, ok := v.(string); ok {
				overlay[k] = s
			}
		}
	}

	opts := replay.Options{
		BaselineRequest: rec.RawRequest,
		// The tool's output always carries a diff, so a record stored without
		// a response is re-sent as the baseline.
		SendBaseline:         true,
		BaselineResponse:     rec.RawResponse,
		BaselineStatus:       rec.StatusCode,
		BaselineResponseTime: rec.ResponseTimeMs,
		Mutations:            mutations,
		Scheme:               rec.Scheme,
		Hostname:             rec.Hostname,
		Port:                 rec.Port,
		HeaderOverlay:        overlay,
		NoRedirects:          argsBool(args, "no_redirects"),
		Client:               r.getClient(),
		CaptureExchange:      true,
	}
	if rawOverride != "" {
		opts.RawRequest = []byte(rawOverride)
	}

	r.incPerRecord(uuid)
	r.totalRun.Add(1)

	doReplay := r.doReplay
	if doReplay == nil {
		doReplay = replay.Do
	}
	result, executionErr := doReplay(ctx, opts)
	var captured, baselineCapture *evidence.Exchange
	if result != nil {
		if result.Replay != nil {
			captured = result.Replay.Exchange
			if result.Replay.Error != "" {
				executionErr = errors.Join(executionErr, errors.New(result.Replay.Error))
			}
		}
		if result.Baseline != nil {
			baselineCapture = result.Baseline.Exchange
		}
	}
	// Retain any partial receipt returned with an error; absence stays missing.
	// Never use RawMutatedRequest or summary renderings as sent evidence.
	receipt, receiptErr := r.RetainHTTPReceipt(captured, "http_client_message")
	baselineReceipt, baselineErr := r.RetainHTTPReceipt(baselineCapture, "http_client_message")
	replayRecordUUID, persistErr := r.persistReplayExchange(ctx, rec.UUID, result)
	persistenceStatus := "saved"
	if persistErr != nil {
		persistenceStatus = "failed"
		if captured == nil || captured.RequestState != evidence.StateComplete || captured.ResponseState != evidence.StateComplete {
			persistenceStatus = "capture_unavailable"
		}
	}
	receipt = r.RefreshHTTPReceiptAvailability(receipt)
	baselineReceipt = r.RefreshHTTPReceiptAvailability(baselineReceipt)
	out := struct {
		RecordUUID         string                   `json:"record_uuid"`
		ReplayRecordUUID   string                   `json:"replay_record_uuid,omitempty"`
		Receipt            tool.HTTPReceiptManifest `json:"receipt"`
		BaselineReceipt    tool.HTTPReceiptManifest `json:"baseline_receipt"`
		Persisted          bool                     `json:"persisted"`
		PersistenceStatus  string                   `json:"persistence_status"`
		PersistError       string                   `json:"persist_error,omitempty"`
		ExecutionError     string                   `json:"execution_error,omitempty"`
		ReceiptError       string                   `json:"receipt_error,omitempty"`
		MutatedRequestKind string                   `json:"mutated_request_kind"`
		*replay.Result
	}{RecordUUID: rec.UUID, ReplayRecordUUID: replayRecordUUID, Receipt: receipt, BaselineReceipt: baselineReceipt,
		Persisted: persistErr == nil && replayRecordUUID != "", PersistenceStatus: persistenceStatus,
		MutatedRequestKind: "intended", Result: result}
	if persistErr != nil {
		out.PersistError = persistErr.Error()
	}
	if executionErr != nil {
		out.ExecutionError = executionErr.Error()
	}
	if err := errors.Join(receiptErr, baselineErr); err != nil {
		out.ReceiptError = err.Error()
	}
	body, _ := json.Marshal(out)
	details := map[string]any{"record_uuid": rec.UUID, "receipt": receipt, "baseline_receipt": baselineReceipt,
		"persisted": out.Persisted, "persistence_status": persistenceStatus, "mutated_request_kind": "intended"}
	if replayRecordUUID != "" {
		details["replay_record_uuid"] = replayRecordUUID
	}
	if persistErr != nil {
		details["persist_error"] = out.PersistError
	}
	if executionErr != nil {
		details["execution_error"] = out.ExecutionError
	}
	if out.ReceiptError != "" {
		details["receipt_error"] = out.ReceiptError
	}
	if result != nil {
		if result.Replay != nil {
			details["status"] = result.Replay.Status
		}
		if result.Diff != nil {
			details["length_delta"] = result.Diff.LengthDelta
			details["content_changed"] = result.Diff.ContentChanged
			if len(result.Diff.ReflectsPayload) > 0 {
				details["reflects_payload"] = true
			}
		}
		if result.AdditionalGroups > 0 {
			details["additional_payload_groups"] = result.AdditionalGroups
		}
	}
	return tool.Result{Content: string(body), Details: details, IsError: executionErr != nil}, nil
}

// perRecordCount reads the current attempt count for uuid without
// incrementing — used by the cap check so we don't mutate state on the
// rejection path.
func (r *replayRequestTool) perRecordCount(uuid string) int {
	r.perRecMu.Lock()
	defer r.perRecMu.Unlock()
	return r.perRecord[uuid]
}

func (r *replayRequestTool) incPerRecord(uuid string) {
	r.perRecMu.Lock()
	defer r.perRecMu.Unlock()
	if r.perRecord == nil {
		r.perRecord = map[string]int{}
	}
	r.perRecord[uuid]++
}

// persistReplayExchange uses only the owned sent capture. SaveRecordVersion
// preserves the original input lineage/project/source without rewriting any
// historical exchange or finding link. Even on an execution error a complete
// receipt can be saved; partial receipts remain selectable, not fake records.
func (r *replayRequestTool) persistReplayExchange(ctx context.Context, previousUUID string, result *replay.Result) (string, error) {
	repo := r.ctx.repo()
	if repo == nil {
		return "", fmt.Errorf("replay persistence unavailable: no repository")
	}
	if result == nil || result.Replay == nil || result.Replay.Exchange == nil {
		return "", fmt.Errorf("replay persistence unavailable: no captured exchange")
	}
	x := result.Replay.Exchange
	if x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete {
		return "", fmt.Errorf("replay persistence unavailable: capture is incomplete; receipt is execution-scoped only")
	}
	rr, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		return "", err
	}
	rr = rr.WithResponse(httpmsg.NewHttpResponseWithDuration(rr.Response().Raw(), time.Duration(result.Replay.ResponseTimeMs)*time.Millisecond)).WithEvidence(x)
	if previousUUID != "" {
		return repo.SaveRecordVersion(ctx, previousUUID, rr)
	}
	return repo.SaveRecord(ctx, rr, replayRecordSource, r.ctx.ProjectUUID)
}

func (r *replayRequestTool) lookupAuthHeaders(ctx context.Context, hostname, name string) (map[string]string, error) {
	rows, err := r.ctx.Repo.GetAuthenticationHostnamesByHostname(ctx, r.ctx.ProjectUUID, hostname)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.SessionName == name {
			return row.Headers, nil
		}
	}
	return nil, fmt.Errorf("no auth session %q for hostname %s", name, hostname)
}

// parseMutations decodes the args["mutations"] payload, accepting both
// concrete []replay.Mutation shapes and the more common JSON-decoded
// []any-of-map.
func parseMutations(raw any) ([]replay.Mutation, error) {
	if raw == nil {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("'mutations' must be an array")
	}
	out := make([]replay.Mutation, 0, len(arr))
	for i, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("'mutations[%d]' must be an object", i)
		}
		name, _ := obj["name"].(string)
		payload, _ := obj["payload"].(string)
		typ, _ := obj["type"].(string)
		if strings.TrimSpace(name) == "" || payload == "" {
			return nil, fmt.Errorf("'mutations[%d]': name and payload are required", i)
		}
		out = append(out, replay.Mutation{Name: name, Type: typ, Payload: payload})
	}
	return out, nil
}

// getClient returns the shared http.Client for this tool, lazy-initializing
// on first call. The client carries a per-run cookie jar so cookies set by
// one replay are visible to the next (multi-step auth flows: login → CSRF
// → action). The transport honours HTTP_PROXY / HTTPS_PROXY so an operator
// can pipe replays through Burp by exporting the env var before launching
// the autopilot.
func (r *replayRequestTool) getClient() *gohttp.Client {
	r.clientOnce.Do(func() {
		jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		r.client = replay.NewDefaultClient(jar, replayHTTPTimeout)
	})
	return r.client
}
