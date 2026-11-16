// Package replay implements HTTP replay-with-mutation: take a baseline
// request, apply insertion-point mutations or a raw-request override,
// send the result, and return a baseline-vs-replay diff.
package replay

import (
	"context"
	gohttp "net/http"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// DefaultExcerptCap clips response/request excerpts emitted in JSON. The
// hash and full length are reported alongside so callers can detect
// when they're looking at a truncated view.
const DefaultExcerptCap = 4 * 1024

// Mutation is one insertion-point payload override. Type is optional
// and only used to disambiguate when the same name exists in multiple
// positions (e.g. URL_PARAM + HEADER + JSON_PARAM).
type Mutation struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Payload string `json:"payload"`
}

// Options describes one replay. Network policy (cookie jar, proxy,
// timeout, TLS, redirect behaviour) is the caller's responsibility —
// the engine doesn't construct clients.
type Options struct {
	// BaselineRequest is the original raw HTTP request that mutations
	// are applied to and that the diff is computed against. Required.
	BaselineRequest []byte

	// SendBaseline sends BaselineRequest as a baseline even when it is the
	// very request being replayed. Without it such a replay (a supplied
	// request, no mutations, no stored response) is sent once and the result
	// carries no baseline and no diff: sending the same request twice doubled
	// every POST for a diff of a request against itself.
	SendBaseline bool

	// BaselineResponse is the original raw HTTP response, used to
	// compute the baseline summary. When empty and BaselineRequest is
	// set, Do() synthesizes a baseline by sending the un-mutated
	// request first.
	BaselineResponse []byte

	// BaselineStatus / BaselineResponseTime are used when
	// BaselineResponse is non-empty so we can mirror the stored
	// record's status code and timing rather than re-deriving them.
	BaselineStatus       int
	BaselineResponseTime int64

	// Either Mutations or RawRequest must be set. Mutations applies
	// named insertion-point overrides; RawRequest replaces the baseline
	// request bytes verbatim.
	Mutations  []Mutation
	RawRequest []byte

	// Destination — used to reconstruct the URL we POST to. Hostname
	// is required when sending; Port=0 lets the scheme default decide.
	Scheme   string
	Hostname string
	Port     int

	// HeaderOverlay rewrites the header block of the request after
	// mutation. Case-insensitive replacement; appends if not present.
	HeaderOverlay map[string]string

	NoRedirects bool

	// CaptureExchange retains an owned receipt for immutable record versioning.
	// Ordinary diff/fuzz calls do not pay for full request/response copies.
	CaptureExchange bool

	// Client is required unless Sender is set.
	Client *gohttp.Client

	// Sender, when non-nil, replaces the built-in net/http send for both the
	// baseline (when re-sent) and the mutated request. It receives the fully
	// assembled request bytes and returns the same *Summary a Go-client send
	// would. Used to route the exact bytes through an external engine (the Burp
	// bridge) that preserves malformed requests instead of normalising them.
	// When set, Client is not required.
	Sender func(context.Context, []byte) *Summary

	// ExcerptCap overrides the excerpt clip size. Zero = DefaultExcerptCap.
	ExcerptCap int

	// BaselineIsEvidence marks a baseline that is a finding's own evidence
	// (replay --finding-id): an identical answer means the finding
	// reproduced, not that a payload failed to take effect.
	BaselineIsEvidence bool
}

// Summary describes the response side of a single HTTP exchange.
//
// RawBody holds the retained response bytes, which may be a prefix on read
// errors or at the engine's limit. Error and Exchange states describe execution
// and capture completeness; Truncated describes only excerpt clipping.
// json:"-" keeps potentially megabyte bodies out of agent-facing payloads.
type Summary struct {
	Status         int           `json:"status"`
	ResponseLen    int           `json:"response_length"`
	ContentHash    string        `json:"content_hash,omitempty"`
	ResponseTimeMs int64         `json:"response_time_ms"`
	Headers        gohttp.Header `json:"headers,omitempty"`
	Excerpt        string        `json:"excerpt,omitempty"`
	Truncated      bool          `json:"excerpt_truncated,omitempty"`
	Error          string        `json:"error,omitempty"`
	// FinalURL is the URL that answered, after any redirects were followed;
	// Redirects counts the hops (absent when the request was answered
	// directly).
	FinalURL  string `json:"final_url,omitempty"`
	Redirects int    `json:"redirects,omitempty"`
	RawBody   []byte `json:"-"`
	// Exchange owns the final available capture, including on execution errors.
	// Request-only and partial-response receipts retain their explicit states;
	// absence means no capture, not permission to pair intended bytes.
	Exchange *evidence.Exchange `json:"-"`
	// Native absolute-form normalization is explicit and is not exact proof
	// reproduction. External Senders must describe their own representation.
	RequestTargetPolicy *httpmsg.RequestTargetPolicy `json:"request_target_policy,omitempty"`
}

// Diff captures the comparison between baseline and replay.
type Diff struct {
	StatusChanged   bool     `json:"status_changed"`
	LengthDelta     int      `json:"length_delta"`
	ContentChanged  bool     `json:"content_changed"`
	ReflectsPayload []string `json:"reflects_payload,omitempty"`
	BaselineStatus  int      `json:"baseline_status"`
	BaselineLen     int      `json:"baseline_length"`
	BaselineHash    string   `json:"baseline_content_hash,omitempty"`
	Interpretation  string   `json:"interpretation,omitempty"`
}

// Result is the complete output of a single replay.
//
// AdditionalGroups is non-zero when BuildRequestWithPayloads returned
// multiple non-conflicting mutation groups and we only sent the first.
// Unmatched lists insertion-point names that didn't resolve.
type Result struct {
	MutatedRequest      string `json:"mutated_request"`
	MutatedRequestTrunc bool   `json:"mutated_request_truncated,omitempty"`
	// Baseline and Diff are nil when the replayed request was its own
	// baseline and was sent once (see Options.SendBaseline).
	Baseline         *Summary `json:"baseline"`
	Replay           *Summary `json:"replay"`
	Diff             *Diff    `json:"diff"`
	AdditionalGroups int      `json:"additional_payload_groups,omitempty"`
	Unmatched        []string `json:"unmatched_mutations,omitempty"`
	// RawMutatedRequest is the complete intended request supplied to the sender.
	// Native transport defaults/redirects may change it; Replay.Exchange, when
	// available, owns the final sent request. Retained for integrations such as
	// Burp staging, but omitted from JSON's bounded MutatedRequest preview.
	RawMutatedRequest []byte `json:"-"`
}
