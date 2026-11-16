// Package evidence describes selected HTTP exchanges independently of crawl
// deduplication and of a finding's confidence. Raw bytes are authoritative;
// textual renderings and URLs are never used to infer a proof role.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RoleUnknown      Role = "unknown"
	RoleBaseline     Role = "baseline"
	RoleObservation  Role = "observation"
	RoleAttack       Role = "attack"
	RoleControl      Role = "control"
	RoleConfirmation Role = "confirmation"
)

type State string

const (
	StateUnknown   State = "unknown"
	StateComplete  State = "complete"
	StateMissing   State = "missing"
	StateTruncated State = "truncated"
)

type Provenance string

const (
	ProvenanceCaptured Provenance = "captured"
	ProvenanceSupplied Provenance = "producer_supplied"
	ProvenanceLegacy   Provenance = "legacy_unknown"
	// Cached identifies a normalized observation, not another sent execution.
	ProvenanceCached Provenance = "cached_observation"
)

// Exchange is an owned receipt. ID identifies this execution, not an endpoint
// or a request hash. ContentHash includes service, both messages and absence
// states; reusing an ID for changed content must be rejected by storage.
// Complete means complete at the capture boundary, not a claim of wire-exact
// TLS/HTTP2 framing or that the server evaluated a vulnerability.
type Exchange struct {
	ID            string     `json:"id"`
	URL           string     `json:"url,omitempty"`
	Service       string     `json:"service,omitempty"`
	Request       []byte     `json:"request,omitempty"`
	Response      []byte     `json:"response,omitempty"`
	RequestState  State      `json:"request_state"`
	ResponseState State      `json:"response_state"`
	Provenance    Provenance `json:"provenance"`
	ContentHash   string     `json:"content_hash"`
	CapturedAt    time.Time  `json:"captured_at"`
}

// Entry associates a selected exchange with one occurrence of a finding. The
// role belongs to this association: the same receipt may be context for one
// assertion and an observation for another. Exchange is omitted in manifests
// and hydrated only when requested; ExchangeID remains available after expiry.
type Entry struct {
	ExchangeID   string    `json:"exchange_id"`
	Role         Role      `json:"role"`
	Primary      bool      `json:"primary,omitempty"`
	Label        string    `json:"label,omitempty"`
	OccurrenceID string    `json:"occurrence_id,omitempty"`
	FindingURL   string    `json:"finding_url,omitempty"`
	ScanUUID     string    `json:"scan_uuid,omitempty"`
	Exchange     *Exchange `json:"exchange,omitempty"`
}

func NewExchange(service, url string, request, response []byte, provenance Provenance) *Exchange {
	x := &Exchange{ID: uuid.NewString(), Service: service, URL: url,
		Request: bytes.Clone(request), Response: bytes.Clone(response),
		RequestState: StateComplete, ResponseState: StateComplete,
		Provenance: provenance, CapturedAt: time.Now().UTC()}
	if len(request) == 0 {
		x.RequestState = StateMissing
	}
	if len(response) == 0 {
		x.ResponseState = StateMissing
	}
	x.ContentHash = x.Hash()
	return x
}

func (x *Exchange) Hash() string {
	h := sha256.New()
	for _, b := range [][]byte{[]byte(x.Service), []byte(x.URL), []byte(x.RequestState), []byte(x.ResponseState), []byte(x.Provenance), x.Request, x.Response} {
		_ = binary.Write(h, binary.BigEndian, uint64(len(b)))
		_, _ = h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (x *Exchange) Validate() error {
	if x == nil || x.ID == "" {
		return fmt.Errorf("evidence exchange has no identity")
	}
	if x.ContentHash != x.Hash() {
		return fmt.Errorf("evidence exchange %s changed after capture", x.ID)
	}
	for _, s := range []State{x.RequestState, x.ResponseState} {
		switch s {
		case StateUnknown, StateComplete, StateMissing, StateTruncated:
		default:
			return fmt.Errorf("invalid evidence capture state %q", s)
		}
	}
	if x.RequestState == StateMissing && len(x.Request) != 0 || x.ResponseState == StateMissing && len(x.Response) != 0 {
		return fmt.Errorf("missing evidence contains bytes")
	}
	if x.RequestState == StateComplete && len(x.Request) == 0 || x.ResponseState == StateComplete && len(x.Response) == 0 {
		return fmt.Errorf("complete evidence has no message bytes")
	}
	switch x.Provenance {
	case ProvenanceCaptured, ProvenanceSupplied, ProvenanceLegacy, ProvenanceCached:
	default:
		return fmt.Errorf("invalid evidence provenance %q", x.Provenance)
	}
	if x.CapturedAt.Year() < 0 || x.CapturedAt.Year() > 9999 {
		return fmt.Errorf("evidence capture time is not representable in JSON")
	}
	if x.CapturedAt.IsZero() && x.Provenance != ProvenanceLegacy {
		return fmt.Errorf("nonlegacy evidence has no capture time")
	}
	return nil
}

func (x *Exchange) Clone() *Exchange {
	if x == nil {
		return nil
	}
	copy := *x
	copy.Request, copy.Response = bytes.Clone(x.Request), bytes.Clone(x.Response)
	return &copy
}

func Select(x *Exchange, role Role, primary bool, label string) Entry {
	if x == nil {
		return Entry{Role: role, Primary: primary, Label: label}
	}
	return Entry{ExchangeID: x.ID, Role: role, Primary: primary, Label: label, Exchange: x.Clone()}
}

func (e Entry) Manifest() Entry { e.Exchange = nil; return e }

func CloneEntries(entries []Entry) []Entry {
	if entries == nil {
		return nil
	}
	out := make([]Entry, len(entries))
	for i, e := range entries {
		out[i] = e
		out[i].Exchange = e.Exchange.Clone()
	}
	return out
}

func ValidRole(role Role) bool {
	switch role {
	case RoleUnknown, RoleBaseline, RoleObservation, RoleAttack, RoleControl, RoleConfirmation:
		return true
	}
	return false
}

// HasSelectedEvidence describes selection, not the validity of an assertion.
func HasSelectedEvidence(entries []Entry) bool {
	for _, e := range entries {
		if e.Primary && (e.Role == RoleAttack || e.Role == RoleConfirmation || e.Role == RoleObservation) && e.ExchangeID != "" {
			return true
		}
	}
	return false
}
