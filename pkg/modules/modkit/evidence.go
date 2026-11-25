package modkit

import (
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// MaxEvidencePairs caps how many request/response pairs a single finding carries
// in AdditionalEvidence at emit time, so a high-round differential module
// (boolean-blind SQLi, race interference) can't emit an unbounded finding. The
// first MaxEvidencePairs pairs win — modules record the most informative context
// first (baseline, then confirmation rounds), so the tail that gets dropped is the
// least interesting.
//
// This is the single source of truth for the evidence-pair cap: the storage layer
// pins its own cap (database.maxAdditionalEvidence) to this value, so a finding's
// emitted evidence is retained in full through conversion and dedup-merge instead
// of being silently truncated to a smaller storage limit.
const MaxEvidencePairs = 10

// EvidenceCollector accumulates bounded context around a selected primary attack:
// the known baseline, negative controls, and confirmation/refetch rounds. Use
// SetPrimaryEvidence for the primary receipt and AddExchange for context receipts,
// captured BEFORE their response chain closes. Assign Entries to AdditionalEvidence
// and Evidence to ResultEvent.Evidence before selecting the primary.
//
// Legacy Add preserves text and an unknown-role supplied entry. Its arbitrary
// label cannot establish a role or
// transport fidelity. AddSupplied is an additive migration API when the producer
// knows an argument's role but only has strings: these are producer-supplied bytes,
// not captured traffic. Neither API proves the vulnerability or changes grading.
// Active results that ONLY analyze their input may instead set BaselineEvidence;
// do not opt probe-based results into baseline inheritance to repair missing proof.
//
// The zero value is ready to use. All methods are nil-safe. Collectors are local
// to a scan call, not concurrent or whole-traffic stores.
type EvidenceCollector struct {
	entries  []string
	selected []evidence.Entry
}

// NewEvidenceCollector returns a ready-to-use collector. Equivalent to
// &EvidenceCollector{}; provided for call-site readability.
func NewEvidenceCollector() *EvidenceCollector {
	return &EvidenceCollector{}
}

// Add records one legacy labeled request/response pair. The label (e.g.
// "baseline", "attack", "confirm round 2") is only a presentation marker, never
// a role inferred into Evidence. Empty pairs are ignored, and
// additions past MaxEvidencePairs are dropped. Safe to call on a nil collector
// (no-op), so reconfirm and other shared helpers can record unconditionally.
func (c *EvidenceCollector) Add(label, request, response string) {
	if c == nil || len(c.entries) >= MaxEvidencePairs {
		return
	}
	c.AddSupplied(evidence.RoleUnknown, label, request, response)
}

// AddSupplied records context with an explicit producer-known role, keeping the
// legacy text rendering too. Use only when argument semantics identify the role;
// never derive it from a label or URL. Missing halves stay missing, and fidelity
// remains producer_supplied even if a caller describes the bytes as "captured".
func (c *EvidenceCollector) AddSupplied(role evidence.Role, label, request, response string) {
	if c == nil || len(c.entries) >= MaxEvidencePairs || !evidence.ValidRole(role) || request == "" && response == "" {
		return
	}
	c.AddExchange(evidence.NewExchange("", "", []byte(request), []byte(response), evidence.ProvenanceSupplied), role, label)
}

// AddExchange retains an owned copy of an already-captured context receipt and
// its explicit role. It preserves identity, provenance and missing/truncated
// states; it never recaptures or upgrades a legacy exchange. Nil/invalid receipts
// and additions beyond the shared context cap are ignored.
func (c *EvidenceCollector) AddExchange(exchange *evidence.Exchange, role evidence.Role, label string) {
	if c == nil || len(c.entries) >= MaxEvidencePairs || exchange == nil || !evidence.ValidRole(role) || exchange.Validate() != nil {
		return
	}
	entry := output.BuildEvidence(label, string(exchange.Request), string(exchange.Response))
	if entry == "" {
		return
	}
	c.entries = append(c.entries, entry)
	c.selected = append(c.selected, evidence.Select(exchange, role, false, label))
}

// AddBaseline records producer-known input/comparison context, not primary proof.
func (c *EvidenceCollector) AddBaseline(label, request, response string) {
	c.AddSupplied(evidence.RoleBaseline, label, request, response)
}

// AddControl records a producer-known negative/benign comparison request.
func (c *EvidenceCollector) AddControl(label, request, response string) {
	c.AddSupplied(evidence.RoleControl, label, request, response)
}

// AddAttack records a producer-known supporting mutation; it is not primary.
func (c *EvidenceCollector) AddAttack(label, request, response string) {
	c.AddSupplied(evidence.RoleAttack, label, request, response)
}

// AddConfirmation records a producer-known reproduction/refetch round.
func (c *EvidenceCollector) AddConfirmation(label, request, response string) {
	c.AddSupplied(evidence.RoleConfirmation, label, request, response)
}

// Evidence returns deeply owned role-aware context entries for ResultEvent.Evidence.
// Legacy Add calls retain unknown roles: informal labels are not role metadata.
func (c *EvidenceCollector) Evidence() []evidence.Entry {
	if c == nil {
		return nil
	}
	return evidence.CloneEntries(c.selected)
}

// ForResult adds a legacy primary pair to the collected context without claiming
// it is transport-captured or assigning it an attack role. Use when migrating
// context semantics in a producer that still lacks a primary receipt. Both empty
// primary fields yield context only; missing halves remain missing. This prevents
// typed context from accidentally hiding a still-legacy primary pair.
func (c *EvidenceCollector) ForResult(request, response string) []evidence.Entry {
	entries := c.Evidence()
	if request == "" && response == "" {
		return entries
	}
	x := evidence.NewExchange("", "", []byte(request), []byte(response), evidence.ProvenanceSupplied)
	return append([]evidence.Entry{evidence.Select(x, evidence.RoleUnknown, true, "Producer-supplied primary")}, entries...)
}

// SetPrimaryEvidence selects the explicit primary attack, confirmation, or
// observation receipt, mirroring its bytes to legacy Request/Response fields.
// It takes ownership by copying, not by retaining a response chain. Context must
// be assigned first (e.g. result.Evidence = collector.Evidence()). Selection does
// not mean complete capture or confirmed exploitability. Missing message halves
// remain missing, and no baseline fallback is requested. Returns false for a nil
// result/receipt, invalid receipt, or a role that can only be context.
func SetPrimaryEvidence(result *output.ResultEvent, exchange *evidence.Exchange, role evidence.Role, label string) bool {
	if result == nil || exchange == nil || exchange.Validate() != nil {
		return false
	}
	switch role {
	case evidence.RoleAttack, evidence.RoleConfirmation, evidence.RoleObservation:
	default:
		return false
	}
	for i := range result.Evidence {
		result.Evidence[i].Primary = false
	}
	result.Evidence = append([]evidence.Entry{evidence.Select(exchange, role, true, label)}, result.Evidence...)
	result.Request, result.Response = string(exchange.Request), string(exchange.Response)
	result.EvidenceStatus = "selected"
	if exchange.RequestState == evidence.StateMissing || exchange.ResponseState == evidence.StateMissing {
		result.EvidenceStatus = "missing"
	}
	return true
}

// Entries returns a copy of the collected evidence entries for assignment to a
// ResultEvent's AdditionalEvidence. Returns nil (not an empty slice) when nothing
// was collected, so a finding without extra context stays unset. Safe on a nil
// collector.
func (c *EvidenceCollector) Entries() []string {
	if c == nil || len(c.entries) == 0 {
		return nil
	}
	out := make([]string, len(c.entries))
	copy(out, c.entries)
	return out
}

// Len reports how many pairs have been collected so far. Safe on a nil collector.
func (c *EvidenceCollector) Len() int {
	if c == nil {
		return 0
	}
	return len(c.entries)
}

// CtxRequestRaw renders ctx's request as a raw string for evidence capture,
// returning "" when the request is absent. Pair with CtxResponseRaw to record the
// original (clean) request/response a module compared its probe against.
func CtxRequestRaw(ctx *httpmsg.HttpRequestResponse) string {
	if ctx == nil || ctx.Request() == nil {
		return ""
	}
	return string(ctx.Request().Raw())
}

// CtxResponseRaw renders ctx's response as a full raw response string for evidence
// capture, returning "" when no response is present.
func CtxResponseRaw(ctx *httpmsg.HttpRequestResponse) string {
	if ctx == nil || ctx.Response() == nil {
		return ""
	}
	return string(ctx.Response().Raw())
}
