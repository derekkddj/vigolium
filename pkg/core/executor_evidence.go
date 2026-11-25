package core

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// suppliedInputSnapshot owns input bytes before analysis changes them. This is
// supplied traffic, not a claim that this executor sent it or recovered history.
func suppliedInputSnapshot(item *httpmsg.HttpRequestResponse) *httpmsg.HttpRequestResponse {
	if item == nil || item.Request() == nil || item.HasEvidence() {
		return item
	}
	var response []byte
	if item.HasResponse() {
		response = item.Response().Raw()
	}
	x := evidence.NewExchange(evidenceService(item), item.Target(), item.Request().Raw(), response, evidence.ProvenanceSupplied)
	return item.WithEvidence(x)
}

// prepareResultEvidence separates input context from selected evidence. Only
// passive/positively declared input analysis can select an input projection.
func (e *Executor) prepareResultEvidence(result *output.ResultEvent, item *httpmsg.HttpRequestResponse, passive bool) (*httpmsg.HttpRequest, *httpmsg.HttpResponse) {
	item = suppliedInputSnapshot(item)
	var baselineReq *httpmsg.HttpRequest
	var baselineResp *httpmsg.HttpResponse
	baseline := item.Evidence()
	hasPrimary := false
	for _, entry := range result.Evidence {
		if entry.Primary && entry.Role != evidence.RoleBaseline {
			hasPrimary = true
			break
		}
	}
	// Supporting controls must not block positively authorized input analysis.
	// An existing primary, even unavailable/invalid, still forbids fallback.
	if !hasPrimary && baseline != nil && (passive || result.BaselineEvidence) && matchesInputProjection(result, item, baseline) {
		result.Evidence = append(result.Evidence, evidence.Select(baseline, evidence.RoleObservation, true, "Input analysis"))
		result.Request, result.Response = string(baseline.Request), string(baseline.Response)
		baselineReq, baselineResp = item.Request(), item.Response()
	}
	e.normalizeLegacyEvidence(result)
	if baseline != nil {
		present := false
		for _, entry := range result.Evidence {
			if entry.ExchangeID == baseline.ID && (entry.Role == evidence.RoleBaseline || entry.Role == evidence.RoleObservation) {
				present = true
				break
			}
		}
		if !present {
			result.Evidence = append(result.Evidence, evidence.Select(baseline, evidence.RoleBaseline, false, "Scan input / context"))
		}
	}
	e.finalizeEvidence(result)
	return baselineReq, baselineResp
}

// Comparing to the analysis projection is permitted only by the positive input
// analysis contract. An active probe never gains this permission by URL/hash.
func matchesInputProjection(result *output.ResultEvent, item *httpmsg.HttpRequestResponse, x *evidence.Exchange) bool {
	requestMatches := result.Request == "" || bytes.Equal([]byte(result.Request), x.Request) || bytes.Equal([]byte(result.Request), item.Request().Raw())
	responseMatches := result.Response == "" || bytes.Equal([]byte(result.Response), x.Response) || item.HasResponse() && bytes.Equal([]byte(result.Response), item.Response().Raw())
	return requestMatches && responseMatches
}

// Mixed and post-hook legacy messages remain available with unknown roles. A
// typed selection of the exact pair already represents it; don't duplicate the
// compatibility text projection or infer a role from an informal label.
func (e *Executor) normalizeLegacyEvidence(result *output.ResultEvent) {
	add := func(request, response, label string, primary bool) {
		if request == "" && response == "" {
			return
		}
		for _, entry := range result.Evidence {
			if entry.Exchange != nil && bytes.Equal(entry.Exchange.Request, []byte(request)) && bytes.Equal(entry.Exchange.Response, []byte(response)) && (primary || entry.Primary && proofRole(entry.Role) || entry.Label == label) {
				return
			}
		}
		service := legacyEvidenceService(request, result.URL)
		x := evidence.NewExchange(service, result.URL, []byte(request), []byte(response), evidence.ProvenanceSupplied)
		result.Evidence = append(result.Evidence, evidence.Select(x, evidence.RoleUnknown, primary, label))
	}
	typedPrimary := false
	for _, entry := range result.Evidence {
		if entry.Primary && proofRole(entry.Role) {
			typedPrimary = true
			break
		}
	}
	if typedPrimary {
		// An explicit declaration remains authoritative even if its receipt is
		// rejected or missing. Preserve unrelated inline text as context only;
		// never turn it into a replacement primary on a later normalization pass.
		add(result.Request, result.Response, "Unselected producer-supplied HTTP", false)
	} else {
		add(result.Request, result.Response, "Producer-supplied HTTP", true)
	}
	for _, raw := range result.AdditionalEvidence {
		p := output.ParseEvidence(raw)
		if p.IsPair() {
			add(p.Request, p.Response, p.Label, false)
		}
	}
}

func evidenceService(rr *httpmsg.HttpRequestResponse) string {
	if rr == nil || rr.Service() == nil {
		return ""
	}
	svc := rr.Service()
	return svc.Protocol() + "://" + net.JoinHostPort(svc.Host(), strconv.Itoa(svc.Port()))
}

// finalizeEvidence describes selection, not confirmation. Fidelity remains a
// separate property and an empty/unknown message never becomes a complete pair.
func (e *Executor) finalizeEvidence(result *output.ResultEvent) {
	result.Evidence = evidence.CloneEntries(result.Evidence)
	// Validate identity across the whole occurrence before any seal or primary
	// projection can collapse duplicates. Self-consistent public hashes do not
	// authorize two different captures under one execution ID.
	sealed := indexEvidenceCaptures(result.Evidence)
	for i := range result.Evidence {
		entry := &result.Evidence[i]
		if original, ok := sealed[entry.ExchangeID]; ok && original == nil {
			rejectConflictingEvidence(entry)
			result.Error = strings.TrimSpace(result.Error + " conflicting evidence capture identity")
		}
	}
	selected, supplied := false, false
	// Explicit selections (including unavailable ones) own the compatibility
	// pair. Unknown/context primaries cannot provide a replacement pair.
	for _, entry := range result.Evidence {
		if entry.Primary && proofRole(entry.Role) {
			result.Request, result.Response = "", ""
			break
		}
	}
	// A native module invocation selects one primary explicitly. Multiple
	// primaries may coexist only in persisted histories of separate occurrences;
	// choosing the first here would turn slice order into evidence attribution.
	primaryCount := 0
	for _, entry := range result.Evidence {
		if entry.Primary && (entry.Role == evidence.RoleAttack || entry.Role == evidence.RoleConfirmation || entry.Role == evidence.RoleObservation) {
			primaryCount++
		}
	}
	ambiguous := primaryCount > 1
	if ambiguous {
		result.Request, result.Response = "", ""
		result.Error = strings.TrimSpace(result.Error + " multiple primary evidence selections in one occurrence")
	}
	occurrence := ""
	for _, entry := range result.Evidence {
		if entry.OccurrenceID != "" {
			occurrence = entry.OccurrenceID
			break
		}
	}
	if occurrence == "" {
		occurrence = uuid.NewString()
	}
	for i := range result.Evidence {
		entry := &result.Evidence[i]
		if entry.Role == "" {
			entry.Role = evidence.RoleUnknown
		}
		entry.OccurrenceID, entry.FindingURL, entry.ScanUUID = occurrence, result.URL, e.scanUUID
		if !evidence.ValidRole(entry.Role) {
			entry.Primary = false
			continue
		}
		if entry.Exchange == nil && entry.ExchangeID == "" {
			// Preserve an unavailable association rather than letting a malformed
			// optional selection reject the entire finding during persistence.
			entry.ExchangeID, entry.Exchange = "rejected-evidence:"+uuid.NewString(), nil
			entry.Label = strings.TrimSpace(entry.Label + " [exchange identity missing]")
			result.Error = strings.TrimSpace(result.Error + " evidence exchange identity missing")
			continue
		}
		if entry.Exchange != nil && (entry.Exchange.Validate() != nil || entry.ExchangeID != entry.Exchange.ID) {
			// Keep the rejected declaration as an explicitly unavailable manifest.
			// Its claimed ID must not resolve a different stored receipt later.
			// No exchange is created for this marker and no invalid bytes become
			// canonical evidence; the finding itself can still be persisted.
			entry.ExchangeID, entry.Exchange = "rejected-evidence:"+uuid.NewString(), nil
			entry.Label = strings.TrimSpace(entry.Label + " [invalid receipt rejected]")
			result.Error = strings.TrimSpace(result.Error + " invalid or modified evidence receipt")
			continue
		}
		if ambiguous && entry.Primary && (entry.Role == evidence.RoleAttack || entry.Role == evidence.RoleConfirmation || entry.Role == evidence.RoleObservation) {
			continue // retain the conflicting declarations without selecting one
		}
		if entry.Primary && entry.Exchange != nil && entry.Role != evidence.RoleBaseline {
			x := entry.Exchange
			if entry.Role == evidence.RoleAttack || entry.Role == evidence.RoleConfirmation || entry.Role == evidence.RoleObservation {
				// A partial explicit selection is authoritative too. Never retain
				// stale legacy bytes for its absent side, or pair it with baseline.
				result.Request, result.Response = string(x.Request), string(x.Response)
			}
			if len(x.Request) > 0 && len(x.Response) > 0 && x.RequestState != evidence.StateMissing && x.ResponseState != evidence.StateMissing {
				if entry.Role == evidence.RoleAttack || entry.Role == evidence.RoleConfirmation || entry.Role == evidence.RoleObservation {
					if !selected {
						result.Request, result.Response = string(x.Request), string(x.Response)
					}
					selected = true
				} else {
					supplied = true
				}
			}
		}
	}
	switch {
	case ambiguous:
		result.EvidenceStatus = "missing"
	case selected:
		result.EvidenceStatus = "selected"
	case supplied:
		result.EvidenceStatus = "unclassified"
	default:
		result.EvidenceStatus = "missing"
	}
}

func proofRole(role evidence.Role) bool {
	return role == evidence.RoleAttack || role == evidence.RoleConfirmation || role == evidence.RoleObservation
}

// sealPostHookEvidence retains executor-owned captures outside a mutable hook
// event. A public hash is self-consistency, not a seal: rewriting bytes and
// recomputing it must not alter first-save capture identity or metadata. A nil
// value marks conflicting captures; neither variant may be selected by order.
func sealPostHookEvidence(entries []evidence.Entry) map[string]*evidence.Exchange {
	sealed := indexEvidenceCaptures(entries)
	for id, x := range sealed {
		sealed[id] = x.Clone()
	}
	return sealed
}

// Index within the current synchronous event without copying large bodies.
// Only the independent post-hook seal needs owned receipt clones.
func indexEvidenceCaptures(entries []evidence.Entry) map[string]*evidence.Exchange {
	sealed := make(map[string]*evidence.Exchange)
	for _, entry := range entries {
		x := entry.Exchange
		if x == nil {
			continue
		}
		if original, exists := sealed[x.ID]; exists {
			if original != nil && !sameEvidenceCapture(original, x) {
				sealed[x.ID] = nil
			}
			continue
		}
		sealed[x.ID] = x
	}
	return sealed
}

func sameEvidenceCapture(a, b *evidence.Exchange) bool {
	return a.ID == b.ID && a.Service == b.Service && a.URL == b.URL &&
		a.RequestState == b.RequestState && a.ResponseState == b.ResponseState &&
		a.Provenance == b.Provenance && a.ContentHash == b.ContentHash &&
		a.CapturedAt.Equal(b.CapturedAt) && bytes.Equal(a.Request, b.Request) && bytes.Equal(a.Response, b.Response)
}

func rejectConflictingEvidence(entry *evidence.Entry) {
	entry.ExchangeID, entry.Exchange = "rejected-evidence:"+uuid.NewString(), nil
	entry.Label = strings.TrimSpace(entry.Label + " [conflicting capture identity rejected]")
}

func restorePostHookEvidence(result *output.ResultEvent, sealed map[string]*evidence.Exchange) {
	for i := range result.Evidence {
		entry := &result.Evidence[i]
		original, ok := sealed[entry.ExchangeID]
		if !ok && entry.Exchange != nil {
			original, ok = sealed[entry.Exchange.ID]
		}
		if !ok {
			continue
		} // hooks may select another independently captured receipt
		if original == nil {
			rejectConflictingEvidence(entry)
			result.Error = strings.TrimSpace(result.Error + " conflicting evidence capture identity")
			continue
		}
		if entry.Exchange == nil || !sameEvidenceCapture(entry.Exchange, original) {
			entry.ExchangeID, entry.Exchange = original.ID, original.Clone()
			result.Error = strings.TrimSpace(result.Error + " post-hook attempted to rewrite sealed evidence")
		}
	}
}
