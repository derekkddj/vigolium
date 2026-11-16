package verify

import (
	"context"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ambiguousPrimaryOccurrence treats missing occurrence IDs as one legacy group.
// Distinct historical occurrence IDs may each have one primary; declarations
// within the same occurrence cannot be resolved by availability or slice order.
func ambiguousPrimaryOccurrence(entries []evidence.Entry) bool {
	counts := make(map[string]int)
	for _, entry := range entries {
		if entry.Primary && (entry.Role == evidence.RoleAttack || entry.Role == evidence.RoleConfirmation || entry.Role == evidence.RoleObservation) {
			counts[entry.OccurrenceID]++
			if counts[entry.OccurrenceID] > 1 {
				return true
			}
		}
	}
	return false
}

func usableSelectedResult(entries []evidence.Entry) bool {
	if ambiguousPrimaryOccurrence(entries) {
		return false
	}
	for _, entry := range entries {
		x := entry.Exchange
		if !entry.Primary || (entry.Role != evidence.RoleAttack && entry.Role != evidence.RoleConfirmation && entry.Role != evidence.RoleObservation) {
			continue
		}
		if x != nil && x.ID == entry.ExchangeID && x.Provenance != evidence.ProvenanceLegacy && x.RequestState == evidence.StateComplete && x.ResponseState == evidence.StateComplete && len(x.Request) > 0 && len(x.Response) > 0 && x.Validate() == nil {
			return true
		}
	}
	return false
}

// useSelectedExchange reconstructs replay from an explicit association. Unknown,
// control and attack exchanges cannot be guessed into an active baseline.
func (p *Plan) useSelectedExchange(ctx context.Context, repo *database.Repository, projectUUID string, passive bool) bool {
	if ambiguousPrimaryOccurrence(p.finding.Evidence) {
		return p.fail(database.VerdictInconclusive, "multiple primary declarations within one occurrence; no replay chosen")
	}
	var selected *evidence.Entry
	for i := range p.finding.Evidence {
		e := &p.finding.Evidence[i]
		eligible := e.Role == evidence.RoleBaseline
		if passive {
			eligible = e.Primary && e.Role == evidence.RoleObservation
		}
		if !eligible {
			continue
		}
		if selected != nil {
			return p.fail(database.VerdictInconclusive, "multiple selected replay exchanges; exact occurrence selection is required")
		}
		selected = e
	}
	if selected == nil {
		return p.fail(database.VerdictInconclusive, "no explicitly selected baseline / observation; unknown legacy data is not proof and no URL fallback is used")
	}
	if p.finding.ProjectUUID == "" || p.finding.ProjectUUID != projectUUID {
		return p.fail(database.VerdictInconclusive, "selected evidence has no matching captured project")
	}
	x := selected.Exchange
	if x == nil && repo != nil && selected.ExchangeID != "" {
		var err error
		x, err = repo.GetEvidenceExchange(ctx, selected.ExchangeID, projectUUID)
		if err != nil {
			return p.fail(database.VerdictInconclusive, "selected exchange unavailable in the captured project: "+err.Error())
		}
	}
	if x == nil || x.ID != selected.ExchangeID || x.Validate() != nil || x.RequestState != evidence.StateComplete || len(x.Request) == 0 {
		return p.fail(database.VerdictInconclusive, "selected replay request missing, unknown or truncated; no fallback substituted")
	}
	// Never analyze an incomplete/unknown response as complete proof.
	if passive && (x.Provenance == evidence.ProvenanceLegacy || x.ResponseState != evidence.StateComplete) {
		return p.fail(database.VerdictInconclusive, "selected observation response missing, unknown or truncated")
	}
	// Restore the receipt, not a parsed/repaired URL-derived request. Service is
	// the captured destination even when Host, absolute target and URL disagree;
	// binary bodies and declared Content-Length must remain exactly as captured.
	item, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		return p.fail(database.VerdictInconclusive, "selected replay receipt cannot be restored: "+err.Error())
	}
	if !passive && httpmsg.NativeRequestTargetPolicy(item.Request().Raw()) != nil {
		// Native module requests cannot preserve an absolute-form target
		// independently of the connection destination. A normalized send is not
		// exact reproduction of this selected baseline; do not certify it.
		return p.fail(database.VerdictInconclusive, "selected absolute-form request cannot be reproduced by the native HTTP sender; request-target fidelity unknown (raw-capable sender required)")
	}
	if x.ResponseState != evidence.StateComplete {
		item = item.WithResponse(nil)
	}
	p.item = item
	p.Baseline = &Baseline{Source: BaselineSelectedExchange, ExchangeID: selected.ExchangeID, Role: selected.Role}
	return true
}
