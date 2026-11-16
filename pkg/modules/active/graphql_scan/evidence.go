package graphql_scan

import (
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// gqlProof is scoped to one candidate, not to an endpoint/client. Roles are
// chosen by the probe's semantics, never its URL, body hash or informal label.
type gqlProof struct {
	primary     *evidence.Exchange
	primaryHTML bool // XSS error reflection prefers the receipt establishing HTML context
	context     modkit.EvidenceCollector
	payload     string
}

func (p *gqlProof) attack(r *gqlResp, payload string) {
	if r == nil {
		return
	}
	if p.primary == nil {
		p.primary, p.payload = r.Exchange, payload
		return
	}
	p.context.AddExchange(r.Exchange, evidence.RoleConfirmation, "Independent attack confirmation")
}
func (p *gqlProof) control(r *gqlResp) {
	if r != nil {
		p.context.AddExchange(r.Exchange, evidence.RoleControl, "Negative control")
	}
}
func (p *gqlProof) confirm(r *gqlResp) {
	if r != nil {
		p.context.AddExchange(r.Exchange, evidence.RoleConfirmation, "Independent confirmation")
	}
}
func (p *gqlProof) selectResult(result *output.ResultEvent, role evidence.Role) *output.ResultEvent {
	if result == nil {
		return nil
	}
	result.Request, result.Response = "", ""
	result.EvidenceStatus = "missing"
	if p != nil {
		result.Evidence, result.AdditionalEvidence = p.context.Evidence(), p.context.Entries()
		result.Payload = p.payload
		modkit.SetPrimaryEvidence(result, p.primary, role, "Selected GraphQL operation")
	}
	return result
}
func (p *gqlProof) observation(result *output.ResultEvent) *output.ResultEvent {
	return p.selectResult(result, evidence.RoleObservation)
}
func (p *gqlProof) finding(result *output.ResultEvent) *output.ResultEvent {
	return p.selectResult(result, evidence.RoleAttack)
}
