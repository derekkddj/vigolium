package aem

import (
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Proof is local to one assertion. It retains the explicitly returned proving
// operation, never an endpoint's last response or the seed input exchange.
type Proof struct {
	Primary *evidence.Exchange
	Context modkit.EvidenceCollector
	Payload string
}

func NewProof(probe ProbeResult) *Proof { return &Proof{Primary: probe.Exchange} }

func (p *Proof) Control(probe ProbeResult) {
	if p != nil {
		p.Context.AddExchange(probe.Exchange, evidence.RoleControl, "Negative control")
	}
}
func (p *Proof) Confirmation(probe ProbeResult) {
	if p != nil {
		p.Context.AddExchange(probe.Exchange, evidence.RoleConfirmation, "Independent confirmation")
	}
}
func (p *Proof) Observe(probe ProbeResult) {
	if p != nil {
		p.Context.AddExchange(probe.Exchange, evidence.RoleObservation, "Supporting observation")
	}
}
func (p *Proof) Observation(result *output.ResultEvent) *output.ResultEvent {
	return p.selectPrimary(result, evidence.RoleObservation)
}
func (p *Proof) Attack(result *output.ResultEvent) *output.ResultEvent {
	return p.selectPrimary(result, evidence.RoleAttack)
}
func (p *Proof) selectPrimary(result *output.ResultEvent, role evidence.Role) *output.ResultEvent {
	if result == nil {
		return nil
	}
	result.Request, result.Response = "", ""
	result.EvidenceStatus = "missing"
	if p != nil {
		result.Evidence = p.Context.Evidence()
		result.AdditionalEvidence = p.Context.Entries()
		result.Payload = p.Payload
		modkit.SetPrimaryEvidence(result, p.Primary, role, "Selected AEM operation")
	}
	return result
}
