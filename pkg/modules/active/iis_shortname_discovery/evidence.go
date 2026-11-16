package iis_shortname_discovery

import "github.com/vigolium/vigolium/pkg/evidence"

// Add only a candidate whose existing confirmation verdict succeeded. Controls
// retain their original cached operation identities; no evidence-only fetches.
func (r *resolver) addResolvedEvidence(first, confirmation probeResp, negative negBaseline, name string) {
	r.context.AddExchange(first.receipt, evidence.RoleObservation, "Resolved candidate: "+name)
	r.context.AddExchange(confirmation.receipt, evidence.RoleConfirmation, "Resolved candidate confirmation: "+name)
	for _, receipt := range negative.receipts {
		r.context.AddExchange(receipt, evidence.RoleControl, "Resolution extension negative")
	}
	for _, receipt := range r.methodReceipts {
		r.context.AddExchange(receipt, evidence.RoleControl, "Resolution method calibration")
	}
}
