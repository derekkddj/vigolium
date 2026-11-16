package sqli_boolean_blind

import (
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// appendStabilityEvidence runs only after the producer assigned its context and
// selected its primary. Reserve two actual unmodified controls by dropping
// redundant confirmation context, never the primary, baseline, FALSE controls,
// syntax-break control or status/HPP annotations. Selection changes no traffic.
func appendStabilityEvidence(result *output.ResultEvent, proof *modkit.EvidenceCollector) {
	if result == nil || proof.Len() == 0 {
		return
	}
	budget := modkit.MaxEvidencePairs - min(2, proof.Len())
	for {
		contextCount, remove, renderedIndex := 0, -1, -1
		for i, entry := range result.Evidence {
			if entry.Primary {
				continue
			}
			if entry.Role == evidence.RoleConfirmation {
				remove, renderedIndex = i, contextCount
			}
			contextCount++
		}
		if contextCount <= budget && len(result.AdditionalEvidence) <= budget || remove < 0 {
			break
		}
		result.Evidence = append(result.Evidence[:remove], result.Evidence[remove+1:]...)
		// Producers render each supporting receipt in selection order, with
		// non-pair annotations following those receipts. Preserve those annotations.
		if renderedIndex < len(result.AdditionalEvidence) {
			result.AdditionalEvidence = append(result.AdditionalEvidence[:renderedIndex], result.AdditionalEvidence[renderedIndex+1:]...)
		}
	}
	modkit.AppendEvidence(result, proof)
}
