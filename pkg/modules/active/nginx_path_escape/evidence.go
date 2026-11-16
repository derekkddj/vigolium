package nginx_path_escape

import (
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// buildEvidenceResult preserves Info grading and selects only the explicitly
// validated reached-resource operation. Probe.Base is never a request receipt.
func buildEvidenceResult(url, host, report string, findings []*finding) *output.ResultEvent {
	if len(findings) == 0 {
		return nil
	}
	context := modkit.NewEvidenceCollector()
	for i, f := range findings {
		if i > 0 {
			context.AddExchange(f.Primary, evidence.RoleAttack, "Additional validated path probe")
		}
		for _, entry := range f.Context.Evidence() {
			context.AddExchange(entry.Exchange, entry.Role, entry.Label)
		}
	}
	result := &output.ResultEvent{
		URL: url, Host: host, FuzzingParameter: "PATH",
		AdditionalEvidence: context.Entries(), Evidence: context.Evidence(),
		Info: output.Info{Severity: severity.Info, Description: report},
	}
	modkit.SetPrimaryEvidence(result, findings[0].Primary, evidence.RoleAttack, "Validated reached-resource path probe")
	return result
}

func addSnapshotContext(sink *modkit.EvidenceCollector, attack *diffscan.Attack, role evidence.Role, label string) {
	if attack == nil || attack.FirstSnapshot == nil {
		return
	}
	sink.AddExchange(attack.FirstSnapshot.Exchange, role, label)
}
