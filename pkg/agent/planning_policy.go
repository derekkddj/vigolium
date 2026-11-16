package agent

import (
	"fmt"
	"html"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/skill"
)

// The phase boundary is system-level and selected by orchestration, so custom
// templates and overall scan instructions cannot grant execution tools here.
const planningSystem = `You are the swarm planning phase, not a discovery, authentication or exploitation agent.
Analyze ONLY the HTTP/recon/source context supplied in the prompt. Select scanner modules and recommend skills for LATER triage. No tools are available: do not run commands, fetch URLs, replay requests, read files or load/execute skills. Overall scan instructions specify objectives for later phases, not permission to investigate in this phase.
Produce your final markdown plan now, including a nonempty ## FOCUS_AREAS section. Put observations, assumptions and missing-context limitations in ## NOTES. Do not claim that unperformed tests or authentication checks succeeded. Omit MODULE_TAGS when the evidence does not justify a restrictive selection; do not guess evidence or endpoints.`

func planningProviderPolicy(p provider.Provider) error {
	if provider.HasInternalToolLoop(p) {
		return fmt.Errorf("planning requires a provider without an internal tool loop; %s cannot enforce the planning boundary", p.Name())
	}
	return nil
}

func validatePlanningDeliverable(plan *SwarmPlan) error {
	if plan != nil {
		for _, focus := range plan.FocusAreas {
			if strings.TrimSpace(focus) != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("planning deliverable requires nonempty FOCUS_AREAS; notes or module tags alone are not a completed plan")
}

func planningSystemPrompt(reg *skill.Registry) string {
	var b strings.Builder
	b.WriteString(planningSystem)
	if reg == nil || reg.Len() == 0 {
		return b.String()
	}
	b.WriteString("\n\n<available_skills>\nSelection catalog only: recommend matching names for later triage; do not load or execute these workflows.\n")
	for _, s := range reg.List() {
		fmt.Fprintf(&b, "<skill><name>%s</name><description>%s</description><tags>%s</tags></skill>\n",
			html.EscapeString(s.Name), html.EscapeString(s.Description), html.EscapeString(strings.Join(s.Tags, ", ")))
	}
	b.WriteString("</available_skills>")
	return b.String()
}
