package server

import "github.com/vigolium/vigolium/pkg/agent"

func autopilotFindingCount(result *agent.AutopilotPipelineResult) int {
	if result != nil && result.FindingCountAvailable {
		return result.TotalFindings
	}
	return -1
}

// Both SSE and background paths use the pipeline's reconciled total, including
// on failure/cancellation. Only update memory here: the count must be persisted
// together with terminal metadata in the project-validated enrichment update.
func (h *Handlers) finalizeAutopilotFindingCount(uuid, project string, result *agent.AutopilotPipelineResult) {
	h.agentMu.Lock()
	if status := h.agenticScanStatus[uuid]; status != nil && status.ProjectUUID == project {
		status.FindingCount = autopilotFindingCount(result)
	}
	h.agentMu.Unlock()
}
