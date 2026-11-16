package agent

import (
	"encoding/json"
	"errors"
	"os"

	"go.uber.org/zap"
)

// These are planning outcomes, NOT native execution coverage. Record intervals
// are zero-based half-open; Batch is the stable one-based orchestration identity.
type planningBatchOutcome struct {
	Batch  int    `json:"batch"`
	Start  int    `json:"record_start"`
	End    int    `json:"record_end"`
	Status string `json:"status"` // completed, failed, cancelled, not_started
}

func persistPlanningBatches(cfg SwarmConfig, outcomes []planningBatchOutcome, complete bool, partial *SwarmPlan, provenance *BatchProvenance) {
	if cfg.SessionDir == "" {
		return
	}
	if complete {
		partial = nil
	}
	f, err := os.CreateTemp(cfg.SessionDir, "plan-batches-*.json")
	if err == nil {
		err = json.NewEncoder(f).Encode(struct {
			Complete   bool                   `json:"complete"`
			Batches    []planningBatchOutcome `json:"batches"`
			Partial    *SwarmPlan             `json:"partial_plan,omitempty"`
			Provenance *BatchProvenance       `json:"batch_provenance,omitempty"`
		}{complete, outcomes, partial, provenance})
		err = errors.Join(err, f.Sync(), f.Close())
	}
	if err != nil {
		zap.L().Warn("Planning batch outcome recording degraded", zap.Error(err))
		_ = WriteRuntimeProgress(cfg.StreamWriter, "agent", "plan", "Evidence degraded: planning batch outcomes could not be persisted")
	}
}
