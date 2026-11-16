package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/agent"
)

type retentionAuditRunner struct{ outcome agent.AuditOutcome }

func (r *retentionAuditRunner) Start(context.Context) error { return nil }
func (r *retentionAuditRunner) Wait() error {
	return errors.Join(r.outcome.ProcessErr, r.outcome.EvidenceErr)
}
func (r *retentionAuditRunner) Done() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
func (r *retentionAuditRunner) Cancel()                         {}
func (r *retentionAuditRunner) Status() *agent.AuditAgentStatus { return &agent.AuditAgentStatus{} }
func (r *retentionAuditRunner) FindingStats() agent.FindingStats {
	return agent.FindingStats{Parsed: 1, Saved: 1}
}
func (r *retentionAuditRunner) CostSummary() agent.ScanCost { return agent.ScanCost{} }
func (r *retentionAuditRunner) AgenticScanUUID() string     { return "audit-retention" }
func (r *retentionAuditRunner) Outcome() agent.AuditOutcome { return r.outcome }

func TestAuditRetentionServerCachePreservesTerminalOutcome(t *testing.T) {
	for _, status := range []string{"completed_with_warnings", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			r := &retentionAuditRunner{outcome: agent.AuditOutcome{Status: status, EvidenceErr: errors.New("archive unavailable")}}
			if status == "cancelled" {
				r.outcome.ProcessErr = context.Canceled
			}
			h := &Handlers{agenticScanStatus: map[string]*AgenticScanStatusResponse{r.AgenticScanUUID(): {Status: "running"}}}
			h.finalizeAuditRun(auditRunPlan{agenticScanUUID: r.AgenticScanUUID()}, r, r.Wait(), "")
			got := h.agenticScanStatus[r.AgenticScanUUID()]
			if got.Status != status || got.CompletedAt == nil {
				t.Fatalf("cache replaced durable outcome: %+v", got)
			}
		})
	}
}

func TestAuditRetentionServerCatalogFailureIsVisible(t *testing.T) {
	for _, combined := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "combined"}[combined], func(t *testing.T) {
			r := &retentionAuditRunner{outcome: agent.AuditOutcome{Status: "completed"}}
			h := &Handlers{repo: newTestRepo(t), agenticScanStatus: map[string]*AgenticScanStatusResponse{r.AgenticScanUUID(): {Status: "running"}}}
			// No catalog row exists: both finalizers must return the lookup error,
			// leave a terminal warning in cache, and never retry the driver.
			var err error
			if combined {
				err = h.finalizeCombinedAuditRun(combinedAuditPlan{parentUUID: r.AgenticScanUUID(), req: AgentAuditRequest{NoDedup: true}}, combinedAuditSetup{}, []driverResult{{runner: r}}, time.Now())
			} else {
				err = h.finalizeAuditRun(auditRunPlan{agenticScanUUID: r.AgenticScanUUID()}, r, nil, "")
			}
			got := h.agenticScanStatus[r.AgenticScanUUID()]
			if err == nil || got.Status != "completed_with_warnings" || got.Error == "" || got.CompletedAt == nil {
				t.Fatalf("catalog failure disappeared: %+v, %v", got, err)
			}
		})
	}
}

func TestAuditRetentionCombinedWarningsAreNotFailedDrivers(t *testing.T) {
	warning := &retentionAuditRunner{outcome: agent.AuditOutcome{Status: "completed_with_warnings", EvidenceErr: errors.New("archive failed")}}
	cancelled := &retentionAuditRunner{outcome: agent.AuditOutcome{Status: "cancelled", ProcessErr: context.Canceled}}
	for _, tt := range []struct {
		name    string
		results []driverResult
		want    string
	}{
		{"evidence only", []driverResult{{runner: warning, runErr: warning.Wait()}}, "completed_with_warnings"},
		{"mixed clean warning", []driverResult{{}, {runner: warning, runErr: warning.Wait()}}, "completed_with_warnings"},
		{"execution failure", []driverResult{{runner: warning, runErr: warning.Wait()}, {runErr: errors.New("process failed")}}, "completed_with_errors"},
		{"cancel", []driverResult{{runner: cancelled, runErr: cancelled.Wait()}}, "cancelled"},
		{"launch failure without terminal outcome", []driverResult{{runner: &retentionAuditRunner{}, runErr: errors.New("start failed")}}, "failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := combinedAuditStatus(tt.results); got != tt.want {
				t.Fatalf("status = %s, want %s", got, tt.want)
			}
		})
	}
}
