package server

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

type autopilotCountUpdateHook struct {
	mu      sync.Mutex
	updates []string
}

func (h *autopilotCountUpdateHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(event.Query)), "UPDATE ") && strings.Contains(event.Query, "agentic_scans") {
		h.mu.Lock()
		h.updates = append(h.updates, event.Query)
		h.mu.Unlock()
	}
	return ctx
}

func (*autopilotCountUpdateHook) AfterQuery(context.Context, *bun.QueryEvent) {}

func (h *autopilotCountUpdateHook) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.updates...)
}

func TestAutopilotFindingCountTerminalUpdate(t *testing.T) {
	cases := []struct {
		name   string
		result *agent.AutopilotPipelineResult
		status string
		want   int
	}{
		{
			name: "available zero success",
			result: &agent.AutopilotPipelineResult{
				FindingCountAvailable: true,
				TotalFindings:         0,
				FindingsCount:         8,
				VerifiedFindingCount:  5,
			},
			status: "completed",
			want:   0,
		},
		{
			name: "available zero failure",
			result: &agent.AutopilotPipelineResult{
				FindingCountAvailable: true,
				TotalFindings:         0,
			},
			status: "failed",
			want:   0,
		},
		{
			name: "available nonzero warnings",
			result: &agent.AutopilotPipelineResult{
				FindingCountAvailable: true,
				TotalFindings:         4,
				FindingsCount:         8,
				VerifiedFindingCount:  5,
				Degraded:              true,
				Warnings:              []string{"partial audit"},
			},
			status: "completed_with_warnings",
			want:   4,
		},
		{
			name: "available nonzero cancellation",
			result: &agent.AutopilotPipelineResult{
				FindingCountAvailable: true,
				TotalFindings:         3,
			},
			status: "cancelled",
			want:   3,
		},
		{
			name: "unavailable ignores stale total success",
			result: &agent.AutopilotPipelineResult{
				TotalFindings:        77,
				FindingsCount:        8,
				VerifiedFindingCount: 5,
			},
			status: "completed",
			want:   -1,
		},
		{
			name:   "unavailable failure",
			result: &agent.AutopilotPipelineResult{},
			status: "failed",
			want:   -1,
		},
		{
			name:   "nil success",
			status: "completed",
			want:   -1,
		},
		{
			name:   "nil failure",
			status: "failed",
			want:   -1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, repo, sessionsDir := newAgentTestHandlers(t)
			runUUID, err := h.registerRunningAgenticScan("autopilot", "olium", "", database.DefaultProjectUUID)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			run, err := repo.GetAgenticScan(ctx, runUUID)
			if err != nil {
				t.Fatal(err)
			}
			run.FindingCount = 9
			run.RecordCount = 12
			run.SavedCount = 7
			run.SourcePath = "/sources/existing"
			run.SourceType = "local"
			run.TargetURL = "https://example.test"
			run.InputRaw = "original instruction"
			run.PromptSent = "original prompt"
			run.SessionDir = sessionsDir
			run.SessionID = "resume-session"
			run.ScanUUID = uuid.NewString()
			run.TokenUsage = map[string]interface{}{"audit": float64(123)}
			run.TotalInputTokens = 123
			run.TotalOutputTokens = 45
			run.EstimatedCostUSD = 0.25
			run.RetryCount = 2
			run.CurrentPhase = "autopilot"
			run.PhasesRun = []string{"audit", "autopilot"}
			run.ModuleNames = []string{"sqli"}
			run.AttackPlan = "original plan"
			run.TriageResult = "original triage"
			run.AgentRawOutput = "original output"
			run.ErrorMessage = "previous warning"
			run.StorageURL = "gs://bucket/existing"
			run.ResultJSON = `{"existing":"result"}`
			if err := repo.UpdateAgenticScan(ctx, run); err != nil {
				t.Fatal(err)
			}
			before, err := repo.GetAgenticScan(ctx, runUUID)
			if err != nil {
				t.Fatal(err)
			}
			h.agentMu.Lock()
			h.agenticScanStatus[runUUID].FindingCount = 9
			h.agentMu.Unlock()
			hook := &autopilotCountUpdateHook{}
			repo.DB().AddQueryHook(hook)

			h.finalizeAutopilotFindingCount(runUUID, database.DefaultProjectUUID, tc.result)
			h.agentMu.Lock()
			memoryCount := h.agenticScanStatus[runUUID].FindingCount
			h.agentMu.Unlock()
			if memoryCount != tc.want {
				t.Fatalf("in-memory finding count = %d, want %d", memoryCount, tc.want)
			}
			if updates := hook.snapshot(); len(updates) != 0 {
				t.Fatalf("count finalization performed a separate DB update: %v", updates)
			}
			pending, err := repo.GetAgenticScan(ctx, runUUID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pending, before) {
				t.Fatal("in-memory count finalization changed the DB before terminal metadata was ready")
			}

			now := before.StartedAt.Add(2 * time.Second)
			errorMessage := ""
			if tc.status == "failed" || tc.status == "cancelled" {
				errorMessage = "operator stopped"
			} else if tc.result != nil {
				errorMessage = strings.Join(tc.result.Warnings, "\n")
			}
			originalTotal := 0
			if tc.result != nil {
				originalTotal = tc.result.TotalFindings
			}
			h.enrichAutopilotScanRecord(runUUID, database.DefaultProjectUUID, tc.result, func(run *database.AgenticScan) {
				run.Status = tc.status
				run.ErrorMessage = errorMessage
				run.CompletedAt = now
				run.DurationMs = now.Sub(run.StartedAt).Milliseconds()
			})
			if tc.result != nil && tc.result.TotalFindings != originalTotal {
				t.Fatalf("terminal persistence mutated the caller's result total: got %d, want %d", tc.result.TotalFindings, originalTotal)
			}
			got, err := repo.GetAgenticScan(ctx, runUUID)
			if err != nil {
				t.Fatal(err)
			}
			if got.FindingCount != tc.want || got.Status != tc.status || !got.CompletedAt.Equal(now) || got.DurationMs != 2000 || got.ErrorMessage != errorMessage {
				t.Fatalf("terminal metadata/count not persisted together: %+v", got)
			}
			updates := hook.snapshot()
			if len(updates) != 1 {
				t.Fatalf("terminal finalization performed %d updates, want one: %v", len(updates), updates)
			}
			_, where, ok := strings.Cut(updates[0], " WHERE ")
			if !ok || !strings.Contains(where, "uuid") || !strings.Contains(where, runUUID) || !strings.Contains(where, "project_uuid") || !strings.Contains(where, database.DefaultProjectUUID) {
				t.Fatalf("terminal update lacks project + UUID predicates: %s", updates[0])
			}

			expected := *before
			expected.FindingCount = tc.want
			expected.Status = tc.status
			expected.ErrorMessage = errorMessage
			expected.CompletedAt = now
			expected.DurationMs = 2000
			if tc.result != nil && (tc.status == "completed" || tc.status == "completed_with_warnings") {
				var persisted agent.AutopilotPipelineResult
				if err := json.Unmarshal([]byte(got.ResultJSON), &persisted); err != nil {
					t.Fatalf("decode success result_json: %v", err)
				}
				if persisted.FindingCountAvailable != tc.result.FindingCountAvailable || persisted.TotalFindings != tc.want {
					t.Fatalf("result_json lost count availability/canonical total: %s", got.ResultJSON)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal([]byte(got.ResultJSON), &fields); err != nil {
					t.Fatal(err)
				}
				if _, ok := fields["FindingCountAvailable"]; !ok {
					t.Fatalf("result_json must explicitly include count availability: %s", got.ResultJSON)
				}
				resultSnapshot := *tc.result
				resultSnapshot.TotalFindings = tc.want
				if !reflect.DeepEqual(persisted, resultSnapshot) {
					t.Fatalf("result_json changed unrelated pipeline fields: got %+v, want %+v", persisted, resultSnapshot)
				}
				data, err := json.Marshal(resultSnapshot)
				if err != nil {
					t.Fatal(err)
				}
				expected.ResultJSON = string(data)
			}
			if !reflect.DeepEqual(got, &expected) {
				t.Fatalf("terminal update lost unrelated loaded metadata:\ngot:  %+v\nwant: %+v", got, &expected)
			}
		})
	}
}

func TestAutopilotFindingCountForeignProjectUnchanged(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	ownerProject := uuid.NewString()
	foreignProject := uuid.NewString()
	runUUID, err := h.registerRunningAgenticScan("autopilot", "olium", "", ownerProject)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	run, err := repo.GetAgenticScan(ctx, runUUID)
	if err != nil {
		t.Fatal(err)
	}
	run.FindingCount = 9
	run.TargetURL = "https://owner.example.test"
	run.SessionID = "owner-session"
	if err := repo.UpdateAgenticScan(ctx, run); err != nil {
		t.Fatal(err)
	}
	before, err := repo.GetAgenticScan(ctx, runUUID)
	if err != nil {
		t.Fatal(err)
	}
	h.agentMu.Lock()
	h.agenticScanStatus[runUUID].FindingCount = 9
	memoryBefore := *h.agenticScanStatus[runUUID]
	h.agentMu.Unlock()
	hook := &autopilotCountUpdateHook{}
	repo.DB().AddQueryHook(hook)

	result := &agent.AutopilotPipelineResult{FindingCountAvailable: true, TotalFindings: 0}
	h.finalizeAutopilotFindingCount(runUUID, foreignProject, result)
	mutated := false
	h.enrichAutopilotScanRecord(runUUID, foreignProject, result, func(run *database.AgenticScan) {
		mutated = true
		run.Status = "completed"
		run.TargetURL = "https://foreign.example.test"
	})
	if mutated {
		t.Fatal("terminal callback received a row belonging to a foreign project")
	}
	h.agentMu.Lock()
	memoryAfter := *h.agenticScanStatus[runUUID]
	h.agentMu.Unlock()
	if !reflect.DeepEqual(memoryAfter, memoryBefore) {
		t.Fatalf("foreign finalization changed in-memory status: got %+v, want %+v", memoryAfter, memoryBefore)
	}
	after, err := repo.GetAgenticScan(ctx, runUUID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("foreign finalization changed the stored row: got %+v, want %+v", after, before)
	}
	if updates := hook.snapshot(); len(updates) != 0 {
		t.Fatalf("foreign finalization issued DB updates: %v", updates)
	}
}

func TestAutopilotFindingCountWithoutRepository(t *testing.T) {
	cases := []struct {
		name   string
		result *agent.AutopilotPipelineResult
		want   int
	}{
		{"zero", &agent.AutopilotPipelineResult{FindingCountAvailable: true}, 0},
		{"nonzero", &agent.AutopilotPipelineResult{FindingCountAvailable: true, TotalFindings: 4}, 4},
		{"unavailable", &agent.AutopilotPipelineResult{TotalFindings: 77}, -1},
		{"nil", nil, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{
				agenticScanStatus: map[string]*AgenticScanStatusResponse{
					"run": {ProjectUUID: database.DefaultProjectUUID, FindingCount: 9},
				},
			}
			h.finalizeAutopilotFindingCount("run", database.DefaultProjectUUID, tc.result)
			if got := h.agenticScanStatus["run"].FindingCount; got != tc.want {
				t.Fatalf("finding count without repository = %d, want %d", got, tc.want)
			}
			h.finalizeAutopilotFindingCount("missing", database.DefaultProjectUUID, tc.result)
			h.enrichAutopilotScanRecord("run", database.DefaultProjectUUID, tc.result, func(*database.AgenticScan) {
				t.Fatal("terminal callback called without a repository")
			})
		})
	}
}
