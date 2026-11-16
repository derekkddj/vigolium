package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/agent/recon"
	"github.com/vigolium/vigolium/pkg/database"
)

func attributionTestFinding(t *testing.T, repo *database.Repository, project, scan, parent string) *database.Finding {
	t.Helper()
	f := &database.Finding{ProjectUUID: project, ScanUUID: scan, AgenticScanUUID: parent, FindingHash: uuid.NewString(), ModuleID: "passive", ModuleName: "Passive", Severity: "high", Confidence: "firm"}
	if err := repo.SaveFindingDirect(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSwarmDiscoveryFailedCountDetachedCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "planner-failed", true: "cancelled"}[cancelled], func(t *testing.T) {
			repo := newAuditTestRepo(t)
			project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
			run := &database.AgenticScan{UUID: parent, ProjectUUID: project, ScanUUID: child, Mode: "swarm", Status: "running"}
			if err := repo.CreateAgenticScan(context.Background(), run); err != nil {
				t.Fatal(err)
			}
			runner := NewSwarmRunner(nil, repo)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := SwarmConfig{ProjectUUID: project, ScanUUID: child}
			cfg.DiscoverFunc = func(context.Context) error {
				if err := repo.CreateScan(context.Background(), &database.Scan{UUID: child, ProjectUUID: project, Name: "discovery", Status: "failed"}); err != nil {
					t.Fatal(err)
				}
				attributionTestFinding(t, repo, project, child, "")
				// An older canonical finding is not a new occurrence for this run.
				attributionTestFinding(t, repo, project, uuid.NewString(), uuid.NewString())
				if cancelled {
					cancel()
				}
				return errors.New("discovery failed after passive evidence")
			}
			result := &SwarmResult{}
			ps := &swarmPipelineState{runner: runner, cfg: cfg, agenticScan: run, result: result, phaseTimings: make(map[string]time.Duration)}
			if err := (discoverySwarmStep{}).Run(ctx, ps); err != nil {
				t.Fatal(err)
			}
			if result.TotalFindings != 1 {
				t.Fatalf("discovery count=%d", result.TotalFindings)
			}
			// The common finalizer must recover evidence even if the phase did
			// not attribute anything (e.g. a fatal exit before completing it).
			if _, err := repo.DB().NewUpdate().Model((*database.Finding)(nil)).Set("agentic_scan_uuid = NULL").Where("scan_uuid = ?", child).Exec(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.DB().NewUpdate().Model((*database.Scan)(nil)).Set("agentic_scan_uuid = NULL").Where("uuid = ?", child).Exec(context.Background()); err != nil {
				t.Fatal(err)
			}
			result.TotalFindings = 0
			fatal := errors.New("planner failed")
			if cancelled {
				fatal = context.Canceled
			}
			got, err := runner.finishRun(ctx, cfg, run, result, time.Now(), fatal)
			if err != fatal || got.TotalFindings != 1 || got.SeverityCounts["high"] != 1 {
				t.Fatalf("err=%v result=%+v", err, got)
			}
			stored, err := repo.GetAgenticScan(context.Background(), parent)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus := "failed"
			if cancelled {
				wantStatus = "cancelled"
			}
			if stored.Status != wantStatus || stored.FindingCount != 1 {
				t.Fatalf("stored status/count=%s/%d", stored.Status, stored.FindingCount)
			}
			native, err := repo.GetScanByUUID(context.Background(), child)
			if err != nil {
				t.Fatal(err)
			}
			if native.Status != "failed" || native.AgenticScanUUID != parent {
				t.Fatalf("native=%+v", native)
			}
		})
	}
}

func TestSwarmFindingCountUnavailableIsNotZero(t *testing.T) {
	repo := newAuditTestRepo(t)
	if err := repo.DB().Close(); err != nil {
		t.Fatal(err)
	}
	result := &SwarmResult{}
	run := &database.AgenticScan{UUID: uuid.NewString(), ProjectUUID: uuid.NewString()}
	fatal := errors.New("planner failed")
	got, err := NewSwarmRunner(nil, repo).finishRun(context.Background(), SwarmConfig{}, run, result, time.Now(), fatal)
	if err != fatal || got.TotalFindings != -1 || run.FindingCount != -1 || run.Status != "failed" {
		t.Fatalf("error/count/status=%v/%d/%s", err, got.TotalFindings, run.Status)
	}
	if !strings.Contains(strings.Join(got.Warnings, "\n"), "finding count unavailable") {
		t.Fatal("unavailable count has no warning")
	}
}

func TestSwarmUnavailableCountDoesNotReplan(t *testing.T) {
	repo := newAuditTestRepo(t)
	if err := repo.DB().Close(); err != nil {
		t.Fatal(err)
	}
	ps := &swarmPipelineState{
		runner:      NewSwarmRunner(nil, repo),
		cfg:         SwarmConfig{ScanFunc: func(context.Context, ScanRequest) error { t.Fatal("unknown count triggered rescan"); return nil }},
		agenticScan: &database.AgenticScan{UUID: uuid.NewString(), ProjectUUID: uuid.NewString()},
		result:      &SwarmResult{}, plan: &SwarmPlan{},
		techStack: &recon.TechStackReport{Stacks: []recon.StackDetection{{Name: "spring-boot", Tag: "spring"}}},
	}
	if err := (replanOnEmptySwarmStep{}).Run(context.Background(), ps); err != nil {
		t.Fatal(err)
	}
	if len(ps.result.Warnings) == 0 {
		t.Fatal("unavailable count was not reported")
	}
}

func TestSwarmCountUsesNativeRelationWithoutMovingOlderParents(t *testing.T) {
	repo := newAuditTestRepo(t)
	project, parent, child := uuid.NewString(), uuid.NewString(), uuid.NewString()
	run := &database.AgenticScan{UUID: parent, ProjectUUID: project, ScanUUID: child, Mode: "swarm", Status: "running"}
	if err := repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScan(context.Background(), &database.Scan{UUID: child, ProjectUUID: project, AgenticScanUUID: parent, Name: "child", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	attributionTestFinding(t, repo, project, child, "")
	olderParent := uuid.NewString()
	old := attributionTestFinding(t, repo, project, child, olderParent)
	ps := &swarmPipelineState{runner: NewSwarmRunner(nil, repo), cfg: SwarmConfig{ScanUUID: child}, agenticScan: run, result: &SwarmResult{}}
	total, _ := ps.runFindingCounts(context.Background())
	if total != 1 {
		t.Fatalf("native relation count=%d, want 1 (not older canonical ownership)", total)
	}
	ps.attributeRunFindings(context.Background())
	stored := &database.Finding{}
	if err := repo.DB().NewSelect().Model(stored).Where("id = ?", old.ID).Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stored.AgenticScanUUID != olderParent || stored.ScanUUID != child {
		t.Fatal("older parent moved")
	}
}
