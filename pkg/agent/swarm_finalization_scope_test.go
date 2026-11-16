package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestSwarmFinalizationRefusesForeignParent(t *testing.T) {
	repo := newAuditTestRepo(t)
	parent, project := uuid.NewString(), uuid.NewString()
	if err := repo.CreateAgenticScan(context.Background(), &database.AgenticScan{UUID: parent, ProjectUUID: project, Mode: "swarm", Status: "running", FindingCount: 7}); err != nil {
		t.Fatal(err)
	}
	run := &database.AgenticScan{UUID: parent, ProjectUUID: uuid.NewString(), Mode: "swarm", Status: "running"}
	fatal := errors.New("planner failed")
	result, err := NewSwarmRunner(nil, repo).finishRun(context.Background(), SwarmConfig{}, run, &SwarmResult{}, time.Now(), fatal)
	if err != fatal || result.TotalFindings != -1 || len(result.Warnings) == 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	stored, err := repo.GetAgenticScan(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ProjectUUID != project || stored.Status != "running" || stored.FindingCount != 7 {
		t.Fatalf("foreign parent mutated: %+v", stored)
	}
}

func TestSwarmFinalizationNoRepositoryCountUnavailable(t *testing.T) {
	run := &database.AgenticScan{UUID: uuid.NewString(), Mode: "swarm", Status: "running"}
	cfg := SwarmConfig{ScanFunc: func(context.Context, ScanRequest) error { return nil }}
	fatal := errors.New("native work failed")
	result, err := NewSwarmRunner(nil, nil).finishRun(context.Background(), cfg, run, &SwarmResult{}, time.Now(), fatal)
	if err != fatal || result.TotalFindings != -1 || len(result.Warnings) == 0 || run.Status != "failed" {
		t.Fatalf("result=%+v err=%v status=%s", result, err, run.Status)
	}
}

func TestSwarmFinalizationPersistsKnownZero(t *testing.T) {
	repo := newAuditTestRepo(t)
	run := &database.AgenticScan{UUID: uuid.NewString(), ProjectUUID: uuid.NewString(), Mode: "swarm", Status: "running", FindingCount: 7}
	if err := repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	result, err := NewSwarmRunner(nil, repo).finishRun(context.Background(), SwarmConfig{}, run, &SwarmResult{}, time.Now(), nil)
	if err != nil || result.TotalFindings != 0 {
		t.Fatalf("err=%v count=%d", err, result.TotalFindings)
	}
	stored, err := repo.GetAgenticScan(context.Background(), run.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.FindingCount != 0 || stored.Status != "completed" {
		t.Fatalf("stored=%+v", stored)
	}
}
