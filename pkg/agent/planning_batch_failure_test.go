package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type planningBatchFailureRuntime struct {
	fakeRuntime
	committed chan struct{}
	root      error
}

func (r *planningBatchFailureRuntime) NewSessionWithSpec(_ *config.OliumConfig, spec SessionSpec) (AgentSession, error) {
	if !spec.PlanningOnly || spec.IncludeTools || spec.VigTools != nil {
		return nil, errors.New("planning capabilities leaked")
	}
	return fakeSession{}, nil // no shared mutable fake.lastSpec in concurrent calls
}
func (r *planningBatchFailureRuntime) RunOnSession(ctx context.Context, _ *config.OliumConfig, _ AgentSession, prompt string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	switch {
	case strings.Contains(prompt, "GET /batch-1 "):
		return oliumRunOutput{Text: "## FOCUS_AREAS\n- /batch-1: native auth checks"}, nil
	case strings.Contains(prompt, "GET /batch-2 "):
		select {
		case <-r.committed:
			return oliumRunOutput{Text: "partial root batch", ToolCalls: 0}, r.root
		case <-ctx.Done():
			return oliumRunOutput{}, ctx.Err()
		}
	default:
		<-ctx.Done()
		return oliumRunOutput{Text: "cancelled partial batch"}, ctx.Err()
	}
}

func TestPlanningFiveBatchFailureKeepsRootAndHonestPartialOutcomes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := errors.New("synthetic originating plan failure")
	rt := &planningBatchFailureRuntime{committed: make(chan struct{}), root: root}
	settings := &config.Settings{}
	settings.Agent.TemplatesDir = t.TempDir()
	body, err := agentprompt.ReadEmbeddedTemplate(SwarmPromptPlan + ".md")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(settings.Agent.TemplatesDir, SwarmPromptPlan+".md"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(settings, nil)
	e.runtime = rt
	s := &SwarmRunner{engine: e}
	var records []*httpmsg.HttpRequestResponse
	for i := range 5 {
		batch, err := agentinput.NormalizeInput(context.Background(), fmt.Sprintf("GET /batch-%d HTTP/1.1\r\nHost: example.test\r\n\r\n", i), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, batch...)
	}
	cfg := SwarmConfig{SessionDir: t.TempDir(), MaxMasterRetries: 1, BatchConcurrency: 5}
	cfg.ProgressCallback = func(event ProgressEvent) {
		if event.SubPhase == "batch" && event.Current == 2 {
			close(rt.committed) // root fails only after batch 2 really completed
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	plan, raw, _, prov, err := s.runMasterAgentBatched(ctx, cfg, records, "https://example.test", 1, "", "")
	if !errors.Is(err, root) || errors.Is(err, context.Canceled) || plan == nil || len(plan.FocusAreas) != 1 || prov == nil || prov.FocusAreas["/batch-1: native auth checks"] != 2 || !strings.Contains(raw, "partial root batch") {
		t.Fatalf("origin failure obscured or partial batch misrepresented: err=%v plan=%+v prov=%+v", err, plan, prov)
	}
	files, _ := filepath.Glob(filepath.Join(cfg.SessionDir, "plan-batches-*.json"))
	if len(files) != 1 {
		t.Fatal("batch completion ledger missing")
	}
	body, err = os.ReadFile(files[0])
	var ledger struct {
		Complete bool                   `json:"complete"`
		Batches  []planningBatchOutcome `json:"batches"`
		Partial  *SwarmPlan             `json:"partial_plan"`
	}
	if err != nil || json.Unmarshal(body, &ledger) != nil || ledger.Complete || len(ledger.Batches) != 5 || ledger.Partial == nil || len(ledger.Partial.FocusAreas) != 1 {
		t.Fatal("failed plan became a completed ledger or lost successful partial plan")
	}
	for i, outcome := range ledger.Batches {
		if outcome.Batch != i+1 || outcome.Start != i || outcome.End != i+1 {
			t.Fatal("cancelled batch identities/ranges changed")
		}
		want := "cancelled"
		if i == 1 {
			want = "completed"
		} else if i == 2 {
			want = "failed"
		}
		if outcome.Status != want && !(want == "cancelled" && outcome.Status == "not_started") {
			t.Fatalf("batch %d false completion: %s", outcome.Batch, outcome.Status)
		}
	}
	if files, _ := filepath.Glob(filepath.Join(cfg.SessionDir, "swarm-plan.json")); len(files) != 0 {
		t.Fatal("incomplete batch plan checkpointed as executable complete plan")
	}
}
