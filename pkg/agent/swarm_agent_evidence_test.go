package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/olium"
)

type phaseEvidenceContextKey struct{}
type phaseEvidenceRuntime struct {
	fakeRuntime
	err                error
	ctx                context.Context
	prompt, sourcePath string
	record             RecordSpec
	calls              int
	outputs            []string
}

func (f *phaseEvidenceRuntime) next(ctx context.Context, prompt string) (oliumRunOutput, error) {
	f.ctx, f.prompt = ctx, prompt
	output := f.output
	if len(f.outputs) > f.calls {
		output = f.outputs[f.calls]
	}
	f.calls++
	return oliumRunOutput{Text: output}, f.err
}
func (f *phaseEvidenceRuntime) RunPrompt(ctx context.Context, _ *config.OliumConfig, prompt string, _, _ io.Writer, sourcePath string, _ bool, rec RecordSpec) (oliumRunOutput, error) {
	f.sourcePath, f.record = sourcePath, rec
	return f.next(ctx, prompt)
}
func (f *phaseEvidenceRuntime) RunOnSession(ctx context.Context, _ *config.OliumConfig, _ AgentSession, prompt string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	f.sourcePath, f.record = f.lastSpec.SourcePath, f.lastSpec.Record
	return f.next(ctx, prompt)
}

func TestSwarmEvidencePhaseWiringAndFailedResponse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, phase := range []string{"plan", "plan_with_skills", "extension"} {
		t.Run(phase, func(t *testing.T) {
			partial := strings.Repeat("partial response\n", 10000)
			failure := errors.New("provider 401: unavailable credentials")
			rt := &phaseEvidenceRuntime{fakeRuntime: fakeRuntime{output: partial}, err: failure}
			s := &SwarmRunner{engine: &Engine{runtime: rt, settings: &config.Settings{}}}
			if phase == "plan_with_skills" {
				s.skills, _ = olium.LoadSkillsFor(false)
			}
			var sink bytes.Buffer
			cfg := SwarmConfig{SessionDir: t.TempDir(), SourcePath: t.TempDir(), Instruction: "INSTRUCTION-EVIDENCE", ProjectUUID: "project-evidence", ScanUUID: "scan-evidence", MaxMasterRetries: 1, StreamWriter: &sink}
			ctx := context.WithValue(context.Background(), phaseEvidenceContextKey{}, "request-context")
			var plan *SwarmPlan
			var raw, prompt string
			var err error
			if phase == "extension" {
				plan, _, raw, prompt, err = s.runExtensionAgent(ctx, cfg, nil, "https://example.test", &SwarmPlan{ModuleTags: []string{"sqli"}}, "REQUEST-EVIDENCE", "TECH-EVIDENCE")
			} else {
				plan, _, raw, prompt, err = s.runPlanAgent(ctx, cfg, nil, "https://example.test", "REQUEST-EVIDENCE", "TECH-EVIDENCE")
			}
			if plan != nil || !errors.Is(err, failure) || raw != partial || prompt == "" {
				t.Fatalf("failed partial response discarded or accepted as plan: %v, %d, %v", plan, len(raw), err)
			}
			wantSource := cfg.SourcePath
			if phase != "extension" {
				wantSource = "" // planning sees supplied context, not filesystem tools
				if !rt.lastSpec.PlanningOnly || rt.lastSpec.IncludeTools || rt.lastSpec.VigTools != nil {
					t.Fatal("plan session leaked execution capabilities")
				}
			}
			if rt.ctx.Value(phaseEvidenceContextKey{}) != "request-context" || rt.record.SessionDir != cfg.SessionDir || rt.record.Template == "" || rt.sourcePath != wantSource {
				t.Fatalf("context/recording not wired: %+v", rt.record)
			}
			if !strings.Contains(rt.prompt, "REQUEST-EVIDENCE") || !strings.Contains(rt.prompt, "INSTRUCTION-EVIDENCE") {
				t.Fatal("phase evidence context missing")
			}
			// The extension template consumes PlanContext, not TechStack; the
			// plan template renders the supplied recon context.
			if phase != "extension" && !strings.Contains(rt.prompt, "TECH-EVIDENCE") {
				t.Fatal("plan recon context missing")
			}
			if phase == "extension" && !strings.Contains(rt.prompt, "sqli") {
				t.Fatal("extension plan context missing")
			}
			if rt.calls != 1 {
				t.Fatalf("terminal runtime failure retried %d times", rt.calls)
			}
			files, _ := filepath.Glob(filepath.Join(cfg.SessionDir, "failed-*-attempt-*.json"))
			if len(files) != 1 {
				t.Fatalf("failed attempt not durable: %v", files)
			}
			body, readErr := os.ReadFile(files[0])
			var artifact map[string]any
			if readErr != nil || json.Unmarshal(body, &artifact) != nil || artifact["raw_output"] != partial || artifact["rendered_prompt"] != prompt || artifact["status"] != "execution_failed" {
				t.Fatal("failed attempt artifact lost fidelity/status")
			}
			info, _ := os.Stat(files[0])
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatal("partial attempt artifact not protected")
			}
			if strings.Contains(sink.String(), "partial response") {
				t.Fatal("failed response dumped into general runtime metadata")
			}
		})
	}
}

func TestSwarmEvidenceInvalidPlanAttemptsPreserved(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rt := &phaseEvidenceRuntime{outputs: []string{"not a plan", "still not a plan"}}
	s := &SwarmRunner{engine: &Engine{runtime: rt, settings: &config.Settings{}}}
	cfg := SwarmConfig{SessionDir: t.TempDir(), MaxMasterRetries: 2}
	plan, _, raw, _, err := s.runPlanAgent(context.Background(), cfg, nil, "https://example.test", "context", "")
	if err == nil || plan != nil || raw != "still not a plan" {
		t.Fatal("unparseable output should remain failed evidence, not a valid plan")
	}
	files, _ := filepath.Glob(filepath.Join(cfg.SessionDir, "failed-plan-attempt-*.json"))
	if len(files) != 2 {
		t.Fatalf("retry overwrote prior failed attempt: %v", files)
	}
}

func TestSwarmEvidenceCancelledExtensionDoesNotOuterRetry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rt := &phaseEvidenceRuntime{fakeRuntime: fakeRuntime{output: "partial extension"}, err: context.Canceled}
	s := &SwarmRunner{engine: &Engine{runtime: rt, settings: &config.Settings{}}}
	cfg := SwarmConfig{SessionDir: t.TempDir()}
	plan, raw, err := s.runExtensionAgentWithRetry(context.Background(), cfg, nil, "https://example.test", &SwarmPlan{}, "", "")
	if plan != nil || raw != "partial extension" || !errors.Is(err, context.Canceled) || rt.calls != 1 {
		t.Fatalf("cancelled extension retried/discarded: plan=%v raw=%q calls=%d err=%v", plan, raw, rt.calls, err)
	}
}

func TestSwarmEvidenceFailedBatchOutputNotDiscarded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rt := &phaseEvidenceRuntime{fakeRuntime: fakeRuntime{output: "partial batch plan"}, err: errors.New("provider 401: unavailable credentials")}
	s := &SwarmRunner{engine: &Engine{runtime: rt, settings: &config.Settings{}}}
	records, err := agentinput.NormalizeInput(context.Background(), "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := SwarmConfig{SessionDir: t.TempDir(), MaxMasterRetries: 1, BatchConcurrency: 1}
	plan, raw, prompt, _, err := s.runMasterAgentBatched(context.Background(), cfg, records, "https://example.test", 1, "", "")
	if err == nil || plan != nil || prompt == "" || !strings.Contains(raw, "partial batch plan") || !strings.Contains(raw, "failed; partial/unvalidated output") {
		t.Fatalf("batch failure lost or legitimized evidence: plan=%v raw=%q err=%v", plan, raw, err)
	}
}

func TestSwarmEvidenceArtifactFailureWarnsWithoutPayload(t *testing.T) {
	var sink bytes.Buffer
	cfg := SwarmConfig{SessionDir: filepath.Join(t.TempDir(), "missing"), StreamWriter: &sink}
	persistFailedPhaseAttempt(cfg, "plan", 1, "execution_failed", &Result{RawOutput: "PRIVATE-OUTPUT", RenderedPrompt: "PRIVATE-PROMPT"}, errors.New("PRIVATE-ERROR"))
	if !strings.Contains(sink.String(), "Evidence degraded") || strings.Contains(sink.String(), "PRIVATE") {
		t.Fatal("artifact failure missing safe degraded warning")
	}
}
