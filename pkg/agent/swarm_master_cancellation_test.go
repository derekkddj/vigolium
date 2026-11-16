package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
	"github.com/vigolium/vigolium/pkg/olium"
)

const masterCancellationPlanOutput = "## FOCUS_AREAS\n- SQL injection parameters on /login\n\n## MODULE_TAGS\nsqli\n\n## NOTES\nvalid original plan\n"

type masterCancellationRuntime struct {
	fakeRuntime
	calls        int
	prompts      []string
	configs      []*config.OliumConfig
	extensionErr func(context.Context) error
}

func (r *masterCancellationRuntime) next(ctx context.Context, cfg *config.OliumConfig, prompt string) (oliumRunOutput, error) {
	r.calls++
	r.prompts = append(r.prompts, prompt)
	r.configs = append(r.configs, cfg)
	if r.calls == 1 {
		return oliumRunOutput{Text: masterCancellationPlanOutput}, nil
	}
	return oliumRunOutput{Text: "partial extension"}, r.extensionErr(ctx)
}

func (r *masterCancellationRuntime) RunPrompt(ctx context.Context, cfg *config.OliumConfig, prompt string, _, _ io.Writer, _ string, _ bool, _ RecordSpec) (oliumRunOutput, error) {
	r.runPromptCalls.Add(1)
	return r.next(ctx, cfg, prompt)
}

func (r *masterCancellationRuntime) RunOnSession(ctx context.Context, cfg *config.OliumConfig, _ AgentSession, prompt string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	r.runOnSessionCalls.Add(1)
	return r.next(ctx, cfg, prompt)
}

func newMasterCancellationRunner(t *testing.T, rt *masterCancellationRuntime) *SwarmRunner {
	t.Helper()
	settings := &config.Settings{}
	settings.Agent.TemplatesDir = t.TempDir()
	// Use real embedded templates in a unique configured directory: neither
	// HOME overrides nor other tests' default-key template cache can affect us.
	for _, id := range []string{SwarmPromptPlan, SwarmPromptExtensions} {
		body, err := agentprompt.ReadEmbeddedTemplate(id + ".md")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(settings.Agent.TemplatesDir, id+".md"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := NewEngine(settings, nil)
	e.runtime = rt
	return &SwarmRunner{engine: e}
}

func TestSwarmEvidenceMasterPropagatesExtensionCancellation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	skills, err := olium.LoadSkillsFor(false)
	if err != nil || skills == nil || skills.Len() == 0 {
		t.Fatalf("embedded skills fixture unavailable: %v", err)
	}
	for _, dispatch := range []string{"plain", "skills"} {
		for _, kind := range []string{"parent_canceled", "parent_deadline", "provider_canceled"} {
			t.Run(dispatch+"/"+kind, func(t *testing.T) {
				// Virtual time advances only when blocked on ctx.Done in the
				// extension fixture, never while building the plan prompt.
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					want := context.Canceled
					if kind == "parent_deadline" {
						cancel()
						ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
						want = context.DeadlineExceeded
					}
					defer cancel()
					rt := &masterCancellationRuntime{extensionErr: func(ctx context.Context) error {
						if kind == "parent_canceled" {
							cancel()
							return ctx.Err()
						}
						if kind == "parent_deadline" {
							<-ctx.Done()
							return ctx.Err()
						}
						return context.Canceled
					}}
					s := newMasterCancellationRunner(t, rt)
					if dispatch == "skills" {
						s.skills = skills
					}
					cfg := SwarmConfig{SessionDir: t.TempDir(), ForceExtensions: true, MaxMasterRetries: 1}
					plan, raw, prompt, err := s.runMasterAgent(ctx, cfg, nil, "https://example.test", "")
					if plan != nil || !errors.Is(err, want) || rt.calls != 2 {
						t.Fatalf("cancelled extension became successful plan or retried: plan=%v calls=%d err=%v", plan, rt.calls, err)
					}
					if kind == "provider_canceled" && ctx.Err() != nil || kind != "provider_canceled" && !errors.Is(ctx.Err(), want) {
						t.Fatalf("fixture did not exercise intended parent context: %v", ctx.Err())
					}
					if prompt == "" || prompt != rt.prompts[0] || !strings.Contains(prompt, "https://example.test") || !strings.HasPrefix(raw, masterCancellationPlanOutput) || !strings.Contains(raw, "partial extension") || !strings.Contains(raw, "failed; partial/unvalidated output") {
						t.Fatal("master cancellation lost original plan/partial extension evidence")
					}
					for _, cfg := range rt.configs {
						if cfg == nil {
							t.Fatal("injected runtime did not receive engine configuration")
						}
					}
					wantSessions := int32(1) // every plan uses the restricted session
					if !rt.lastSpec.PlanningOnly || rt.lastSpec.IncludeTools || rt.lastSpec.VigTools != nil {
						t.Fatal("planning gained execution tools")
					}
					if dispatch == "skills" && rt.lastSpec.Skills != skills {
						t.Fatal("plan selection catalog was lost")
					}
					if rt.runPromptCalls.Load() != 2-wantSessions || rt.runOnSessionCalls.Load() != wantSessions || rt.sessionCalls.Load() != wantSessions {
						t.Fatal("master bypassed the injected runtime dispatch path")
					}
				})
			})
		}
	}
}

func TestSwarmEvidenceMasterOrdinaryExtensionFailureStillDegrades(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	failure := errors.New("provider 401: fixture failure")
	rt := &masterCancellationRuntime{extensionErr: func(context.Context) error { return failure }}
	s := newMasterCancellationRunner(t, rt)
	cfg := SwarmConfig{SessionDir: t.TempDir(), ForceExtensions: true, MaxMasterRetries: 1}
	plan, raw, prompt, err := s.runMasterAgent(context.Background(), cfg, nil, "https://example.test", "")
	if err != nil || plan == nil || plan.ExtensionAgentError == "" || len(plan.ModuleTags) != 1 || plan.ModuleTags[0] != "sqli" || !strings.HasPrefix(raw, masterCancellationPlanOutput) || !strings.Contains(raw, "partial extension") || prompt == "" || rt.calls != 4 {
		t.Fatalf("ordinary optional extension failure no longer degrades gracefully: plan=%+v calls=%d err=%v", plan, rt.calls, err)
	}
}

func TestEngineEvidenceNamedTemplateWithoutSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// A unique ID avoids the shared default-directory cache altogether.
	id := "nil-settings-" + filepath.Base(filepath.Dir(home))
	dir := filepath.Join(home, ".vigolium", "prompts")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := "---\nid: " + id + "\nvariables: [TargetURL]\n---\nNamed template for {{.TargetURL}}"
	if err := os.WriteFile(filepath.Join(dir, id+".md"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{output: "injected runtime answer"}
	e := &Engine{runtime: rt}
	result, err := e.Run(context.Background(), Options{PromptTemplate: id, TargetURL: "https://example.test"})
	if err != nil || result == nil {
		t.Fatalf("named template with optional settings omitted: result=%v err=%v", result, err)
	}
	if result.RenderedPrompt != "Named template for https://example.test" || result.TemplateID != id || result.RawOutput != rt.output || rt.runPromptCalls.Load() != 1 {
		t.Fatalf("named template did not render and dispatch through injected runtime: %+v", result)
	}
}
