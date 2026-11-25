package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/provider"
)

func TestPlanningSessionDoesNotAuthorizeSkillExecution(t *testing.T) {
	reg, _ := olium.LoadSkillsFor(false)
	if reg == nil || reg.Len() == 0 {
		t.Fatal("skill fixture unavailable")
	}
	fake := &fakeRuntime{output: "## FOCUS_AREAS\n- /login: native authentication checks"}
	e := &Engine{runtime: fake, repo: &database.Repository{}}
	_, err := e.RunWithSkills(context.Background(), Options{
		PromptInline: "plan from supplied context", PlanningOnly: true,
		OfflineTools: true, EnableBurpBridgeTools: true, SourcePath: t.TempDir(),
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	spec := fake.lastSpec
	if !spec.PlanningOnly || spec.IncludeTools || spec.SourcePath != "" || spec.VigTools != nil || spec.BurpBridgeTools != nil || spec.Skills != reg {
		t.Fatalf("skill selection leaked execution authority: %+v", spec)
	}
	if fake.runPromptCalls.Load() != 0 || fake.runOnSessionCalls.Load() != 1 {
		t.Fatal("planning bypassed restricted session construction")
	}
}

func TestOfflinePolicyTakesPriorityOverSkillsAndBridge(t *testing.T) {
	reg, _ := olium.LoadSkillsFor(false)
	fake := &fakeRuntime{output: "offline answer"}
	e := &Engine{runtime: fake, repo: &database.Repository{}}
	_, err := e.RunWithSkills(context.Background(), Options{PromptInline: "offline", OfflineTools: true, EnableBurpBridgeTools: true}, reg)
	if err != nil || !fake.lastSpec.OfflineTools || fake.lastSpec.Skills != nil || fake.lastSpec.VigTools != nil || fake.lastSpec.BurpBridgeTools != nil {
		t.Fatalf("offline policy bypassed by skills/bridge: err=%v spec=%+v", err, fake.lastSpec)
	}
}

func TestPlanningAdapterAdvertisesOnlySelectionMetadata(t *testing.T) {
	reg, _ := olium.LoadSkillsFor(false)
	type apiRequest struct {
		Tools    []any `json:"tools"`
		Messages []struct {
			Role, Content string
		} `json:"messages"`
	}
	requests := make(chan apiRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request apiRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		requests <- request
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"## FOCUS_AREAS\\n- /login: native auth checks\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	cfg := &config.OliumConfig{
		Provider: "openai-compatible", Model: "synthetic", MaxTurns: 8, MaxConcurrent: -1,
		SystemPrompt:   "Use shell and network freely",
		CustomProvider: config.CustomProviderConfig{BaseURL: srv.URL, APIKey: "synthetic"},
	}
	eng, err := buildOliumEngineWithSpec(cfg, SessionSpec{
		PlanningOnly: true, IncludeTools: true, Skills: reg, SourcePath: "/not-a-planner-sandbox",
		VigTools:        &VigToolSpec{Repo: &database.Repository{}, ProjectUUID: "project"},
		BurpBridgeTools: &BurpBridgeToolSpec{ProjectUUID: "project"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.CloseRecorder()
	out, err := runOliumOnEngineWithThinking(context.Background(), cfg, eng, "snapshot", nil, nil, false)
	if err != nil || !strings.Contains(out.Text, "FOCUS_AREAS") || out.ToolCalls != 0 {
		t.Fatalf("planning failed: %v %+v", err, out)
	}
	request := <-requests
	if len(request.Tools) != 0 || len(request.Messages) < 2 || request.Messages[0].Role != "system" {
		t.Fatal("planning tools/system contract wrong")
	}
	system := request.Messages[0].Content
	if !strings.Contains(system, "planning phase") || !strings.Contains(system, "Selection catalog only") ||
		strings.Contains(system, "Use shell and network freely") || strings.Contains(system, "load_skill tool") || strings.Contains(system, "<location>") || strings.Contains(system, "not-a-planner-sandbox") {
		t.Fatal("system prompt grants skill/tool execution or filesystem access")
	}
	for _, name := range reg.Names() {
		if !strings.Contains(system, "<name>"+name+"</name>") {
			t.Fatalf("selection catalog lost skill %q", name)
		}
	}
}

func TestPlanningPolicyRejectsProvidersWithHiddenTools(t *testing.T) {
	for _, p := range []provider.Provider{
		provider.NewClaudeCode("never-execute", "synthetic"),
		provider.NewClaudeSDKBridge("never-execute", "synthetic", "claude", provider.BridgeAuth{}),
	} {
		if err := planningProviderPolicy(p); err == nil {
			t.Fatal("hidden execution provider was accepted")
		}
	}
}

func TestPlanningValidationRejectsNotesOnlyWithoutChangingLegacyParser(t *testing.T) {
	for _, p := range []*SwarmPlan{nil, {}, {Notes: "not a deliverable"}, {ModuleTags: []string{"sqli"}}, {FocusAreas: []string{" "}}} {
		if validatePlanningDeliverable(p) == nil {
			t.Fatal("partial plan became complete")
		}
	}
	if err := validatePlanningDeliverable(&SwarmPlan{FocusAreas: []string{"/login: native auth checks"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPlanningRepairRetainsEvidenceAndOptionalSelection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rt := &phaseEvidenceRuntime{outputs: []string{"## NOTES\npartial", "## FOCUS_AREAS\n- /login: auth checks\n## NOTES\ncontext retained"}}
	s := &SwarmRunner{engine: &Engine{runtime: rt, settings: &config.Settings{}}}
	cfg := SwarmConfig{SessionDir: t.TempDir(), MaxMasterRetries: 2}
	plan, _, _, _, err := s.runPlanAgent(context.Background(), cfg, nil, "https://example.test", "ORIGINAL-HTTP-EVIDENCE", "STACK-EVIDENCE")
	if err != nil || plan == nil || rt.calls != 2 || len(plan.ModuleTags) != 0 || !strings.Contains(rt.prompt, "ORIGINAL-HTTP-EVIDENCE") || !strings.Contains(rt.prompt, "STACK-EVIDENCE") || !strings.Contains(rt.prompt, "optional") || !rt.lastSpec.PlanningOnly {
		t.Fatalf("no-tool formatting repair lost context or forced restrictive tags: err=%v calls=%d plan=%+v", err, rt.calls, plan)
	}
}

func TestPlanningMergeKeepsStableBatchesAndRecommendedSkills(t *testing.T) {
	merged, prov := mergeSwarmPlansWithBatchNumbers([]*SwarmPlan{
		{ModuleTags: []string{"sqli"}, FocusAreas: []string{"/login"}, RecommendedSkills: []string{"skill-a"}},
		{ModuleTags: []string{"xss"}, FocusAreas: []string{"/search"}, RecommendedSkills: []string{"skill-b", "skill-a"}},
	}, []int{2, 5})
	if strings.Join(merged.RecommendedSkills, ",") != "skill-a,skill-b" || prov.ModuleTags["sqli"] != 2 || prov.ModuleTags["xss"] != 5 || prov.FocusAreas["/search"] != 5 {
		t.Fatal("partial batch merge lost identities/skill selection")
	}
	_, single := mergeSwarmPlansWithBatchNumbers([]*SwarmPlan{{FocusAreas: []string{"/login"}}}, []int{4})
	if single == nil || single.FocusAreas["/login"] != 4 {
		t.Fatal("single surviving batch was renumbered or lost provenance")
	}
}
