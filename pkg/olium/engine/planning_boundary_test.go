package engine

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// Script the old 32-turn/44-call shape using inert tools, never real shell,
// network or replay implementations. A conforming provider synthesizes instead
// when the request disables tools; an uncooperative one keeps emitting calls.
type planningBoundaryProvider struct {
	calls    int
	callPos  int
	conform  bool
	name     string
	final    string
	stop     stream.StopReason
	requests []provider.Request
}

func (p *planningBoundaryProvider) Name() string {
	if p.name != "" {
		return p.name
	}
	return "synthetic-planning"
}
func (p *planningBoundaryProvider) Stream(_ context.Context, req provider.Request) (<-chan stream.Event, error) {
	p.calls++
	p.requests = append(p.requests, req)
	ch := make(chan stream.Event, 6)
	if p.conform && len(req.Tools) == 0 {
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: p.final}
		ch <- stream.Event{Type: stream.EventDone, StopReason: p.stop}
	} else {
		n := 1
		if p.calls <= 12 {
			n = 2
		}
		for range n {
			name := "bash"
			switch p.callPos {
			case 0, 1:
				name = "replay_request"
			case 2, 3:
				name = "inspect_record"
			case 4, 5:
				name = "web_fetch"
			case 6:
				name = "query_records"
			}
			id := fmt.Sprintf("synthetic-%d", p.callPos)
			p.callPos++
			ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: id, Name: name}}
			ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: id, Name: name, Arguments: map[string]any{}}}
		}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse}
	}
	close(ch)
	return ch, nil
}

type planningInertTool struct {
	fakeTool
	calls atomic.Int32
}

func (t *planningInertTool) Execute(context.Context, map[string]any, tool.UpdateFn) (tool.Result, error) {
	t.calls.Add(1)
	return tool.Result{Content: "inert"}, nil
}

func TestPlanningBoundaryPreventsOld32TurnInvestigation(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		t.Run(fmt.Sprintf("restricted-%t", restricted), func(t *testing.T) {
			p := &planningBoundaryProvider{}
			reg := tool.NewRegistry()
			tools := []*planningInertTool{}
			for _, name := range []string{"bash", "replay_request", "inspect_record", "web_fetch", "query_records"} {
				t := &planningInertTool{fakeTool: fakeTool{name: name}}
				reg.Register(t)
				tools = append(tools, t)
			}
			eng := New(Config{Provider: p, Tools: reg, MaxTurns: 32, DisableTools: restricted, RequireFinalAnswer: restricted})
			var terminal Event
			for ev := range eng.Run(context.Background(), "supplied snapshot") {
				if ev.Type == EventError {
					terminal = ev
				}
			}
			if restricted {
				if p.calls != 1 || len(p.requests[0].Tools) != 0 || !strings.Contains(terminal.Err, "disabled") || eng.ToolCallCount() != 0 {
					t.Fatalf("planning boundary failed: streams=%d terminal=%+v dispatched=%d", p.calls, terminal, eng.ToolCallCount())
				}
				for _, tool := range tools {
					if tool.calls.Load() != 0 {
						t.Fatal("forbidden tool implementation executed")
					}
				}
			} else if p.calls != 32 || eng.ToolCallCount() != 44 || !terminal.BudgetExhausted {
				t.Fatalf("old failure fixture changed: streams=%d calls=%d terminal=%+v", p.calls, eng.ToolCallCount(), terminal)
			}
		})
	}
}

func TestPlanningBoundaryRequiresCompleteFinalAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		stop       stream.StopReason
		wantDone   bool
	}{
		{"final", "## FOCUS_AREAS\n- /login: authentication tests for native scanning", stream.StopReasonStop, true},
		{"empty", "  ", stream.StopReasonStop, false},
		{"truncated", "## FOCUS_AREAS\n- incomplete", stream.StopReasonLength, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &planningBoundaryProvider{conform: true, final: tc.text, stop: tc.stop}
			eng := New(Config{Provider: p, DisableTools: true, RequireFinalAnswer: true, MaxTurns: 32})
			done, failed := false, false
			for ev := range eng.Run(context.Background(), "snapshot") {
				done = done || ev.Type == EventRunDone
				failed = failed || ev.Type == EventError
			}
			if done != tc.wantDone || failed == tc.wantDone || p.calls != 1 {
				t.Fatalf("incomplete answer became completion: done=%t failed=%t streams=%d", done, failed, p.calls)
			}
		})
	}
}

func TestPlanningBoundaryRejectsHiddenToolProvidersBeforeStreaming(t *testing.T) {
	for _, name := range []string{"claude-code", "claude-sdk-bridge"} {
		p := &planningBoundaryProvider{name: name}
		eng := New(Config{Provider: p, DisableTools: true})
		failed := false
		for ev := range eng.Run(context.Background(), "snapshot") {
			failed = failed || ev.Type == EventError
		}
		if !failed || p.calls != 0 {
			t.Fatalf("hidden tool provider started: name=%s streams=%d", name, p.calls)
		}
	}
}
