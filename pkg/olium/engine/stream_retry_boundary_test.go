package engine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// retryBoundaryProvider is entirely in-memory: its first attempt fails after
// exposing text/thinking and a parsed (but never executed) tool call.
type retryBoundaryProvider struct{ calls int }

func (*retryBoundaryProvider) Name() string { return "retry-boundary-test" }
func (p *retryBoundaryProvider) Stream(_ context.Context, _ provider.Request) (<-chan stream.Event, error) {
	p.calls++
	ch := make(chan stream.Event, 6)
	if p.calls == 1 {
		ch <- stream.Event{Type: stream.EventThinkingDelta, Delta: "abandoned reasoning"}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "abandoned text"}
		ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "abandoned", Name: "inspect"}}
		ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: "abandoned", Name: "inspect", Arguments: map[string]any{"path": "partial"}}}
		ch <- stream.Event{Type: stream.EventError, Err: "connection reset by peer"}
	} else {
		ch <- stream.Event{Type: stream.EventThinkingDelta, Delta: "recovered reasoning"}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "recovered text"}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop}
	}
	close(ch)
	return ch, nil
}

func TestEngineEvidenceStreamRetryBoundary(t *testing.T) {
	p := &retryBoundaryProvider{}
	rec := &captureRecorder{}
	eng := New(Config{Provider: p, Recorder: rec, RetryInitialBackoff: time.Millisecond})
	var events []Event
	for ev := range eng.Run(context.Background(), "test") {
		events = append(events, ev)
	}
	if p.calls != 2 {
		t.Fatalf("provider attempts=%d, want 2", p.calls)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !reflect.DeepEqual(events, rec.events) {
		t.Fatal("retry boundary was not teed in order")
	}
	retries, completed, boundary := 0, 0, -1
	for i, ev := range events {
		switch ev.Type {
		case EventError, EventToolExecStart, EventToolExecEnd:
			t.Fatalf("abandoned call executed or retry became terminal: %+v", ev)
		case EventStreamRetry:
			retries++
			boundary = i
			if ev.Attempt != 1 || ev.Err != "connection reset by peer" || len(ev.ToolCalls) != 1 || ev.ToolCalls[0].ID != "abandoned" || ev.ToolCalls[0].Arguments["path"] != "partial" {
				t.Fatalf("incomplete retry boundary: %+v", ev)
			}
		case EventThinkingDelta:
			if ev.Delta == "recovered reasoning" && boundary < 0 {
				t.Fatal("retry deltas arrived before boundary")
			}
		case EventRunDone:
			completed++
		}
	}
	if retries != 1 || completed != 1 {
		t.Fatalf("retry/run-done counts=%d/%d", retries, completed)
	}
	history := eng.History()
	if len(history) != 2 || history[1].Text != "recovered text" || len(history[1].ToolCalls) != 0 {
		t.Fatalf("failed attempt contaminated history: %+v", history)
	}
}
