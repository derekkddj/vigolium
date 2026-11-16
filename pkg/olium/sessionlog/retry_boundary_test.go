package sessionlog

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

func TestRecorderEvidenceRetryBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	r, err := New(path, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	r.UserPrompt("inspect")
	r.Record(engine.Event{Type: engine.EventThinkingDelta, Delta: "partial reasoning"})
	r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "partial text"})
	r.Record(engine.Event{Type: engine.EventStreamRetry, Attempt: 1, Err: "connection reset", ToolCalls: []stream.ToolCall{{ID: "not-executed", Name: "inspect", Arguments: map[string]any{"path": "partial"}}}})
	r.Record(engine.Event{Type: engine.EventThinkingDelta, Delta: "recovered reasoning"})
	r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "recovered text"})
	r.Record(engine.Event{Type: engine.EventTurnDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{Input: 10, Output: 2}})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	if len(lines) != 7 {
		t.Fatalf("want header, user, partial, retry, success: %+v", lines)
	}
	partial := msgBody(t, lines[4])
	parts := partial["content"].([]any)
	if partial["stopReason"] != "interrupted" || parts[0].(map[string]any)["thinking"] != "partial reasoning" || parts[1].(map[string]any)["text"] != "partial text" || parts[2].(map[string]any)["id"] != "not-executed" {
		t.Fatalf("abandoned output not retained as partial: %+v", partial)
	}
	if _, ok := partial["usage"]; ok {
		t.Fatal("successful attempt's usage attributed to abandoned attempt")
	}
	if lines[5]["type"] != "stream_retry" || lines[5]["attempt"] != float64(1) || lines[5]["error"] != "connection reset" {
		t.Fatalf("nonterminal retry boundary missing: %+v", lines[5])
	}
	success := msgBody(t, lines[6])
	successParts := success["content"].([]any)
	if success["stopReason"] != "stop" || successParts[0].(map[string]any)["thinking"] != "recovered reasoning" || successParts[1].(map[string]any)["text"] != "recovered text" {
		t.Fatalf("retry attempts merged: %+v", success)
	}
	for _, line := range lines {
		if line["type"] == "error" {
			t.Fatal("recovered retry recorded as terminal run failure")
		}
	}
	assertLinearChain(t, lines)
}

func TestRecorderEvidenceRetryBoundaryStickyFailure(t *testing.T) {
	boom := errors.New("failed retry line")
	// Header consumes 3 writes; partial assistant is 4, boundary is 5.
	for _, failAt := range []int{4, 5} {
		f := &faultTranscriptFile{failAt: failAt, short: true, writeErr: boom}
		r, err := newWithFile(f, Meta{})
		if err != nil {
			t.Fatal(err)
		}
		r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "partial"})
		r.Record(engine.Event{Type: engine.EventStreamRetry, Attempt: 1, Err: "connection reset"})
		parent := r.lastID
		r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "recovered"})
		r.Record(engine.Event{Type: engine.EventTurnDone, StopReason: stream.StopReasonStop})
		if !errors.Is(r.Err(), boom) || r.lastID != parent || f.writes != failAt || !errors.Is(r.Close(), boom) {
			t.Fatalf("retry line failure advanced state or hid error: failAt=%d writes=%d err=%v", failAt, f.writes, r.Err())
		}
	}
}
