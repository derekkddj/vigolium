package sessionlog

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestRecorderArchiveReceiptHydratesExactBinaryWithoutExpandingPreview(t *testing.T) {
	dir := t.TempDir()
	r, err := New(filepath.Join(dir, Filename), Meta{})
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Repeat("synthetic full parameter\n", 1000)
	args := map[string]any{"command": command}
	r.Record(engine.Event{Type: engine.EventTurnDone, ToolCalls: []stream.ToolCall{{ID: "call", Name: "bash", Arguments: args}}})
	binary := []byte{0, 0xff, 0xfe, '\r', '\n'}
	res := tool.ArchiveExecution(context.Background(), dir, "call", "bash", args, func(context.Context) tool.Result {
		return tool.Result{Content: string(binary), Details: map[string]any{"record_uuid": "record", "raw_blob": binary}}
	})
	r.Record(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: "call", ToolName: "bash", ToolResult: res.Content, ToolDetails: res.Details})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(dir, Filename))
	if len(lines) != 5 {
		t.Fatal("unexpected transcript envelope count")
	}
	call := msgBody(t, lines[3])["content"].([]any)[0].(map[string]any)
	if call["arguments"].(map[string]any)["command"] != command {
		t.Fatal("UI-sized abbreviation leaked into full transcript parameters")
	}
	details := msgBody(t, lines[4])["details"].(map[string]any)
	if details["record_uuid"] != "record" || details["raw_blob"] != base64.StdEncoding.EncodeToString(binary) {
		t.Fatal("existing BLOB/base64 receipt contract changed")
	}
	receipt := details[tool.ArchiveDetailsKey].(map[string]any)
	if receipt["complete"] != true {
		t.Fatal("durable archive receipt not preserved in transcript")
	}
	// JSON text is not canonical for invalid UTF-8. Hydrate the exact raw
	// bytes from the private artifact pointer, not a fabricated reconstruction.
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(receipt["result"].(string))))
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("archive hydration changed bytes: bytes=%d err=%v", len(got), err)
	}
	assertLinearChain(t, lines)
}

func TestRecorderPreservesDegradedArchiveReceiptWithoutInventingHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	r, err := New(path, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	r.Record(engine.Event{
		Type: engine.EventToolExecEnd, ToolName: "bash", ToolCallID: "old-call",
		ToolResult:  "historical capped preview",
		ToolDetails: map[string]any{tool.ArchiveDetailsKey: map[string]any{"version": 1, "complete": false, "status": "failed", "error": "initialization_failed"}},
	})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	body := msgBody(t, readLines(t, path)[3])
	receipt := body["details"].(map[string]any)[tool.ArchiveDetailsKey].(map[string]any)
	if receipt["complete"] != false || firstPartText(t, body) != "historical capped preview" {
		t.Fatal("degraded archive changed historical evidence")
	}
	if _, invented := receipt["result"]; invented {
		t.Fatal("missing historical result bytes fabricated")
	}
}
