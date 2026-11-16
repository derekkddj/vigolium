package toollog

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestLoggerDistinguishesAbbreviatedArgsReturnedBytesAndRawArchive(t *testing.T) {
	disableColor(t)
	var buf bytes.Buffer
	l := New(&buf)
	command := strings.Repeat("synthetic command ", 20)
	l.Handle(engine.Event{Type: engine.EventToolExecStart, ToolCallID: "call", ToolName: "bash", ToolArgs: map[string]any{"command": command}})
	path := "tool-archive/01234567-89ab-cdef-0123-456789abcdef"
	l.Handle(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: "call", ToolName: "bash", ToolResult: strings.Repeat("p", 190), ToolDetails: map[string]any{
		tool.ArchiveDetailsKey: map[string]any{"complete": true, "path": path, "streams": map[string]any{
			"stdout": map[string]any{"stored_bytes": int64(2097152)},
			"stderr": map[string]any{"stored_bytes": float64(4)},
		}},
	}})
	out := buf.String()
	if strings.Contains(out, command) || !strings.Contains(out, "…") {
		t.Fatal("operator argument card stopped being abbreviated")
	}
	for _, want := range []string{"✓ 190 bytes", "archive complete: " + path, "raw stdout=2097152 bytes, stderr=4 bytes"} {
		if !strings.Contains(out, want) {
			t.Fatal("operator log confused returned payload with raw retention")
		}
	}
}

func TestLoggerArchiveFailureIsVisibleEvenOnToolErrorWithoutEvidenceDump(t *testing.T) {
	disableColor(t)
	var buf bytes.Buffer
	l := New(&buf)
	l.Handle(engine.Event{Type: engine.EventToolExecEnd, ToolName: "bash", ToolResult: "handled error", ToolIsErr: true, ToolDetails: map[string]any{
		tool.ArchiveDetailsKey: map[string]any{"complete": false, "path": "private-value", "error": "synthetic-sensitive-error", "output": "synthetic-sensitive-output"},
	}})
	out := buf.String()
	if !strings.Contains(out, "archive incomplete") || !strings.Contains(out, "failed: handled error") {
		t.Fatal("failure result hid degraded archive health")
	}
	if strings.Contains(out, "synthetic-sensitive") || strings.Contains(out, "private-value") {
		t.Fatal("operator archive status leaked private receipt material")
	}
}

func TestArchiveLabelsRejectToolControlledAndAbsolutePaths(t *testing.T) {
	for _, path := range []string{
		"/private/session/tool-archive/01234567-89ab-cdef-0123-456789abcdef",
		"tool-archive/../../private-value",
		"tool-archive/01234567-89ab-cdef-0123-456789abcde\n",
		"tool-archive/01234567-89ab-cdef-0123-456789abcdef/more",
	} {
		if safeArchiveLabel(path) {
			t.Fatal("unsafe metadata label accepted")
		}
	}
}
