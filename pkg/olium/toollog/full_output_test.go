package toollog

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestFullRuntimeLogHasCompleteArgumentsAndResultWithoutVerbose(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf).WithFullOutput(t.TempDir())
	command := "cd /synthetic && fetch \"https://example.test/" + strings.Repeat("long-path-", 1000) + "main.js\"\nprintf 'done'"
	args := map[string]any{"command": command, "timeout_seconds": 123}
	result := strings.Repeat("output line\n", 1000) + "LAST-RESULT-BYTE"
	l.HandleTool(engine.Event{Type: engine.EventToolExecStart, ToolCallID: "call", ToolName: "bash", ToolArgs: args})
	l.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: "call", ToolName: "bash", ToolResult: result})
	out := buf.String()
	if !strings.Contains(out, command) || !strings.Contains(out, result) || !strings.Contains(out, "123") || strings.Contains(out, "▶ bash command=") || strings.Contains(out, "✓ ") || strings.Contains(out, "… head") {
		t.Fatal("full log still contains abbreviated arguments/results")
	}
	if args["command"] != command || l.Err() != nil {
		t.Fatal("logger mutated source arguments or reported a render failure")
	}
}

func TestFullRuntimeLogPreservesWholeFailedToolResult(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf).WithFullOutput(t.TempDir())
	result := "first failure\n" + strings.Repeat("partial evidence\n", 300) + "last failure"
	l.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: "failed", ToolName: "synthetic", ToolIsErr: true, ToolResult: result})
	if !strings.Contains(buf.String(), result) || !strings.Contains(buf.String(), "failed") || strings.Contains(buf.String(), "✗ failed:") {
		t.Fatal("failed tool result replaced with a one-line reason")
	}
}

func TestFullRuntimeLogCopiesRawBashPastThePreviewCapAndBinaryBytes(t *testing.T) {
	dir := t.TempDir()
	a, err := tool.NewCallArchive(dir, "call", "bash", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	stdout := bytes.Repeat([]byte("0123456789\n"), 100000)
	stdout = append(stdout, []byte("RAW-TAIL-BEYOND-CAP")...)
	stderr := []byte{0, 0xff, 0xfe, '\r', '\n'}
	a.WriteStream("stdout", stdout)
	a.WriteStream("stderr", stderr)
	res := tool.Result{Content: "capped preview; not full stdout"}
	receipt := a.Finish(res)
	var buf bytes.Buffer
	l := New(&buf).WithFullOutput(dir)
	l.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolName: "bash", ToolDetails: map[string]any{tool.ArchiveDetailsKey: receipt}, ToolResult: res.Content})
	if !bytes.Contains(buf.Bytes(), stdout) || !bytes.Contains(buf.Bytes(), stderr) || strings.Contains(buf.String(), res.Content) || l.Err() != nil {
		t.Fatal("full runtime log used capped preview or changed raw stream bytes")
	}
}

func TestFullRuntimeLogMissingStreamIsVisibleWithoutReplacement(t *testing.T) {
	dir := t.TempDir()
	a, err := tool.NewCallArchive(dir, "call", "bash", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	a.WriteStream("stdout", []byte("stored"))
	a.WriteStream("stderr", nil)
	receipt := a.Finish(tool.Result{})
	streams := receipt["streams"].(map[string]any)
	path := streams["stdout"].(map[string]any)["path"].(string)
	if err := os.Remove(filepath.Join(dir, filepath.FromSlash(path))); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	l := New(&buf).WithFullOutput(dir)
	l.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolName: "bash", ToolResult: "DO-NOT-FABRICATE-RAW", ToolDetails: map[string]any{tool.ArchiveDetailsKey: receipt}})
	if l.Err() == nil || !strings.Contains(buf.String(), "unavailable, unreadable or changed") || strings.Contains(buf.String(), "DO-NOT-FABRICATE-RAW") {
		t.Fatal("missing stream silently replaced by a preview")
	}
}

func TestFullLogArchivePathRejectsEscapesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"/etc/passwd", "../outside", "tool-archive/not-a-uuid/stdout.bin", "tool-archive/00000000-0000-0000-0000-000000000000/other.bin"} {
		if copyFullArtifact(io.Discard, dir, path, "stdout.bin", map[string]any{"stored_bytes": int64(12), "sha256": strings.Repeat("0", 64)}) == nil {
			t.Fatal("untrusted archive path accepted")
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("not evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := "tool-archive/00000000-0000-0000-0000-000000000000/stdout.bin"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, path)); err != nil {
		t.Skip("symlinks unavailable")
	}
	if copyFullArtifact(io.Discard, dir, path, "stdout.bin", map[string]any{"stored_bytes": int64(12), "sha256": strings.Repeat("0", 64)}) == nil {
		t.Fatal("symlinked archive accepted")
	}
}

type fullLogFailWriter struct{}

func (fullLogFailWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic write failure") }

func TestFullRuntimeLogWriterFailureIsSticky(t *testing.T) {
	l := New(fullLogFailWriter{}).WithFullOutput(t.TempDir())
	l.HandleTool(engine.Event{Type: engine.EventToolExecStart, ToolName: "synthetic"})
	l.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolName: "synthetic", ToolResult: "result"})
	if l.Err() == nil {
		t.Fatal("write failure concealed")
	}
	// Explicit opt-out retains the old unrecorded operator format.
	var buf bytes.Buffer
	New(&buf).WithFullOutput("").HandleTool(engine.Event{Type: engine.EventToolExecStart, ToolName: "synthetic"})
	if !strings.Contains(buf.String(), "▶ synthetic") {
		t.Fatal("empty archive root changed unrecorded console behavior")
	}
}
