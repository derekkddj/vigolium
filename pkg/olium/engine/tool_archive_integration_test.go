package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestEngineArchivesBashRawOutputBeforeBothModelCaps(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	dir := t.TempDir()
	reg := tool.NewRegistry()
	reg.Register(tool.NewBash(nil))
	eng := New(Config{Tools: reg, SpillDir: dir, MaxToolResultBytes: 1024})
	command := "printf '%1048615s' x; printf '\\000\\377\\015\\012' >&2 # " + strings.Repeat("synthetic argument ", 1000)
	tc := provider.ToolCall{ID: "reused/unsafe-id", Name: "bash", Args: map[string]any{"command": command}}
	ch := make(chan Event, 128)
	eng.dispatchAndRecord(context.Background(), tc, ch)
	close(ch)
	var result Event
	for ev := range ch {
		if ev.Type == EventToolExecEnd {
			result = ev
		}
	}
	receipt, _ := result.ToolDetails[tool.ArchiveDetailsKey].(map[string]any)
	if receipt["complete"] != true || result.ToolIsErr {
		t.Fatal("raw archive incomplete")
	}
	streams := receipt["streams"].(map[string]any)
	stdout := streams["stdout"].(map[string]any)
	stderr := streams["stderr"].(map[string]any)
	combined := streams["combined"].(map[string]any)
	if stdout["stored_bytes"] != int64(1048615) || stderr["stored_bytes"] != int64(4) || combined["stored_bytes"] != int64(1048619) {
		t.Fatal("raw stdout/stderr clipped to model or shell preview cap")
	}
	body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(stderr["path"].(string))))
	if err != nil || !bytes.Equal(body, []byte{0, 0xff, '\r', '\n'}) {
		t.Fatal("binary stderr bytes changed")
	}
	body, err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(receipt["arguments"].(string))))
	var args struct {
		Arguments map[string]any `json:"arguments"`
	}
	if err != nil || json.Unmarshal(body, &args) != nil || args.Arguments["command"] != command {
		t.Fatal("full command parameters lost")
	}
	body, err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(receipt["result"].(string))))
	if err != nil || string(body) != result.ToolResult {
		t.Fatal("operator tool-returned result differs from pre-model archive")
	}
	history := eng.History()
	if len(history) != 1 || len(history[0].Content) > 2048 || !strings.Contains(history[0].Content, "combined.bin") || !strings.Contains(history[0].Content, "read_file path=") {
		t.Fatal("model content unbounded or raw-output hydration pointer absent")
	}
	if _, err := os.Stat(filepath.Join(dir, "tool-results")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capped preview redundantly spilled as if it were full stdout")
	}
}

func TestEngineArchivesUnavailableAndInvalidCalls(t *testing.T) {
	for _, tc := range []provider.ToolCall{
		{ID: "missing", Name: "unavailable", Args: map[string]any{"command": strings.Repeat("synthetic", 1000)}},
		{ID: "invalid", Name: "inert", Args: map[string]any{}, ArgsError: "arguments were incomplete"},
	} {
		dir := t.TempDir()
		reg := tool.NewRegistry()
		inert := &planningInertTool{fakeTool: fakeTool{name: "inert"}}
		reg.Register(inert)
		eng := New(Config{Tools: reg, SpillDir: dir})
		res := eng.runTool(context.Background(), tc, nil)
		receipt, _ := res.Details[tool.ArchiveDetailsKey].(map[string]any)
		if !res.IsError || receipt["complete"] != true || inert.calls.Load() != 0 {
			t.Fatal("early error bypassed archival or executed invalid call")
		}
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(receipt["result"].(string))))
		if err != nil || string(body) != res.Content {
			t.Fatal("early failure result not retained")
		}
	}
}

func TestEngineCancelledParallelWaitsRetainArchives(t *testing.T) {
	dir := t.TempDir()
	reg := tool.NewRegistry()
	inert := &planningInertTool{fakeTool: fakeTool{name: "inert"}}
	reg.Register(inert)
	eng := New(Config{Tools: reg, SpillDir: dir})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := make([]provider.ToolCall, 24)
	for i := range calls {
		calls[i] = provider.ToolCall{ID: "repeat", Name: "inert", Args: map[string]any{"index": i}}
	}
	ch := make(chan Event, len(calls)*2)
	eng.dispatchToolsParallel(ctx, calls, ch)
	close(ch)
	ends := 0
	for ev := range ch {
		if ev.Type == EventToolExecEnd {
			ends++
			receipt, _ := ev.ToolDetails[tool.ArchiveDetailsKey].(map[string]any)
			if receipt["complete"] != true {
				t.Fatal("parallel cancellation bypassed archive finalization")
			}
		}
	}
	if ends != len(calls) || inert.calls.Load() != 0 {
		t.Fatal("cancelled parallel batch lost per-call outcome or executed tools")
	}
}

func TestEngineBashProgressCannotDeadlockOnCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	reg := tool.NewRegistry()
	reg.Register(tool.NewBash(nil))
	eng := New(Config{Tools: reg, SpillDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	// Intentionally never drain the progress channel. The context must release
	// bash's joined update goroutine so archival/finalization can complete.
	ch := make(chan Event)
	done := make(chan tool.Result, 1)
	go func() {
		done <- eng.dispatchTool(ctx, provider.ToolCall{ID: "cancel", Name: "bash", Args: map[string]any{"command": "printf partial; sleep 30"}}, ch)
	}()
	select {
	case res := <-done:
		if !res.IsError {
			t.Fatal("cancelled command reported success")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("bash update goroutine blocked archive closure after cancellation")
	}
}

func TestArchiveHydrationPointerSurvivesScratchpadTail(t *testing.T) {
	pointer := "[archive: read_file path=\"/synthetic/combined.bin\"]"
	content := strings.Repeat("output\n", 1000) + pointer + "\n\nscratchpad digest after pointer"
	if got := elideToolResult(content); !strings.Contains(got, pointer) || strings.Contains(got, "re-run the tool") {
		t.Fatal("compaction lost saved-byte hydration or requested a command rerun")
	}
}
