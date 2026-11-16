package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

type receiptTool struct {
	fakeTool
	details map[string]any
}

func (f *receiptTool) Execute(_ context.Context, _ map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	return tool.Result{Content: f.out, Details: f.details, IsError: f.isErr}, nil
}

func TestEngineEvidenceToolDetailsSerialAndParallel(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		for _, isErr := range []bool{false, true} {
			details := map[string]any{"record_uuid": "record-1", "capture": map[string]any{"status": "partial", "omitted_bytes": 37}}
			full := strings.Repeat("tool result\n", 20000)
			reg := tool.NewRegistry()
			reg.Register(&receiptTool{fakeTool: fakeTool{name: "receipt", out: full, isErr: isErr}, details: details})
			e := &Engine{cfg: Config{Tools: reg, SpillDir: t.TempDir()}, maxToolResultLen: 1024}
			calls := []provider.ToolCall{{ID: "same", Name: "receipt"}}
			if parallel {
				calls = append(calls, provider.ToolCall{ID: "same", Name: "receipt"})
			}
			ch := make(chan Event, 8)
			if parallel {
				e.dispatchToolsParallel(context.Background(), calls, ch)
			} else {
				e.dispatchAndRecord(context.Background(), calls[0], ch)
			}
			close(ch)
			ends := 0
			for ev := range ch {
				if ev.Type != EventToolExecEnd {
					continue
				}
				ends++
				preserved := make(map[string]any, len(ev.ToolDetails))
				for key, value := range ev.ToolDetails {
					if key != tool.ArchiveDetailsKey {
						preserved[key] = value
					}
				}
				archive, _ := ev.ToolDetails[tool.ArchiveDetailsKey].(map[string]any)
				if !strings.HasSuffix(ev.ToolResult, full) || ev.ToolIsErr != isErr || !reflect.DeepEqual(preserved, details) || archive["complete"] != true {
					t.Fatalf("parallel=%v error=%v: receipt/content lost: bytes=%d details=%v", parallel, isErr, len(ev.ToolResult), ev.ToolDetails)
				}
				body, err := json.Marshal(ev)
				if err != nil || !strings.Contains(string(body), `"tool_details"`) {
					t.Fatal("receipt absent from event JSON")
				}
			}
			if ends != len(calls) {
				t.Fatal("missing end events")
			}
			for _, m := range e.History() {
				if m.Content == full || !strings.Contains(m.Content, spillPointerMarker) {
					t.Fatal("history not shrunk independently of receipt event")
				}
			}
		}
	}
}

func TestSpillEvidenceRepeatedAndSanitizedIDsImmutable(t *testing.T) {
	dir := t.TempDir()
	ids := []string{"repeat", "repeat", "a/b", "a-b", strings.Repeat("x", 80) + "1", strings.Repeat("x", 80) + "2"}
	var paths []string
	var payloads []string
	for i, id := range ids {
		payload := strings.Repeat(string(rune('a'+i)), 2000)
		got, ok := spillToolResult(dir, provider.ToolCall{ID: id, Name: "inspect"}, payload, 200)
		if !ok {
			t.Fatal("spill failed")
		}
		path := spillEvidencePath(t, got)
		paths, payloads = append(paths, path), append(payloads, payload)
	}
	seen := map[string]bool{}
	for i, path := range paths {
		if seen[path] {
			t.Fatalf("repeated/colliding ID reused spill: %s", path)
		}
		seen[path] = true
		body, err := os.ReadFile(path)
		if err != nil || string(body) != payloads[i] {
			t.Fatalf("old pointer changed: %s (%v)", path, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatal("spill not owner-only")
		}
	}
	if filepath.Base(paths[0]) != "inspect-repeat.txt" {
		t.Fatal("clean first-use pointer compatibility lost")
	}
}

func spillEvidencePath(t *testing.T, pointer string) string {
	t.Helper()
	i := strings.Index(pointer, spillPointerMarker)
	if i < 0 {
		t.Fatalf("no read pointer: %q", pointer)
	}
	quoted := strings.SplitN(pointer[i+len(spillPointerMarker):], "`", 2)[0]
	var path string
	if err := json.Unmarshal([]byte(quoted), &path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSpillEvidenceConcurrentSameID(t *testing.T) {
	dir := t.TempDir()
	const count = 12
	paths := make(chan string, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, ok := spillToolResult(dir, provider.ToolCall{ID: "repeat", Name: "inspect"}, "full result", 200)
			if !ok {
				paths <- ""
				return
			}
			paths <- got
		}()
	}
	wg.Wait()
	close(paths)
	seen := map[string]bool{}
	for pointer := range paths {
		if pointer == "" {
			t.Fatal("concurrent spill failed")
		}
		path := spillEvidencePath(t, pointer)
		if seen[path] {
			t.Fatal("concurrent spills shared a path")
		}
		seen[path] = true
	}
	if len(seen) != count {
		t.Fatal("spills lost")
	}
}
