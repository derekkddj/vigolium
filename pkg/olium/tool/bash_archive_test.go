package tool

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBashExecuteArchivesFullSeparateStreamsBeforeCaptureCap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX bash printf")
	}
	dir := t.TempDir()
	args := map[string]any{"command": "printf '%1048600s' x; printf '\\000\\377\\015\\012' >&2"}
	res := ArchiveExecution(context.Background(), dir, "call", "bash", args, func(ctx context.Context) Result {
		res, err := NewBash(nil).Execute(ctx, args, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	})
	if res.IsError || !strings.Contains(res.Content, "output capped") || len(res.Content) > maxBashCapture+256 {
		t.Fatalf("model-facing result not bounded: bytes=%d error=%v", len(res.Content), res.IsError)
	}
	receipt := archiveReceipt(t, res)
	if receipt["complete"] != true {
		t.Fatal("full shell output not durably retained")
	}
	streams := receipt["streams"].(map[string]any)
	for name, want := range map[string]int64{"stdout": 1048600, "stderr": 4, "combined": 1048604} {
		stream := streams[name].(map[string]any)
		if stream["stored_bytes"] != want || stream["observed_bytes"] != want {
			t.Fatalf("%s raw byte count mismatch", name)
		}
	}
	stderr := streams["stderr"].(map[string]any)
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(stderr["path"].(string))))
	if err != nil || !bytes.Equal(got, []byte{0, 0xff, '\r', '\n'}) {
		t.Fatalf("binary stderr not retained: bytes=%d err=%v", len(got), err)
	}
	if res.Details["output_truncated"] != true || res.Details["output_archive_enabled"] != true {
		t.Fatal("model truncation confused with archive retention")
	}
}

func TestBashCancelledInvocationRetainsPartialStreamAndFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX shell")
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	args := map[string]any{"command": "printf partial; sleep 30"}
	res := ArchiveExecution(ctx, dir, "call", "bash", args, func(ctx context.Context) Result {
		// Cancel only after observing the prefix, not on a scheduling-sensitive
		// deadline that could fire before the command has written anything.
		res, err := NewBash(nil).Execute(ctx, args, func(Result) { cancel() })
		if err != nil {
			t.Fatal(err)
		}
		return res
	})
	if !res.IsError || ctx.Err() == nil {
		t.Fatal("cancelled command lost failure outcome")
	}
	receipt := archiveReceipt(t, res)
	streams := receipt["streams"].(map[string]any)
	stream := streams["stdout"].(map[string]any)
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(stream["path"].(string))))
	if err != nil || string(got) != "partial" {
		t.Fatalf("partial raw bytes not retained: bytes=%d err=%v", len(got), err)
	}
	metadata := readArchiveJSON(t, dir, receipt["metadata"].(string))
	if metadata["is_error"] != true {
		t.Fatal("durable output retention fabricated successful execution")
	}
}
