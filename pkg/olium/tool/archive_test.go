package tool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func archiveReceipt(t *testing.T, res Result) map[string]any {
	t.Helper()
	r, ok := res.Details[ArchiveDetailsKey].(map[string]any)
	if !ok {
		t.Fatal("missing archive receipt")
	}
	return r
}

func readArchiveJSON(t *testing.T, dir, relative string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(b, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestArchiveExecutionArgumentsBeforeExecuteAndBinaryResult(t *testing.T) {
	dir := t.TempDir()
	command := strings.Repeat("long synthetic argument\n", 10000)
	binary := []byte{0, 0xff, 0xfe, '\r', '\n', 0x80}
	sharedDetails := map[string]any{"record_uuid": "record", "blob": binary}
	res := ArchiveExecution(context.Background(), dir, "reused/id", "inspect", map[string]any{"command": command}, func(ctx context.Context) Result {
		a := callArchiveFrom(ctx)
		if a == nil {
			t.Fatal("per-call context missing")
		}
		params := readArchiveJSON(t, dir, filepath.ToSlash(filepath.Join(a.path, "arguments.json")))
		if params["arguments"].(map[string]any)["command"] != command {
			t.Fatal("full parameters not persisted before execution")
		}
		return Result{Content: string(binary), Details: sharedDetails}
	})
	receipt := archiveReceipt(t, res)
	if receipt["complete"] != true || receipt["result_stored_bytes"] != int64(len(binary)) {
		t.Fatal("binary result archive incomplete")
	}
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(receipt["result"].(string))))
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("binary result changed: stored bytes=%d err=%v", len(got), err)
	}
	sum := sha256.Sum256(binary)
	if receipt["result_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatal("raw result digest differs")
	}
	metadata := readArchiveJSON(t, dir, receipt["metadata"].(string))
	if metadata["details"].(map[string]any)["blob"] != base64.StdEncoding.EncodeToString(binary) {
		t.Fatal("binary details must retain base64 JSON contract")
	}
	if _, mutated := sharedDetails[ArchiveDetailsKey]; mutated {
		t.Fatal("shared evidence details were mutated")
	}
	assertArchivePrivate(t, dir, receipt["path"].(string))
}

func assertArchivePrivate(t *testing.T, dir, relative string) {
	t.Helper()
	err := filepath.WalkDir(filepath.Join(dir, filepath.FromSlash(relative)), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("archive is not owner-only")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBashCaptureStreamsBeyondModelCapWithoutExecutingCommand(t *testing.T) {
	dir := t.TempDir()
	a, err := NewCallArchive(dir, "call", "bash", map[string]any{"command": "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	capture := &bashCapture{archive: a}
	stdout := bashCaptureWriter{capture: capture, stream: "stdout"}
	stderr := bashCaptureWriter{capture: capture, stream: "stderr"}
	// Chunked binary output exceeds both the bash preview and engine's model
	// budget. No shell/network/process jobs are needed for this regression.
	chunk := bytes.Repeat([]byte{0, 0xff, '\r', '\n'}, 1024)
	const count = 600
	for range count {
		if n, err := stdout.Write(chunk); n != len(chunk) || err != nil {
			t.Fatal("stdout drainage interrupted")
		}
	}
	tail := []byte{0xfe, 0, 'e', 'r', 'r', '\n'}
	_, _ = stderr.Write(tail)
	if len(capture.snapshot()) != maxBashCapture {
		t.Fatal("model capture did not stay bounded")
	}
	res := Result{Content: capture.snapshot(), Details: capture.details()}
	res = withArchiveReceipt(res, a.Finish(res))
	receipt := archiveReceipt(t, res)
	streams := receipt["streams"].(map[string]any)
	if receipt["complete"] != true {
		t.Fatal("stream archive failed")
	}
	for name, want := range map[string]int64{"stdout": int64(count * len(chunk)), "stderr": int64(len(tail)), "combined": int64(count*len(chunk) + len(tail))} {
		stream := streams[name].(map[string]any)
		if stream["observed_bytes"] != want || stream["stored_bytes"] != want || stream["complete"] != true {
			t.Fatalf("stream %s: retained byte count mismatch", name)
		}
		info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(stream["path"].(string))))
		if err != nil || info.Size() != want {
			t.Fatalf("stream %s: file size mismatch: err=%v", name, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, a.path, "stderr.bin"))
	if err != nil || !bytes.Equal(got, tail) {
		t.Fatal("stderr binary bytes changed")
	}
	combined, err := os.Open(filepath.Join(dir, a.path, "combined.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer combined.Close()
	last := make([]byte, len(tail))
	if _, err := combined.ReadAt(last, int64(count*len(chunk))); err != nil || !bytes.Equal(last, tail) {
		t.Fatal("combined ordering or trailing bytes lost")
	}
}

func TestArchiveExecutionReusedIDsAreCollisionSafeConcurrent(t *testing.T) {
	dir := t.TempDir()
	const count = 8
	results := make([]Result, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = ArchiveExecution(context.Background(), dir, "../../same", "same/tool", nil, func(ctx context.Context) Result {
				callArchiveFrom(ctx).WriteStream("stdout", []byte{byte(i)})
				return Result{Content: string([]byte{byte(i)})}
			})
		}(i)
	}
	wg.Wait()
	seen := make(map[string]bool)
	for i, result := range results {
		receipt := archiveReceipt(t, result)
		path := receipt["path"].(string)
		if seen[path] || receipt["complete"] != true || !strings.HasPrefix(path, ArchiveDirectory+"/") {
			t.Fatal("reused IDs collided or escaped session")
		}
		seen[path] = true
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(receipt["result"].(string))))
		if err != nil || !bytes.Equal(got, []byte{byte(i)}) {
			t.Fatal("one invocation overwrote another result")
		}
	}
}

func TestArchiveStreamFailureIsStickyDoesNotStopDrainage(t *testing.T) {
	dir := t.TempDir()
	a, err := NewCallArchive(dir, "call", "bash", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.WriteStream("stdout", []byte("first"))
	// A closed file simulates a write failure after an already-retained prefix.
	if err := a.files["stdout"].f.Close(); err != nil {
		t.Fatal(err)
	}
	capture := &bashCapture{archive: a}
	w := bashCaptureWriter{capture: capture, stream: "stdout"}
	for range 3 {
		if n, err := w.Write([]byte("later")); n != 5 || err != nil {
			t.Fatal("archive failure stopped command pipe drainage")
		}
	}
	receipt := a.Finish(Result{Content: capture.snapshot()})
	stream := receipt["streams"].(map[string]any)["stdout"].(map[string]any)
	if receipt["complete"] != false || stream["complete"] != false || stream["stored_bytes"] != int64(5) || stream["observed_bytes"] != int64(20) {
		t.Fatal("failed stream fabricated retained trailing bytes")
	}
	if a.Err() == nil || a.Close() == nil || a.Close() == nil {
		t.Fatal("sticky finalization health lost")
	}
}

func TestArchiveFailureAndDisabledDoNotChangeToolOutcome(t *testing.T) {
	outer, err := NewCallArchive(t.TempDir(), "outer", "inspect", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	ctx := WithCallArchive(context.Background(), outer)
	bad := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(bad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"", bad} {
		runs := 0
		res := ArchiveExecution(ctx, dir, "call", "inspect", nil, func(ctx context.Context) Result {
			if callArchiveFrom(ctx) != nil {
				t.Fatal("failed/disabled call inherited another invocation's archive")
			}
			runs++
			return Result{Content: "handled failure", IsError: true, Details: map[string]any{"record_uuid": "record"}}
		})
		if runs != 1 || res.Content != "handled failure" || !res.IsError || res.Details["record_uuid"] != "record" {
			t.Fatal("archive initialization changed tool execution/outcome")
		}
		if dir == "" {
			if _, exists := res.Details[ArchiveDetailsKey]; exists {
				t.Fatal("disabled archive fabricated evidence")
			}
		} else if archiveReceipt(t, res)["complete"] != false {
			t.Fatal("failed initialization claimed retention")
		}
	}
}

func TestArchiveCloseInterruptedAndPanic(t *testing.T) {
	dir := t.TempDir()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected synthetic panic")
			}
		}()
		ArchiveExecution(context.Background(), dir, "call", "inspect", nil, func(ctx context.Context) Result {
			callArchiveFrom(ctx).WriteStream("stdout", []byte("partial"))
			panic("synthetic")
		})
	}()
	entries, err := os.ReadDir(filepath.Join(dir, ArchiveDirectory))
	if err != nil || len(entries) != 1 {
		t.Fatal("interrupted archive missing")
	}
	b, err := os.ReadFile(filepath.Join(dir, ArchiveDirectory, entries[0].Name(), "lifecycle.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("interrupted lifecycle lost boundary")
	}
	var end map[string]any
	if err := json.Unmarshal(lines[1], &end); err != nil {
		t.Fatal(err)
	}
	if end["type"] != "interrupted" || end["receipt"].(map[string]any)["complete"] != false {
		t.Fatal("interrupted archive promoted to complete")
	}
}

func TestArchiveJSONFailureAndPipeFailureNeverClaimComplete(t *testing.T) {
	for _, pipeFailure := range []bool{false, true} {
		a, err := NewCallArchive(t.TempDir(), "call", "inspect", nil)
		if err != nil {
			t.Fatal(err)
		}
		a.WriteStream("stdout", []byte("observed"))
		res := Result{}
		if pipeFailure {
			a.markStreamsIncomplete()
		} else {
			res.Details = map[string]any{"invalid": math.NaN()}
		}
		if receipt := a.Finish(res); receipt["complete"] != false || receipt["status"] != "partial" || a.Close() == nil {
			t.Fatal("archive failure hidden")
		}
	}
}

func TestArchiveRejectsOutsideSymlinkAndStreamTraversal(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, ArchiveDirectory)); err != nil {
		t.Skip("symlinks unavailable")
	}
	if a, err := NewCallArchive(dir, "call", "inspect", nil); err == nil {
		_ = a.Close()
		t.Fatal("archive escaped rooted session directory")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("archive wrote outside session")
	}
	a, err := NewCallArchive(t.TempDir(), "call", "inspect", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.WriteStream("../../escape", []byte("never stored"))
	if a.Finish(Result{})["complete"] != false || len(a.files) != 0 {
		t.Fatal("invalid stream name accepted")
	}
	_ = a.Close()
}
