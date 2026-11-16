package sessionlog

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

type faultTranscriptFile struct {
	bytes.Buffer
	writes, failAt, closes, syncs int
	short                         bool
	writeErr, syncErr, closeErr   error
}

func (f *faultTranscriptFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == f.failAt {
		if f.short {
			n, _ := f.Buffer.Write(p[:len(p)/2])
			return n, f.writeErr
		}
		return 0, f.writeErr
	}
	return f.Buffer.Write(p)
}
func (f *faultTranscriptFile) Sync() error  { f.syncs++; return f.syncErr }
func (f *faultTranscriptFile) Close() error { f.closes++; return f.closeErr }

func TestRecorderEvidenceFailedHeader(t *testing.T) {
	boom := errors.New("disk failed")
	for _, failAt := range []int{1, 2, 3} {
		f := &faultTranscriptFile{failAt: failAt, writeErr: boom}
		rec, err := newWithFile(f, Meta{})
		if rec != nil || !errors.Is(err, boom) {
			t.Fatalf("header line %d: rec=%v err=%v", failAt, rec, err)
		}
		if f.writes != failAt || f.closes != 1 || f.syncs != 1 {
			t.Fatalf("failed header kept writing or leaked file: %+v", f)
		}
	}
	f := &faultTranscriptFile{failAt: 1, short: true}
	if rec, err := newWithFile(f, Meta{}); rec != nil || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short header must fail construction: %v, %v", rec, err)
	}
}

func TestRecorderEvidenceStickyWriteHealth(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "write_error", true: "short_write"}[short], func(t *testing.T) {
			boom := errors.New("write failure")
			f := &faultTranscriptFile{failAt: 4, short: short, writeErr: boom}
			r, err := newWithFile(f, Meta{})
			if err != nil {
				t.Fatal(err)
			}
			parent := r.lastID
			r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "partial text"})
			r.Record(engine.Event{Type: engine.EventTurnDone})
			if r.lastID != parent || r.text.String() != "partial text" || !errors.Is(r.Err(), boom) {
				t.Fatalf("failed write committed state or hid health: parent=%s text=%q err=%v", r.lastID, r.text.String(), r.Err())
			}
			if short && !errors.Is(r.Err(), io.ErrShortWrite) {
				t.Fatal("short write not tracked")
			}
			r.UserPrompt("later prompt")
			r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "later text"})
			r.Record(engine.Event{Type: engine.EventError, Err: "later error"})
			r.SectionStart("section", 1, "test", "later task")
			if f.writes != 4 || r.lastID != parent || r.text.String() != "partial text" {
				t.Fatal("recording continued after a broken line")
			}
			if !errors.Is(r.Close(), boom) || !errors.Is(r.Close(), boom) || f.closes != 1 {
				t.Fatal("Close hid sticky error or was not idempotent")
			}
		})
	}
}

func TestRecorderEvidenceMarshalFailure(t *testing.T) {
	f := &faultTranscriptFile{}
	r, err := newWithFile(f, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	parent := r.lastID
	r.Record(engine.Event{Type: engine.EventToolExecEnd, ToolDetails: map[string]any{"invalid": math.NaN()}})
	if r.Err() == nil || r.lastID != parent || f.writes != 3 || r.Close() == nil {
		t.Fatal("marshal failure hidden or parent chain advanced")
	}
}

func TestRecorderEvidenceFinalizationErrors(t *testing.T) {
	writeErr, syncErr, closeErr := errors.New("write"), errors.New("sync"), errors.New("close")
	for _, failWrite := range []bool{false, true} {
		f := &faultTranscriptFile{}
		r, err := newWithFile(f, Meta{})
		if err != nil {
			t.Fatal(err)
		}
		f.syncErr, f.closeErr = syncErr, closeErr
		if failWrite {
			f.failAt, f.writeErr = 4, writeErr
		}
		r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "interrupted turn"})
		err = r.Close()
		if !errors.Is(err, syncErr) || !errors.Is(err, closeErr) || (failWrite && !errors.Is(err, writeErr)) {
			t.Fatalf("finalization errors not joined: %v", err)
		}
		if !errors.Is(r.Err(), syncErr) || !errors.Is(r.Close(), closeErr) || f.syncs != 1 || f.closes != 1 {
			t.Fatal("final health lost or finalization repeated")
		}
	}
}

func TestRecorderEvidenceLongArgsResultsAndReceipts(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	r, err := New(path, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	args, result := strings.Repeat("argument\n", 20000), strings.Repeat("result\n", 30000)
	r.UserPrompt("inspect")
	r.Record(engine.Event{Type: engine.EventTurnDone, ToolCalls: []stream.ToolCall{{ID: "call", Name: "inspect", Arguments: map[string]any{"payload": args}}}})
	details := map[string]any{"record_uuid": "http-uuid", "capture": map[string]any{"status": "partial", "omitted_bytes": 2048}}
	r.Record(engine.Event{Type: engine.EventToolExecEnd, ToolCallID: "call", ToolName: "inspect", ToolResult: result, ToolDetails: details})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, path)
	parts := msgBody(t, lines[4])["content"].([]any)
	gotArgs := parts[0].(map[string]any)["arguments"].(map[string]any)["payload"]
	body := msgBody(t, lines[5])
	if gotArgs != args || firstPartText(t, body) != result {
		t.Fatal("long arguments/results truncated")
	}
	meta := body["details"].(map[string]any)
	if meta["record_uuid"] != "http-uuid" || meta["capture"].(map[string]any)["omitted_bytes"] != float64(2048) {
		t.Fatal("typed receipts lost")
	}
	assertLinearChain(t, lines)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("transcript not owner-only: %v, %v", info, err)
	}
}

func TestRecorderEvidenceInterruptedTurnOrdering(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	r, err := New(path, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	r.UserPrompt("start")
	r.Record(engine.Event{Type: engine.EventTextDelta, Delta: "partial response"})
	r.Record(engine.Event{Type: engine.EventError, Err: "context canceled"})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Close() }()
	}
	wg.Wait()
	lines := readLines(t, path)
	if len(lines) != 6 || lines[5]["type"] != "error" || msgBody(t, lines[4])["stopReason"] != "error" {
		t.Fatalf("partial response must precede terminal error: %+v", lines)
	}
	assertLinearChain(t, lines)
}
