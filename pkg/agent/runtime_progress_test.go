package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type runtimeTestWriter struct {
	bytes.Buffer
	calls int
	err   error
	short bool
}

func (w *runtimeTestWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return len(p) - 1, nil
	}
	return w.Buffer.Write(p)
}

func (w *runtimeTestWriter) Close() error { return nil }

func TestNewSynchronizedWriter_NilOwnershipAndRawBytes(t *testing.T) {
	if NewSynchronizedWriter(nil) != nil {
		t.Fatal("nil writer must stay nil")
	}
	out := &runtimeTestWriter{}
	writer := NewSynchronizedWriter(out)
	if _, ok := writer.(io.Closer); ok {
		t.Fatal("wrapper must not expose ownership of Close")
	}
	if NewSynchronizedWriter(writer) != writer {
		t.Fatal("an already synchronized writer must keep its shared mutex")
	}
	raw := []byte("AI chunk\x1b[31m\r\n\x00tail without newline")
	n, err := writer.Write(raw)
	if err != nil || n != len(raw) || !bytes.Equal(out.Bytes(), raw) || out.calls != 1 {
		t.Fatalf("raw bytes changed or duplicated: n=%d err=%v output=%q calls=%d", n, err, out.Bytes(), out.calls)
	}
	wantErr := errors.New("sink failed")
	out.err = wantErr
	if n, err := writer.Write(raw); n != 0 || err != wantErr {
		t.Fatalf("writer return values changed: n=%d err=%v", n, err)
	}
}

func TestWriteRuntimeProgress_MetadataOneWrite(t *testing.T) {
	out := &runtimeTestWriter{}
	before := time.Now()
	err := WriteRuntimeProgress(NewSynchronizedWriter(out), "\x1b[32m\x1b(Bnative\x1b[0m\x1bc\r\n", "\x1b[2Kscan\tphase", "\x1b]8;;https://example.invalid\x1b\\done\x1b]8;;\x1b\\\r\nnext\rline\n")
	if err != nil {
		t.Fatal(err)
	}
	line := out.String()
	if out.calls != 1 || strings.Count(line, "\n") != 1 || strings.ContainsAny(line, "\x1b\r\t") {
		t.Fatalf("metadata must be one clean line and one Write: calls=%d line=%q", out.calls, line)
	}
	end := strings.Index(line, "]")
	if end < 0 {
		t.Fatalf("missing timestamp: %q", line)
	}
	stamp, err := time.Parse(time.RFC3339Nano, line[1:end])
	if err != nil || stamp.Before(before) || stamp.After(time.Now()) || !strings.HasSuffix(line[:end], "Z") {
		t.Fatalf("invalid UTC timestamp: %q, err=%v", line[:end], err)
	}
	if got, want := line[end+1:], " [native] [scan phase] done next line\n"; got != want {
		t.Fatalf("metadata: got %q want %q", got, want)
	}
}

func TestWriteRuntimeProgress_NilAndErrors(t *testing.T) {
	if err := WriteRuntimeProgress(nil, "native", "scan", "ignored"); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("sink failed")
	if err := WriteRuntimeProgress(&runtimeTestWriter{err: wantErr}, "swarm", "run", "done"); err != wantErr {
		t.Fatalf("missing write error: %v", err)
	}
	if err := WriteRuntimeProgress(&runtimeTestWriter{short: true}, "swarm", "run", "done"); err != io.ErrShortWrite {
		t.Fatalf("missing short-write error: %v", err)
	}
}

func TestNewSynchronizedWriter_ConcurrentRawAndProgress(t *testing.T) {
	// bytes.Buffer is intentionally not thread-safe: -race verifies that every
	// producer shares the wrapper's lock, including runtime metadata writes.
	var out bytes.Buffer
	writer := NewSynchronizedWriter(&out)
	const producers, writes = 16, 100
	var wg sync.WaitGroup
	for producer := 0; producer < producers; producer++ {
		wg.Go(func() {
			for i := 0; i < writes; i++ {
				if producer%2 == 0 {
					line := fmt.Sprintf("raw-%d-%d\x1b[31m\r\n", producer, i)
					if _, err := writer.Write([]byte(line)); err != nil {
						t.Error(err)
					}
				} else if err := WriteRuntimeProgress(writer, "native", "scan", fmt.Sprintf("event-%d-%d", producer, i)); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if got := strings.Count(out.String(), "\n"); got != producers*writes {
		t.Fatalf("writes lost/interleaved: lines=%d", got)
	}
	for producer := 0; producer < producers; producer++ {
		for i := 0; i < writes; i++ {
			want := fmt.Sprintf("raw-%d-%d\x1b[31m\r\n", producer, i)
			if producer%2 != 0 {
				want = fmt.Sprintf(" [native] [scan] event-%d-%d\n", producer, i)
			}
			if got := strings.Count(out.String(), want); got != 1 {
				t.Fatalf("expected one intact Write %q, got %d", want, got)
			}
		}
	}
}
