package agent

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

// streamGroup serializes line-flushes from multiple concurrent
// prefixedStreamWriters onto a single underlying writer. It exists because
// safeWriter (mutex around byte-level Write) doesn't actually prevent
// terminal garbage when 3 goroutines stream tokens at once — the chars
// interleave per-write-call, not per-line.
//
// Use newStreamGroup(out) to wrap a stream sink, then call .writer(prefix)
// per goroutine. Each writer buffers internally and flushes whole lines
// (prefixed with [tag]) under the group's mutex. Trailing partial lines are
// drained by calling .Flush() on the writer.
type streamGroup struct {
	mu  sync.Mutex
	out io.Writer
}

// newStreamGroup wraps an underlying writer; returns nil if out is nil so
// callers can pass-through the no-stream case.
func newStreamGroup(out io.Writer) *streamGroup {
	if out == nil {
		return nil
	}
	return &streamGroup{out: out}
}

// writer returns a prefix-tagged stream writer. The prefix is rendered as
// "[prefix] " before each emitted line.
func (g *streamGroup) writer(prefix string) *prefixedStreamWriter {
	if g == nil {
		return nil
	}
	return &prefixedStreamWriter{group: g, prefix: prefix}
}

// prefixedStreamWriter buffers tokens until newline, then flushes the whole
// line atomically through the group mutex. Tokens within a single line stay
// contiguous; lines from different writers never interleave mid-line.
type prefixedStreamWriter struct {
	group  *streamGroup
	prefix string

	mu  sync.Mutex
	buf bytes.Buffer
	err error // sticky narrative failure; never retry a possibly partial line
}

// Write appends narrative bytes to the per-writer buffer and flushes complete
// prefixed lines. Successful writes accept the full input, including its tail.
func (w *prefixedStreamWriter) Write(p []byte) (int, error) {
	if w == nil || w.group == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	w.buf.Write(p)
	w.err = w.flushCompleteLinesLocked()
	return len(p), w.err
}

// WriteBlock flushes pending narrative before streaming an unmodified payload.
// Raw bytes bypass the line buffer and prefixes, even for huge lines or binary
// streams. Lock order is writer -> group -> shared sink, as for narrative writes.
// The callback must use its supplied writer, not re-enter this writer/group/sink.
func (w *prefixedStreamWriter) WriteBlock(write func(io.Writer) error) error {
	if w == nil || w.group == nil {
		return write(io.Discard)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.group.mu.Lock()
	defer w.group.mu.Unlock()

	render := func(out io.Writer) error {
		if err := w.flushPendingLocked(out); err != nil {
			return err
		}
		return write(out)
	}
	if out, ok := w.group.out.(interface {
		WriteBlock(func(io.Writer) error) error
	}); ok {
		// Share the session lock with producers outside this group (e.g. audit).
		return out.WriteBlock(render)
	}
	return render(w.group.out)
}

// Flush drains any trailing partial line. Call after the producer goroutine
// finishes so the last incomplete chunk reaches the user's terminal. Failures
// remain sticky and are returned by subsequent Write/WriteBlock calls.
func (w *prefixedStreamWriter) Flush() {
	if w == nil || w.group == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil || w.buf.Len() == 0 {
		return
	}
	w.group.mu.Lock()
	defer w.group.mu.Unlock()
	_ = w.flushPendingLocked(w.group.out)
}

// flushPendingLocked is called with both writer and group locks held. out may
// already be inside the shared sink's block; never write via the outer wrapper.
func (w *prefixedStreamWriter) flushPendingLocked(out io.Writer) error {
	if w.buf.Len() == 0 {
		return nil
	}
	n, err := fmt.Fprintf(out, "[%s] %s\n", w.prefix, w.buf.Bytes())
	if err == nil && n != len(w.prefix)+3+w.buf.Len()+1 {
		err = io.ErrShortWrite
	}
	w.buf.Reset()
	w.err = err
	return err
}

// flushCompleteLinesLocked emits every \n-terminated chunk currently in the
// buffer. Caller must hold w.mu.
func (w *prefixedStreamWriter) flushCompleteLinesLocked() error {
	for {
		data := w.buf.Bytes()
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			return nil
		}
		line := data[:idx+1]
		w.group.mu.Lock()
		n, err := fmt.Fprintf(w.group.out, "[%s] %s", w.prefix, line)
		w.group.mu.Unlock()
		w.buf.Next(idx + 1)
		if err == nil && n != len(w.prefix)+3+len(line) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return err
		}
	}
}
