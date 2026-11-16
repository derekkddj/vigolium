package agent

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
)

// All writes in this fixture originate from source while its mutex is held.
// Inspect the narrative buffer at the sink, not just after the block resets it.
type fullStreamBufferProbe struct {
	out         bytes.Buffer
	source      *prefixedStreamWriter
	maxBuffered int
	maxCapacity int
}

func (p *fullStreamBufferProbe) Write(data []byte) (int, error) {
	if p.source.buf.Len() > p.maxBuffered {
		p.maxBuffered = p.source.buf.Len()
	}
	if p.source.buf.Cap() > p.maxCapacity {
		p.maxCapacity = p.source.buf.Cap()
	}
	return p.out.Write(data)
}

func TestStreamGroupFullLoggerPreservesLargeVerbatimPayloads(t *testing.T) {
	dir := t.TempDir()
	probe := &fullStreamBufferProbe{}
	writer := newStreamGroup(NewSynchronizedWriter(probe)).writer("format-routes")
	probe.source = writer
	if _, err := io.WriteString(writer, "pending narrative"); err != nil {
		t.Fatal(err)
	}
	logger := toollog.New(writer).WithFullOutput(dir)

	// No shell is executed: these are synthetic events and archived bytes.
	command := "first command\n" + strings.Repeat("x", (1<<20)+31) + "\nLAST-COMMAND"
	logger.HandleTool(oengine.Event{
		Type: oengine.EventToolExecStart, ToolCallID: "shell", ToolName: "bash",
		ToolArgs: map[string]any{"command": command},
	})
	archive, err := tool.NewCallArchive(dir, "shell", "bash", map[string]any{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = archive.Close() })
	// A >1 MiB line must never accumulate in the prefixed narrative buffer.
	stdout := append(bytes.Repeat([]byte{0, 0xff, 'x', '\r'}, 270000), []byte("RAW-TAIL")...)
	stderr := []byte("stderr first\nstderr last\x00\xff")
	archive.WriteStream("stdout", stdout)
	archive.WriteStream("stderr", stderr)
	result := tool.Result{Content: "capped preview; never a replacement for raw bytes"}
	receipt := archive.Finish(result)
	logger.HandleTool(oengine.Event{
		Type: oengine.EventToolExecEnd, ToolCallID: "shell", ToolName: "bash",
		ToolResult: result.Content, ToolDetails: map[string]any{tool.ArchiveDetailsKey: receipt},
	})

	returned := strings.Repeat("result line\n", 100000) + "LAST-RESULT"
	logger.HandleTool(oengine.Event{
		Type: oengine.EventToolExecEnd, ToolCallID: "synthetic", ToolName: "synthetic",
		ToolResult: returned,
	})
	if logger.Err() != nil {
		t.Fatal(logger.Err())
	}
	out := probe.out.Bytes()
	if !bytes.HasPrefix(out, []byte("[format-routes] pending narrative\n\nTool call")) {
		t.Fatal("pending narrative was not flushed before the raw block")
	}
	for _, payload := range [][]byte{
		[]byte("Command (verbatim):\n" + command + "\n"),
		append(append([]byte("stdout (raw archived bytes):\n"), stdout...), '\n'),
		append(append([]byte("stderr (raw archived bytes):\n"), stderr...), '\n'),
		[]byte("Result (tool-returned bytes before model truncation):\n" + returned + "\n"),
	} {
		if !bytes.Contains(out, payload) {
			t.Fatal("a complete command/result/raw stream was modified or prefixed")
		}
	}
	if bytes.Contains(out, []byte(result.Content)) {
		t.Fatal("raw streams were replaced with the capped preview")
	}
	if probe.maxBuffered > 4096 || probe.maxCapacity > 4096 {
		t.Fatalf("raw payload entered narrative buffer: len=%d capacity=%d", probe.maxBuffered, probe.maxCapacity)
	}
}

type fullStreamFailureWriter struct {
	err error
}

func (w fullStreamFailureWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > 3 {
		n = 3
	}
	return n, w.err
}

func TestStreamGroupRawBlockPropagatesActualWriteFailure(t *testing.T) {
	failure := errors.New("synthetic stream failure")
	writer := newStreamGroup(fullStreamFailureWriter{err: failure}).writer("source")
	var accepted int
	err := writer.WriteBlock(func(out io.Writer) error {
		n, err := out.Write([]byte("raw\nbytes"))
		accepted = n
		return err
	})
	if !errors.Is(err, failure) || accepted != 3 {
		t.Fatalf("raw write failure/count concealed: n=%d err=%v", accepted, err)
	}
	if writer.buf.Len() != 0 || writer.buf.Cap() != 0 {
		t.Fatal("failed raw payload entered the narrative buffer")
	}
	logger := toollog.New(writer).WithFullOutput(t.TempDir())
	logger.HandleTool(oengine.Event{Type: oengine.EventToolExecStart, ToolName: "synthetic"})
	if logger.Err() == nil {
		t.Fatal("full logger did not observe the downstream writer failure")
	}
}

func TestStreamGroupRawBlockRejectsFailedPendingNarrative(t *testing.T) {
	failure := errors.New("pending narrative failure")
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "error", err: failure, want: failure},
		{name: "short-write", want: io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := newStreamGroup(fullStreamFailureWriter{err: tc.err}).writer("source")
			if _, err := io.WriteString(writer, "pending narrative"); err != nil {
				t.Fatal(err)
			}
			called := false
			err := writer.WriteBlock(func(io.Writer) error { called = true; return nil })
			if !errors.Is(err, tc.want) || called {
				t.Fatalf("raw payload continued after a failed narrative flush: called=%v err=%v", called, err)
			}
			if n, err := writer.Write([]byte("later\n")); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("partial narrative failure was not sticky: n=%d err=%v", n, err)
			}
		})
	}
}

func TestStreamGroupFullBlocksShareSessionLock(t *testing.T) {
	for _, sameGroup := range []bool{true, false} {
		name := "independent-groups"
		if sameGroup {
			name = "same-group"
		}
		t.Run(name, func(t *testing.T) {
			var sink bytes.Buffer
			shared := NewSynchronizedWriter(&sink).(*synchronizedWriter)
			a := newStreamGroup(shared).writer("a")
			b := a.group.writer("b")
			if !sameGroup {
				b = newStreamGroup(shared).writer("b")
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			releaseBlock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(releaseBlock)
			doneA := make(chan error, 1)
			go func() {
				doneA <- a.WriteBlock(func(out io.Writer) error {
					// Check both locks before allowing competing producers to start;
					// scheduling a goroutine alone would not prove block ownership.
					var lockErr error
					if a.group.mu.TryLock() {
						a.group.mu.Unlock()
						lockErr = errors.New("raw block did not hold group lock")
					}
					if shared.mu.TryLock() {
						shared.mu.Unlock()
						lockErr = errors.New("raw block did not hold shared session lock")
					}
					close(entered)
					if lockErr != nil {
						return lockErr
					}
					if _, err := io.WriteString(out, "a-begin\n"); err != nil {
						return err
					}
					<-release
					_, err := io.WriteString(out, "a-end\n")
					return err
				})
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first block never entered (possible nested-lock deadlock)")
			}
			attemptB := make(chan struct{})
			doneB := make(chan error, 1)
			go func() {
				close(attemptB)
				doneB <- b.WriteBlock(func(out io.Writer) error {
					if _, err := io.WriteString(out, "b-begin\n"); err != nil {
						return err
					}
					_, err := io.WriteString(out, "b-end\n")
					return err
				})
			}()
			attemptOther := make(chan struct{})
			doneOther := make(chan error, 1)
			go func() {
				close(attemptOther)
				_, err := io.WriteString(shared, "outside-group\n")
				doneOther <- err
			}()
			<-attemptB
			<-attemptOther
			releaseBlock()
			for _, done := range []<-chan error{doneA, doneB, doneOther} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("stream producer deadlocked")
				}
			}
			out := sink.String()
			if !strings.HasPrefix(out, "a-begin\na-end\n") || !strings.Contains(out, "b-begin\nb-end\n") || strings.Count(out, "outside-group\n") != 1 {
				t.Fatalf("producer interleaved inside a raw block: %q", out)
			}
		})
	}
}

func TestStreamGroupNilRawBlockUsesDiscard(t *testing.T) {
	var writer *prefixedStreamWriter
	failure := errors.New("callback failure")
	if err := writer.WriteBlock(func(out io.Writer) error {
		if n, err := io.WriteString(out, "raw"); n != 3 || err != nil {
			t.Fatalf("nil raw sink returned n=%d err=%v", n, err)
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal("nil sink concealed callback failure")
	}
}
