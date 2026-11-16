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
	"github.com/vigolium/vigolium/pkg/olium/toollog"
)

func TestProgressWriterPreservesFullLoggerBlocksAndReentrantCallbacks(t *testing.T) {
	var sink bytes.Buffer
	shared := NewSynchronizedWriter(&sink).(*synchronizedWriter)
	source := newStreamGroup(shared).writer("source")
	pw := &progressWriter{inner: source, phase: "autopilot", interval: 1}
	var callbackErr error
	var callbackCount int
	pw.callback = func(phase, message string) {
		callbackCount++
		if phase != "autopilot" || !strings.HasPrefix(message, "agent output: ") {
			callbackErr = errors.New("unexpected progress metadata")
			return
		}
		// Both the shared block lock and this wrapper's counter lock must
		// already be released before callbacks that write to the same sink.
		if !shared.mu.TryLock() {
			callbackErr = errors.New("progress callback ran under session lock")
			return
		}
		shared.mu.Unlock()
		if !pw.mu.TryLock() {
			callbackErr = errors.New("progress callback ran under counter lock")
			return
		}
		pw.mu.Unlock()
		callbackErr = WriteRuntimeProgress(shared, "agent", phase, message)
	}
	var capable io.Writer = pw
	if _, ok := capable.(interface {
		WriteBlock(func(io.Writer) error) error
	}); !ok {
		t.Fatal("progress wrapper hid WriteBlock")
	}

	// Drive the actual full logger through both wrappers, without executing tools.
	result := "first result\n" + strings.Repeat("x", (1<<20)+51) + "\nLAST-RESULT"
	logger := toollog.New(pw).WithFullOutput(t.TempDir())
	done := make(chan struct{})
	go func() {
		logger.HandleTool(oengine.Event{
			Type: oengine.EventToolExecEnd, ToolCallID: "synthetic", ToolName: "synthetic",
			ToolResult: result,
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("progress callback deadlocked while writing to the shared stream")
	}
	if logger.Err() != nil || callbackErr != nil || callbackCount != 1 {
		t.Fatalf("block/callback failure: render=%v callback=%v calls=%d", logger.Err(), callbackErr, callbackCount)
	}
	if !strings.Contains(sink.String(), "Result (tool-returned bytes before model truncation):\n"+result+"\n") {
		t.Fatal("progress or source wrapper modified/interrupted the raw payload")
	}
	if source.buf.Len() != 0 || source.buf.Cap() != 0 {
		t.Fatal("full result entered the source narrative buffer")
	}
	pw.mu.Lock()
	written := pw.written
	pw.mu.Unlock()
	if written <= int64(len(result)) || written >= int64(sink.Len()) {
		t.Fatal("block counter failed to count payload/headers or included callback metadata")
	}
}

func TestProgressWriterCallbackCanReenterWrite(t *testing.T) {
	var sink bytes.Buffer
	shared := NewSynchronizedWriter(&sink)
	pw := &progressWriter{inner: shared, phase: "autopilot", interval: 1}
	var callbackMu sync.Mutex
	var reentered bool
	var callbackErr error
	pw.callback = func(string, string) {
		callbackMu.Lock()
		if reentered {
			callbackMu.Unlock()
			return
		}
		reentered = true
		callbackMu.Unlock()
		_, callbackErr = io.WriteString(pw, "callback\n")
	}
	done := make(chan error, 1)
	go func() {
		done <- pw.WriteBlock(func(out io.Writer) error {
			_, err := io.WriteString(out, "raw\n")
			return err
		})
	}()
	select {
	case err := <-done:
		if err != nil || callbackErr != nil {
			t.Fatalf("reentrant progress write failed: block=%v callback=%v", err, callbackErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reentrant progress callback deadlocked")
	}
	if sink.String() != "raw\ncallback\n" {
		t.Fatalf("callback ran inside or modified raw output: %q", sink.String())
	}
}

func TestProgressWriterCountsPartialFailuresWithoutInventingBytes(t *testing.T) {
	failure := errors.New("synthetic partial write")
	pw := &progressWriter{inner: fullStreamFailureWriter{err: failure}, interval: 1}
	if n, err := pw.Write([]byte("ordinary")); n != 3 || !errors.Is(err, failure) {
		t.Fatalf("ordinary return values changed: n=%d err=%v", n, err)
	}
	var accepted int
	err := pw.WriteBlock(func(out io.Writer) error {
		n, err := out.Write([]byte("raw output"))
		accepted = n
		return err
	})
	if accepted != 3 || !errors.Is(err, failure) {
		t.Fatalf("raw return values changed: n=%d err=%v", accepted, err)
	}
	pw.mu.Lock()
	written, emitted := pw.written, pw.lastEmitted
	pw.mu.Unlock()
	if written != 6 || emitted != 6 {
		t.Fatalf("partial writes counted as complete: written=%d emitted=%d", written, emitted)
	}
	callbackFailure := errors.New("synthetic callback failure")
	if err := pw.WriteBlock(func(io.Writer) error { return callbackFailure }); !errors.Is(err, callbackFailure) {
		t.Fatal("block callback error concealed")
	}
}

func TestProgressWriterConcurrentBlocksAndWritesCountActualBytes(t *testing.T) {
	var sink bytes.Buffer
	pw := &progressWriter{inner: NewSynchronizedWriter(&sink), interval: 64}
	var callbackMu sync.Mutex
	var callbacks int
	pw.callback = func(string, string) {
		callbackMu.Lock()
		callbacks++
		callbackMu.Unlock()
	}
	const producers, writes = 16, 32
	var wg sync.WaitGroup
	failures := make(chan error, producers)
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writes; j++ {
				if _, err := io.WriteString(pw, "w"); err != nil {
					failures <- err
					return
				}
				if err := pw.WriteBlock(func(out io.Writer) error {
					if _, err := io.WriteString(out, "b"); err != nil {
						return err
					}
					_, err := io.WriteString(out, "b")
					return err
				}); err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	const expected = producers * writes * 3
	pw.mu.Lock()
	written, emitted := pw.written, pw.lastEmitted
	pw.mu.Unlock()
	callbackMu.Lock()
	count := callbacks
	callbackMu.Unlock()
	if sink.Len() != expected || written != expected || count == 0 || emitted > written || written-emitted >= pw.interval {
		t.Fatalf("concurrent counters diverged: sink=%d written=%d emitted=%d callbacks=%d", sink.Len(), written, emitted, count)
	}
}
