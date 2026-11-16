package agent

import (
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NewSynchronizedWriter serializes Write calls without changing their bytes,
// return values, or ownership. It returns nil for nil and does not expose Close.
// Share this same wrapper with every producer of a session stream; separately
// wrapping the same underlying writer does not synchronize those wrappers.
func NewSynchronizedWriter(writer io.Writer) io.Writer {
	if writer == nil {
		return nil
	}
	if _, ok := writer.(*synchronizedWriter); ok {
		return writer
	}
	return &synchronizedWriter{writer: writer}
}

type synchronizedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *synchronizedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}

// runtimeANSI matches CSI (including colors/cursor controls), OSC (including
// hyperlinks), and other escape sequences (e.g. charset selection/reset).
// Only metadata is cleaned; raw AI chunks are never reformatted.
var runtimeANSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[ -/]*[0-~]`)

func runtimeMetadata(value string) string {
	value = runtimeANSI.ReplaceAllString(value, "")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

// WriteRuntimeProgress writes one UTC timestamped origin/phase/message line in
// a single Write call. Nil is a no-op. ANSI and line breaks are removed only
// from these metadata fields. This is not a stderr capture or secret redactor:
// callers must supply safe metadata, not credentials, prompts or HTTP bodies.
// A shared NewSynchronizedWriter also serializes this line with raw AI writes.
func WriteRuntimeProgress(writer io.Writer, origin, phase, message string) error {
	if writer == nil {
		return nil
	}
	line := "[" + time.Now().UTC().Format(time.RFC3339Nano) + "] [" + runtimeMetadata(origin) + "] [" + runtimeMetadata(phase) + "] " + runtimeMetadata(message) + "\n"
	n, err := writer.Write([]byte(line))
	if err == nil && n != len(line) {
		return io.ErrShortWrite
	}
	return err
}
