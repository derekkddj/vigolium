package agent

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"strings"
	"testing"

	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

type fullRuntimeProvider struct {
	command string
	calls   int
}

func (*fullRuntimeProvider) Name() string { return "synthetic-full-runtime" }
func (p *fullRuntimeProvider) Stream(context.Context, provider.Request) (<-chan stream.Event, error) {
	p.calls++
	ch := make(chan stream.Event, 3)
	if p.calls == 1 {
		ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "full", Name: "bash"}}
		ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: "full", Name: "bash", Arguments: map[string]any{"command": p.command}}}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse}
	} else {
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "final assistant answer"}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop}
	}
	close(ch)
	return ch, nil
}

func TestRecordedAgentRuntimeLogsFullShellWhileModelHistoryStaysBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	command := "printf '%1048615s' x; printf RAW-TAIL-BEYOND-PREVIEW; printf STDERR-LAST >&2 # " + strings.Repeat("synthetic argument ", 1000)
	reg := tool.NewRegistry()
	reg.Register(tool.NewBash(nil))
	eng := oengine.New(oengine.Config{
		Provider: &fullRuntimeProvider{command: command}, Tools: reg,
		SpillDir: t.TempDir(), MaxToolResultBytes: 1024,
	})
	var logs bytes.Buffer
	out, err := runOliumOnEngineWithThinking(context.Background(), nil, eng, "synthetic", NewSynchronizedWriter(&logs), nil, false)
	if err != nil || out.Text != "final assistant answer" {
		t.Fatalf("operator rendering contaminated parsed assistant output: %v", err)
	}
	text := logs.String()
	if !strings.Contains(text, command) || !strings.Contains(text, "RAW-TAIL-BEYOND-PREVIEW") || !strings.Contains(text, "STDERR-LAST") || strings.Contains(text, "▶ bash command=") || strings.Contains(text, "✓ ") {
		t.Fatal("recorded agent still writes abbreviated tool cards rather than command/raw output")
	}
	for _, message := range eng.History() {
		if message.Role == provider.RoleTool && (len(message.Content) > 2048 || strings.Contains(message.Content, "RAW-TAIL-BEYOND-PREVIEW")) {
			t.Fatal("full web/runtime output leaked into bounded model history")
		}
	}
}

func TestSynchronizedRuntimeWriterSerializesWholeStreamingBlocks(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSynchronizedWriter(&buf)
	blocks := writer.(interface {
		WriteBlock(func(io.Writer) error) error
	})
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- blocks.WriteBlock(func(w io.Writer) error {
			_, err := io.WriteString(w, "begin\n")
			close(entered)
			<-release
			if err != nil {
				return err
			}
			_, err = io.WriteString(w, "end\n")
			return err
		})
	}()
	<-entered
	other := make(chan struct{})
	go func() { _, _ = io.WriteString(writer, "other\n"); close(other) }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-other
	if buf.String() != "begin\nend\nother\n" {
		t.Fatal("another producer interleaved inside a chunked tool result")
	}
}
