package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// The second turn has two provider attempts, after one already-completed turn
// and tool dispatch. Channels are prefilled; no provider/network is contacted.
type adapterRetryBoundaryProvider struct {
	calls    int
	terminal bool
}

func (*adapterRetryBoundaryProvider) Name() string { return "adapter-retry-boundary-test" }
func (p *adapterRetryBoundaryProvider) Stream(_ context.Context, _ provider.Request) (<-chan stream.Event, error) {
	p.calls++
	ch := make(chan stream.Event, 5)
	switch p.calls {
	case 1:
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "completed first turn\n"}
		ch <- stream.Event{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "first-call", Name: "unavailable"}}
		ch <- stream.Event{Type: stream.EventToolCallEnd, ToolCall: &stream.ToolCall{ID: "first-call", Name: "unavailable", Arguments: map[string]any{}}}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonToolUse, Usage: &stream.Usage{Input: 10, Output: 2}}
	case 2:
		ch <- stream.Event{Type: stream.EventThinkingDelta, Delta: "abandoned reasoning"}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "abandoned second turn"}
		ch <- stream.Event{Type: stream.EventError, Err: "connection reset by peer"}
	default:
		ch <- stream.Event{Type: stream.EventThinkingDelta, Delta: "final reasoning"}
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "final second turn"}
		if p.terminal {
			ch <- stream.Event{Type: stream.EventError, Err: "context deadline exceeded"}
		} else {
			ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{Input: 12, Output: 3}}
		}
	}
	close(ch)
	return ch, nil
}

func TestOliumEvidenceRetryKeepsCompletedTurns(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovered", true: "final_attempt_failed"}[terminal], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), sessionlog.Filename)
			rec, err := sessionlog.New(path, sessionlog.Meta{})
			if err != nil {
				t.Fatal(err)
			}
			p := &adapterRetryBoundaryProvider{terminal: terminal}
			eng := oengine.New(oengine.Config{Provider: p, Recorder: rec, Tools: tool.NewRegistry(), RetryInitialBackoff: time.Millisecond})
			var live, thinking bytes.Buffer
			out, runErr := runOliumOnEngineWithThinking(context.Background(), nil, eng, "test", &live, &thinking, false)
			if err := eng.CloseRecorder(); err != nil {
				t.Fatal(err)
			}
			if terminal && !errors.Is(runErr, context.DeadlineExceeded) || !terminal && runErr != nil {
				t.Fatalf("retry became terminal or lost final sentinel: %v", runErr)
			}
			if p.calls != 3 || out.Text != "completed first turn\nfinal second turn" || out.ToolCalls != 1 {
				t.Fatalf("failed attempt contaminated output or erased completed turn: calls=%d out=%+v", p.calls, out)
			}
			wantInput, wantOutput := 22, 5
			if terminal {
				wantInput, wantOutput = 10, 2
			}
			if out.Usage.InputTokens != wantInput || out.Usage.OutputTokens != wantOutput {
				t.Fatalf("completed-turn usage changed: %+v", out.Usage)
			}
			if !strings.Contains(live.String(), "abandoned second turn") || thinking.String() != "abandoned reasoningfinal reasoning" {
				t.Fatal("live/raw evidence should retain exposed failed-attempt deltas")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var assistants []map[string]any
			retries, terminalErrors := 0, 0
			for _, line := range bytes.Split(bytes.TrimSpace(body), []byte{'\n'}) {
				var event map[string]any
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				switch event["type"] {
				case "stream_retry":
					retries++
					if event["attempt"] != float64(1) {
						t.Fatal("retry number should be local to current turn")
					}
				case "error":
					terminalErrors++
				case "message":
					message := event["message"].(map[string]any)
					if message["role"] == "assistant" {
						assistants = append(assistants, message)
					}
				}
			}
			wantErrors, finalStop := 0, "stop"
			if terminal {
				wantErrors, finalStop = 1, "error"
			}
			if retries != 1 || terminalErrors != wantErrors || len(assistants) != 3 || assistants[1]["stopReason"] != "interrupted" || assistants[2]["stopReason"] != finalStop {
				t.Fatalf("retry/terminal/assistant records incorrect: %d/%d %+v", retries, terminalErrors, assistants)
			}
			for i, want := range []string{"completed first turn\n", "abandoned second turn", "final second turn"} {
				var text strings.Builder
				for _, value := range assistants[i]["content"].([]any) {
					part := value.(map[string]any)
					if part["type"] == "text" {
						text.WriteString(part["text"].(string))
					}
				}
				if text.String() != want {
					t.Fatalf("transcript attempts merged: assistant=%d text=%q", i, text.String())
				}
			}
		})
	}
}
