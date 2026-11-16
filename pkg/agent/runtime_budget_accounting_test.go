package agent

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

type attemptBudgetRuntime struct {
	fakeRuntime
	calls int
}

func (r *attemptBudgetRuntime) RunPrompt(context.Context, *config.OliumConfig, string, io.Writer, io.Writer, string, bool, RecordSpec) (oliumRunOutput, error) {
	r.calls++
	out := oliumRunOutput{Text: "partial attempt", Usage: agenttypes.TokenUsage{InputTokens: 10, OutputTokens: 3}, ToolCalls: 2}
	if r.calls == 1 {
		return out, errProviderRateLimited
	}
	out.Text = "final answer"
	return out, nil
}

type reportedAttemptUsageProvider struct {
	calls    int
	terminal bool
}

func (*reportedAttemptUsageProvider) Name() string { return "reported-attempt-test" }
func (p *reportedAttemptUsageProvider) Stream(context.Context, provider.Request) (<-chan stream.Event, error) {
	p.calls++
	ch := make(chan stream.Event, 3)
	if p.calls == 1 {
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "abandoned attempt"}
		ch <- stream.Event{Type: stream.EventDone, Usage: &stream.Usage{Input: 5, Output: 1}}
		ch <- stream.Event{Type: stream.EventError, Err: "connection reset by peer"}
	} else {
		ch <- stream.Event{Type: stream.EventTextDelta, Delta: "final attempt"}
		ch <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &stream.Usage{Input: 7, Output: 2}}
		if p.terminal {
			ch <- stream.Event{Type: stream.EventError, Err: "context deadline exceeded"}
		}
	}
	close(ch)
	return ch, nil
}

type cancelOnUsageRetryRecorder struct{ cancel context.CancelFunc }

func (cancelOnUsageRetryRecorder) UserPrompt(string) {}
func (r cancelOnUsageRetryRecorder) Record(ev oengine.Event) {
	if ev.Type == oengine.EventStreamRetry {
		r.cancel()
	}
}

func TestRuntimeBudgetCountsReportedStreamAttemptsOnce(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		p := &reportedAttemptUsageProvider{terminal: terminal}
		eng := oengine.New(oengine.Config{Provider: p, RetryInitialBackoff: time.Millisecond})
		out, err := runOliumOnEngineWithThinking(context.Background(), nil, eng, "synthetic", nil, nil, false)
		if terminal && !errors.Is(err, context.DeadlineExceeded) || !terminal && err != nil || out.Usage.InputTokens != 12 || out.Usage.OutputTokens != 3 || out.Text != "final attempt" {
			t.Fatalf("reported stream cost lost or failed text merged: err=%v out=%+v", err, out)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eng := oengine.New(oengine.Config{
		Provider: &reportedAttemptUsageProvider{}, RetryInitialBackoff: time.Minute,
		Recorder: cancelOnUsageRetryRecorder{cancel: cancel},
	})
	out, err := runOliumOnEngineWithThinking(ctx, nil, eng, "synthetic", nil, nil, false)
	if !errors.Is(err, context.Canceled) || out.Usage.InputTokens != 5 || out.Usage.OutputTokens != 1 {
		t.Fatalf("backoff cancellation double charged abandoned-attempt usage: err=%v out=%+v", err, out)
	}
}

func TestRuntimeBudgetChargesAllAttemptsWithoutRefilling(t *testing.T) {
	for _, cap := range []int{0, 2} {
		rt := &attemptBudgetRuntime{}
		e := &Engine{runtime: rt}
		e.SetRunBudget(RunBudget{MaxCommands: cap}, nil)
		result, err := e.Run(context.Background(), Options{PromptInline: "synthetic", Retry: &RetryConfig{MaxRetries: 1, InitialDelay: time.Millisecond}})
		wantAttempts := 2
		if cap > 0 {
			wantAttempts = 1
			var budgetErr *BudgetExhaustedError
			if !errors.As(err, &budgetErr) || result == nil || result.RawOutput != "partial attempt" {
				t.Fatalf("exhausted attempt restarted or lost partial text: %v", err)
			}
		} else if err != nil || result == nil || result.RawOutput != "final answer" {
			t.Fatalf("transient recovery failed: %v", err)
		}
		calls, _ := e.RunBudgetUsage()
		usage := e.TokenUsage()
		if rt.calls != wantAttempts || calls != wantAttempts*2 || usage.InputTokens != wantAttempts*10 || usage.OutputTokens != wantAttempts*3 || result.TokenUsage != usage {
			t.Fatalf("attempt cost lost or double charged: attempts=%d tools=%d usage=%+v result=%+v", rt.calls, calls, usage, result.TokenUsage)
		}
	}
}
