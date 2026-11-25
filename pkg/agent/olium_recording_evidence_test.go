package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

func TestOliumEvidenceContextClassification(t *testing.T) {
	for _, tc := range []struct {
		msg      string
		sentinel error
		retry    bool
	}{
		{"olium stream: context deadline exceeded", context.DeadlineExceeded, true},
		{"olium stream: context canceled", context.Canceled, false},
		{"anthropic 429: rate limit", errProviderRateLimited, true},
		{"openai 503: unavailable", errProviderServerError, true},
	} {
		err := classifyOliumEventError(context.Background(), tc.msg)
		if !errors.Is(err, tc.sentinel) || isRetryableAgentError(context.Background(), err) != tc.retry {
			t.Fatalf("classification/retry changed: %q => %v", tc.msg, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if isRetryableAgentError(ctx, err) {
			t.Fatal("cancelled parent must not retry")
		}
	}
}

func TestOliumEvidenceRecorderWarningSafeAndSticky(t *testing.T) {
	var sink bytes.Buffer
	boom := errors.New("PRIVATE-DETAILS")
	r := &adapterRecorder{err: boom, sink: NewSynchronizedWriter(&sink)}
	r.UserPrompt("PRIVATE-PROMPT")
	r.Record(oengine.Event{Type: oengine.EventToolExecEnd, ToolResult: "PRIVATE-RESULT"})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !errors.Is(r.Close(), boom) {
				t.Error("recording error lost")
			}
		}()
	}
	wg.Wait()
	if strings.Count(sink.String(), "Evidence degraded") != 1 || strings.Contains(sink.String(), "PRIVATE") {
		t.Fatalf("warning missing, duplicated, or leaked payload: %q", sink.String())
	}
}

type evidenceErrorProvider struct{}

func (evidenceErrorProvider) Name() string { return "evidence-test" }
func (evidenceErrorProvider) Stream(_ context.Context, _ provider.Request) (<-chan stream.Event, error) {
	ch := make(chan stream.Event, 3)
	ch <- stream.Event{Type: stream.EventTextDelta, Delta: "partial answer"}
	ch <- stream.Event{Type: stream.EventError, Err: "context deadline exceeded"}
	close(ch)
	return ch, nil
}

func TestOliumEvidenceAdapterKeepsPartialAndDeadline(t *testing.T) {
	eng := oengine.New(oengine.Config{Provider: evidenceErrorProvider{}, RetryInitialBackoff: time.Millisecond})
	out, err := runOliumOnEngineWithThinking(context.Background(), nil, eng, "prompt", nil, nil, false)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(out.Text, "partial answer") || !isRetryableAgentError(context.Background(), err) {
		t.Fatalf("partial/error sentinel lost: out=%+v err=%v", out, err)
	}
}
