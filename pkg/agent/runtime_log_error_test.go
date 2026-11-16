package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

type recoveringRuntimeWriter struct {
	output bytes.Buffer
	failed bool
}

func (w *recoveringRuntimeWriter) Write(p []byte) (int, error) {
	if !w.failed && bytes.HasPrefix(p, []byte("\nTool call")) {
		w.failed = true
		return 0, errors.New("synthetic private storage error")
	}
	return w.output.Write(p)
}

func TestAgentRuntimeRecordingFailureIsNonFatalAndVisibleAfterRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	reg := tool.NewRegistry()
	reg.Register(tool.NewBash(nil))
	eng := oengine.New(oengine.Config{Provider: &fullRuntimeProvider{command: "printf synthetic"}, Tools: reg, SpillDir: t.TempDir()})
	writer := &recoveringRuntimeWriter{}
	out, err := runOliumOnEngineWithThinking(context.Background(), nil, eng, "synthetic", NewSynchronizedWriter(writer), nil, false)
	if err != nil || out.Text != "final assistant answer" || out.RecordingError == "" {
		t.Fatalf("recording failure changed parsed output/execution or vanished: err=%v", err)
	}
	if !strings.Contains(writer.output.String(), "Runtime log incomplete") || strings.Contains(writer.output.String(), "synthetic private storage error") {
		t.Fatal("recovered runtime log did not signal incomplete rendering safely")
	}
}

type recordingWarningRuntime struct{ fakeRuntime }

func (r *recordingWarningRuntime) RunPrompt(context.Context, *config.OliumConfig, string, io.Writer, io.Writer, string, bool, RecordSpec) (oliumRunOutput, error) {
	r.runPromptCalls.Add(1)
	return oliumRunOutput{Text: "retained assistant answer", RecordingError: "complete runtime tool rendering failed"}, nil
}

func TestEnginePreservesRecordingWarningWithoutRetrying(t *testing.T) {
	rt := &recordingWarningRuntime{}
	eng := &Engine{runtime: rt}
	result, err := eng.Run(context.Background(), Options{PromptInline: "synthetic"})
	if err != nil || result.RawOutput != "retained assistant answer" || result.RecordingError == "" || rt.runPromptCalls.Load() != 1 {
		t.Fatal("recording warning hidden or treated as retryable execution error")
	}
}
