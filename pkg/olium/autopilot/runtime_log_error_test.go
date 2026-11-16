package autopilot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type recoverableRuntimeWriter struct {
	output bytes.Buffer
	failed bool
}

func (w *recoverableRuntimeWriter) Write(p []byte) (int, error) {
	if !w.failed && bytes.HasPrefix(p, []byte("\nTool call")) {
		w.failed = true
		return 0, errors.New("synthetic private storage error")
	}
	return w.output.Write(p)
}

func TestAutopilotSurfacesNonFatalRuntimeRecordingFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writer := &recoverableRuntimeWriter{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := Run(ctx, Options{
		Provider: toolLoopProvider{in: 1000, out: 500}, Model: "synthetic",
		Out: io.Discard, ToolLog: writer, NoSkillFilter: true,
		SourcePath: t.TempDir(), SessionDir: t.TempDir(), MaxTurns: 50,
		TokenBudget: 2000,
	})
	if err != nil || result == nil || result.RecordingError == "" || result.BudgetStop != BudgetTokens {
		t.Fatalf("runtime recording failure changed execution or warning vanished: err=%v", err)
	}
	if !strings.Contains(writer.output.String(), "Runtime log incomplete") || strings.Contains(writer.output.String(), "synthetic private storage error") {
		t.Fatal("recovered autopilot log concealed missing bytes or leaked private error")
	}
}
