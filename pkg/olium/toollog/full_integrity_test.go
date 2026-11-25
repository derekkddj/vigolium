package toollog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestFullRuntimeLogDetectsChangedArchivedStreams(t *testing.T) {
	for _, mutation := range []string{"truncate", "same-length replacement", "append"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			a, err := tool.NewCallArchive(dir, "synthetic", "bash", nil)
			if err != nil {
				t.Fatal(err)
			}
			a.WriteStream("stdout", []byte("original"))
			a.WriteStream("stderr", nil)
			receipt := a.Finish(tool.Result{})
			entry := receipt["streams"].(map[string]any)["stdout"].(map[string]any)
			path := filepath.Join(dir, filepath.FromSlash(entry["path"].(string)))
			var changed []byte
			switch mutation {
			case "same-length replacement":
				changed = []byte("replaced")
			case "append":
				changed = []byte("original-extra")
			}
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			logger := New(&output).WithFullOutput(dir)
			logger.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolName: "bash", ToolDetails: map[string]any{tool.ArchiveDetailsKey: receipt}})
			logger.ReportIncomplete()
			if logger.Err() == nil || !strings.Contains(output.String(), "changed since capture") || !strings.Contains(output.String(), "Runtime log incomplete") || strings.Contains(output.String(), "archive complete:") {
				t.Fatal("changed archive falsely presented as verified complete runtime output")
			}
			if receipt["complete"] != true {
				t.Fatal("renderer mutated the original capture receipt")
			}
		})
	}
}

type recoverableFullWriter struct {
	bytes.Buffer
	failed bool
}

func (w *recoverableFullWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, errors.New("synthetic private error")
	}
	return w.Buffer.Write(p)
}

func TestFullRuntimeLogRecoveredWriterGetsIncompleteMarker(t *testing.T) {
	writer := &recoverableFullWriter{}
	logger := New(writer).WithFullOutput(t.TempDir())
	logger.HandleTool(engine.Event{Type: engine.EventToolExecStart, ToolName: "synthetic"})
	logger.HandleTool(engine.Event{Type: engine.EventToolExecEnd, ToolName: "synthetic", ToolResult: "retained result"})
	logger.ReportIncomplete()
	if logger.Err() == nil || !strings.Contains(writer.String(), "Runtime log incomplete") || !strings.Contains(writer.String(), "retained result") || strings.Contains(writer.String(), "synthetic private error") {
		t.Fatal("recovered sink concealed incomplete log or exposed private error")
	}
}
