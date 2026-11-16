//go:build unix

package server

import (
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestArtifactSpecialFileDoesNotBlockOpen(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)
	dir := t.TempDir()
	pipe := filepath.Join(dir, "result.log")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("cannot create FIFO fixture: %v", err)
	}
	// Release a regressed blocking reader during test cleanup, rather than
	// leaving a leaked handler goroutine even when this assertion fails.
	done := make(chan struct{})
	defer func() {
		f, err := os.OpenFile(pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = f.Close()
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	run := seedAgentSession(t, repo, dir)
	go func() {
		defer close(done)
		resp, _, err := getRequest(app, "/api/agent/sessions/"+run+"/artifacts/result.log?download=1", nil)
		if err != nil {
			t.Errorf("request: %v", err)
			return
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("special artifact status=%d want=404", resp.StatusCode)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("artifact open blocked on a FIFO before rejecting its type")
	}
}
