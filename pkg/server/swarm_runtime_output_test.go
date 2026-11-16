package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

func TestSwarmNativeRuntimeOutputScoped(t *testing.T) {
	var first, second bytes.Buffer
	ctx1 := withSwarmRuntimeOutput(context.Background(), agent.NewSynchronizedWriter(&first))
	ctx2 := withSwarmRuntimeOutput(context.Background(), agent.NewSynchronizedWriter(&second))
	// Context values survive the child deadlines native phases use.
	child, cancel := context.WithTimeout(ctx1, time.Second)
	defer cancel()
	callbacks := []func(scanevents.Event){swarmNativeRuntimeCallback(child), swarmNativeRuntimeCallback(ctx2)}
	var wg sync.WaitGroup
	for i, callback := range callbacks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := []string{"native-first", "native-second"}[i]
			for range 100 {
				callback(scanevents.Event{Type: scanevents.TypePhaseProgress, ScanUUID: id, Phase: "spidering", RequestsSent: scanevents.Int64(0), Findings: scanevents.Int64(0)})
			}
		}()
	}
	wg.Wait()
	for i, buffer := range []*bytes.Buffer{&first, &second} {
		own := []string{"native-first", "native-second"}[i]
		other := []string{"native-second", "native-first"}[i]
		text := buffer.String()
		if strings.Count(text, "scan="+own) != 100 || strings.Contains(text, other) {
			t.Fatalf("run %d mixed or lost events: %q", i, text)
		}
		if !strings.Contains(text, "requests=0 findings=0") {
			t.Fatal("zero progress counters must remain visible")
		}
	}
	if swarmNativeRuntimeCallback(context.Background()) != nil {
		t.Fatal("unrelated native runs must not inherit an agent writer")
	}
	if swarmNativeRuntimeCallback(withSwarmRuntimeOutput(context.Background(), nil)) != nil {
		t.Fatal("nil writer should be a no-op")
	}
}

func TestSwarmNativeRuntimeOutputMetadataOnly(t *testing.T) {
	var buffer bytes.Buffer
	writer := agent.NewSynchronizedWriter(&buffer)
	writeSwarmNativeRuntimeEvent(writer, scanevents.Event{
		Type: scanevents.TypeFindingNew, ScanUUID: "native-test", Phase: "dynamic-assessment",
		ModuleID: "secret-detect", Severity: "high",
		URL:     "https://user:password@example.test/product?token=secret-value#private-fragment",
		Message: "Authorization: Bearer private-token",
	})
	text := buffer.String()
	if !strings.Contains(text, "module=secret-detect severity=high origin=https://example.test") {
		t.Fatalf("expected safe finding metadata: %q", text)
	}
	for _, secret := range []string{"user:", "password", "secret-value", "private-fragment", "private-token", "Authorization"} {
		if strings.Contains(text, secret) {
			t.Fatalf("runtime progress exposed %q: %q", secret, text)
		}
	}
	before := buffer.Len()
	writeSwarmNativeRuntimeEvent(writer, scanevents.Event{Type: scanevents.TypeScanPlan, Target: "private-target", Message: "private-plan"})
	if buffer.Len() != before {
		t.Fatal("plan/auth details should not be forwarded")
	}
	writeSwarmNativeRuntimeEvent(writer, scanevents.Event{
		Type: scanevents.TypePhaseFinished, Phase: "discovery", Status: "curtailed", DurationMS: 1000,
		Done: scanevents.Int64(10), Total: scanevents.Int64(20), Unit: "records",
		Reasons: []string{"phase_deadline"}, Limits: []string{"request_budget"},
	})
	for _, expected := range []string{"status=curtailed", "duration_ms=1000", "records=10/20", "reasons=phase_deadline", "limits=request_budget"} {
		if !strings.Contains(buffer.String(), expected) {
			t.Fatalf("missing %q: %q", expected, buffer.String())
		}
	}
}

func TestSwarmRuntimeOrigin(t *testing.T) {
	for input, expected := range map[string]string{
		"http://example.test:8080/product?id=1":                  "http://example.test:8080",
		"https://user:pass@example.test/path?token=x#secret":     "https://example.test",
		"https://example.test/reset-password/private-path-token": "https://example.test",
		"/relative?token=x":    "",
		"file:///root/private": "",
		"http://%invalid":      "",
	} {
		if actual := swarmRuntimeOrigin(input); actual != expected {
			t.Errorf("swarmRuntimeOrigin(%q)=%q, want %q", input, actual, expected)
		}
	}
}

// Exercise the same logs API and SSE chunk protocol STREAMING RESPONSE uses.
// No native scan, external target or paid model is involved.
func TestSwarmRuntimeOutputServedToWeb(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)
	sessionDir := t.TempDir()
	path := filepath.Join(sessionDir, config.RuntimeLogFilename)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := agent.NewSynchronizedWriter(file)
	ctx := withSwarmRuntimeOutput(context.Background(), writer)
	agent.WriteRuntimeProgress(writer, "swarm", "native-discover", "phase started")
	callback := swarmNativeRuntimeCallback(ctx)
	callback(scanevents.Event{Type: scanevents.TypePhaseStarted, ScanUUID: "native-web-test", Phase: "spidering"})
	callback(scanevents.Event{Type: scanevents.TypePhaseProgress, ScanUUID: "native-web-test", Phase: "spidering", RequestsSent: scanevents.Int64(241)})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	uuid := seedAgentSession(t, repo, sessionDir)
	for _, headers := range []map[string]string{nil, {"Accept": "text/event-stream"}} {
		resp, body, err := getRequest(app, "/api/agent/sessions/"+uuid+"/logs?strip=1", headers)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200, got %d: %s", resp.StatusCode, body)
		}
		for _, expected := range []string{"native-discover", "phase.started", "phase.progress", "requests=241", "native-web-test"} {
			if !strings.Contains(string(body), expected) {
				t.Fatalf("web logs missing %q: %s", expected, body)
			}
		}
		if headers != nil && (!strings.Contains(string(body), `"type":"chunk"`) || !strings.Contains(string(body), `"type":"done"`)) {
			t.Fatalf("expected SSE chunk and done events: %s", body)
		}
	}
}

func TestSwarmRuntimeOutputConcurrentProducers(t *testing.T) {
	var buffer bytes.Buffer
	writer := agent.NewSynchronizedWriter(&buffer)
	callback := swarmNativeRuntimeCallback(withSwarmRuntimeOutput(context.Background(), writer))
	var wg sync.WaitGroup
	for producer := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				switch producer {
				case 0:
					callback(scanevents.Event{Type: scanevents.TypePhaseProgress, Phase: "spidering", RequestsSent: scanevents.Int64(int64(i))})
				case 1:
					agent.WriteRuntimeProgress(writer, "swarm", "native-discover", "swarm-progress")
				case 2:
					_, _ = fmt.Fprintln(writer, "agent-raw-chunk")
				}
			}
		}()
	}
	wg.Wait()
	text := buffer.String()
	for _, expected := range []string{"phase.progress", "swarm-progress", "agent-raw-chunk"} {
		if strings.Count(text, expected) != 100 {
			t.Fatalf("lost/corrupted %s output", expected)
		}
	}
	if len(strings.Split(strings.TrimSpace(text), "\n")) != 300 {
		t.Fatalf("writes were not complete lines: %q", text)
	}
}

type swarmRuntimeTestWriterFunc func([]byte) (int, error)

func (f swarmRuntimeTestWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestSwarmRuntimeTeeKeepsSSEOnDiskFailure(t *testing.T) {
	for _, shortWrite := range []bool{false, true} {
		var stream bytes.Buffer
		attempts := 0
		tee := &swarmRuntimeTee{
			log: swarmRuntimeTestWriterFunc(func(p []byte) (int, error) {
				attempts++
				if shortWrite {
					return len(p) - 1, nil
				}
				return 0, errors.New("test disk full")
			}),
			stream: &stream,
		}
		writer := agent.NewSynchronizedWriter(tee)
		for _, text := range []string{"first\n", "second\n"} {
			if n, err := writer.Write([]byte(text)); err != nil || n != len(text) {
				t.Fatalf("disk failure interrupted live output: n=%d err=%v", n, err)
			}
		}
		if stream.String() != "first\nsecond\n" || attempts != 1 {
			t.Fatalf("unexpected output/retries: %q attempts=%d", stream.String(), attempts)
		}
	}
}

func TestSwarmRuntimeOutputLiveFollowAndReconnect(t *testing.T) {
	path := filepath.Join(t.TempDir(), config.RuntimeLogFilename)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	writer := agent.NewSynchronizedWriter(file)
	callback := swarmNativeRuntimeCallback(withSwarmRuntimeOutput(context.Background(), writer))
	var done atomic.Bool
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	followerDone := make(chan struct{})
	go func() {
		defer close(followerDone)
		defer func() { _ = pw.Close() }()
		tailSessionLog(bufio.NewWriter(pw), path, done.Load, time.Millisecond, 5*time.Second, true)
	}()
	firstChunk := make(chan string, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "phase.started") {
				firstChunk <- scanner.Text()
			}
		}
	}()
	callback(scanevents.Event{Type: scanevents.TypePhaseStarted, Phase: "spidering"})
	select {
	case text := <-firstChunk:
		if done.Load() || !strings.Contains(text, `"type":"chunk"`) {
			t.Fatalf("expected live chunk before completion: %s", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no live chunk received before run completion")
	}
	// Disconnect the viewer, then keep producing output to disk.
	_ = pr.Close()
	callback(scanevents.Event{Type: scanevents.TypePhaseProgress, Phase: "spidering", RequestsSent: scanevents.Int64(241)})
	done.Store(true)
	for _, stopped := range []<-chan struct{}{followerDone, readerDone} {
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("log follower did not close after viewer disconnected")
		}
	}
	var replay bytes.Buffer
	tailSessionLog(bufio.NewWriter(&replay), path, done.Load, time.Millisecond, time.Second, true)
	for _, expected := range []string{"phase.started", "phase.progress", "requests=241", `"type":"done"`} {
		if !strings.Contains(replay.String(), expected) {
			t.Fatalf("reconnect lost %q: %s", expected, replay.String())
		}
	}
}
