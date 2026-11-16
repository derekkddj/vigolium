package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

func TestArtifactPreviewPagesAndDownload(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)
	dir := t.TempDir()
	// Deliberately splits UTF-8 and JSONL at page boundaries: paging must
	// preserve bytes, not decode or reshape each page independently.
	content := []byte("{\"command\":\"á\"}\n{\"result\":\"complete\"}\n")
	if err := os.WriteFile(filepath.Join(dir, "transcript.jsonl"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	run := seedAgentSession(t, repo, dir)
	base := "/api/agent/sessions/" + run + "/artifacts/transcript.jsonl"
	var collected []byte
	for offset := 0; offset < len(content); offset += 7 {
		path := base + "?max_bytes=7&offset=" + strconv.Itoa(offset)
		resp, body, err := getRequest(app, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page status=%d body=%s", resp.StatusCode, body)
		}
		if resp.Header.Get("X-Artifact-Offset") != strconv.Itoa(offset) ||
			resp.Header.Get("X-Artifact-Returned-Bytes") != strconv.Itoa(len(body)) ||
			resp.Header.Get("X-Artifact-Total-Size") != strconv.Itoa(len(content)) ||
			resp.Header.Get("X-Artifact-Truncated") != "1" {
			t.Fatalf("incorrect page receipt: %v", resp.Header)
		}
		collected = append(collected, body...)
	}
	if !bytes.Equal(content, collected) {
		t.Fatalf("paged archive changed bytes: %q", collected)
	}

	resp, body, err := getRequest(app, base+"?download=1&max_bytes=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, content) {
		t.Fatalf("download applied preview cap: status=%d body=%q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Artifact-Truncated") != "0" ||
		resp.Header.Get("Content-Disposition") != "attachment; filename=transcript.jsonl" ||
		resp.Header.Get("Content-Type") != "application/octet-stream" ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("incorrect download receipt: %v", resp.Header)
	}
	resp, body, err = getRequest(app, base+"?offset="+strconv.Itoa(len(content)), nil)
	if err != nil || resp.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("EOF page: response=%v bytes=%d err=%v", resp, len(body), err)
	}
	for _, query := range []string{"offset=-1", "offset=no", "offset=99999", "offset=9223372036854775808", "download=1&offset=0"} {
		resp, _, err := getRequest(app, base+"?"+query, nil)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid query %q: response=%v err=%v", query, resp, err)
		}
	}
}

func TestArtifactDownloadRemainsScopedAndAuthenticated(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.log"), []byte("private fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := seedAgentSession(t, repo, dir)
	app := fiber.New()
	app.Use(BearerAuth([]string{"fixture-key"}, nil))
	app.Use(ProjectUUIDMiddleware(nil))
	app.Get("/api/agent/sessions/:id/artifacts/*", h.HandleAgentSessionArtifact)
	path := "/api/agent/sessions/" + run + "/artifacts/runtime.log?download=1"
	for _, tc := range []struct {
		name, token, project string
		status               int
	}{
		{"no token", "", "", http.StatusUnauthorized},
		{"other project", "fixture-key", uuid.NewString(), http.StatusNotFound},
		{"owner project", "fixture-key", "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.project != "" {
				req.Header.Set("X-Project-UUID", tc.project)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status || (tc.status != http.StatusOK && bytes.Contains(body, []byte("private fixture"))) {
				t.Fatalf("status=%d body=%s", resp.StatusCode, body)
			}
		})
	}
}

func TestArtifactDownloadCannotEscapeMutableSessionTree(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)
	dir := t.TempDir()
	inside := filepath.Join(dir, "inside")
	outside := t.TempDir()
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(inside, "result.log"):  "inside fixture",
		filepath.Join(outside, "result.log"): "must never escape",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink("inside", alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	run := seedAgentSession(t, repo, dir)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			for _, target := range []string{"inside", outside} {
				select {
				case <-stop:
					return
				default:
				}
				next := filepath.Join(dir, "next-alias")
				_ = os.Remove(next)
				if err := os.Symlink(target, next); err == nil {
					_ = os.Rename(next, alias)
				}
			}
		}
	}()
	defer func() { close(stop); wg.Wait() }()
	for i := 0; i < 100; i++ {
		resp, body, err := getRequest(app, "/api/agent/sessions/"+run+"/artifacts/alias/result.log?download=1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("must never escape")) {
			t.Fatal("artifact escaped the rooted directory during path replacement")
		}
		if resp.StatusCode == http.StatusOK && string(body) != "inside fixture" {
			t.Fatalf("unexpected successful artifact: %q", body)
		}
	}
}

func TestLogTailStripDoesNotReportFalseTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.log")
	if err := os.WriteFile(path, []byte("\x1b[31mcomplete\x1b[0m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Get("/log", func(c fiber.Ctx) error { return sendLogTail(c, path, true) })
	for _, tc := range []struct{ query, truncated string }{{"", "false"}, {"?max_bytes=5", "true"}} {
		resp, _, err := getRequest(app, "/log"+tc.query, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.Header.Get("X-Log-Truncated"); got != tc.truncated {
			t.Fatalf("query=%q truncated=%q want=%q", tc.query, got, tc.truncated)
		}
	}
}

func TestCORSExposesArchiveReceipts(t *testing.T) {
	app := fiber.New()
	registerRoutes(app, &Handlers{}, ServerConfig{
		CORSAllowedOrigins: "https://ui.example.test", NoAuth: true, DemoOnly: true,
	})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://ui.example.test")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	exposed := strings.ToLower(resp.Header.Get("Access-Control-Expose-Headers"))
	for _, header := range []string{"X-Log-Size", "X-Log-Truncated", "X-Artifact-Total-Size", "X-Artifact-Truncated", "X-Artifact-Offset", "X-Artifact-Returned-Bytes", "Content-Disposition"} {
		if !strings.Contains(exposed, strings.ToLower(header)) {
			t.Errorf("CORS hides %s: %q", header, exposed)
		}
	}
}
