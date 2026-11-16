package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func TestToolArchiveNestedBinaryExportIsExactAndProjectScoped(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(nil))
	app.Get("/api/agent/sessions/:id/artifacts", h.HandleAgentSessionArtifacts)
	app.Get("/api/agent/sessions/:id/artifacts/*", h.HandleAgentSessionArtifact)
	dir := t.TempDir()
	command := strings.Repeat("synthetic full argument ", 1000)
	payload := bytes.Repeat([]byte{0, 0xff, 0xfe, '\r', '\n', 'x'}, 400000)
	result := tool.ArchiveExecution(context.Background(), dir, "same/provider-id", "synthetic", map[string]any{"command": command}, func(context.Context) tool.Result {
		return tool.Result{Content: string(payload)}
	})
	receipt := result.Details[tool.ArchiveDetailsKey].(map[string]any)
	if receipt["complete"] != true {
		t.Fatal("synthetic archive did not complete")
	}
	run := seedAgentSession(t, repo, dir)
	base := "/api/agent/sessions/" + run + "/artifacts/"
	path := receipt["result"].(string)
	resp, body, err := getRequest(app, base+path+"?download=1&max_bytes=1", nil)
	if err != nil || resp.StatusCode != http.StatusOK || len(body) != len(payload) || sha256.Sum256(body) != sha256.Sum256(payload) || resp.Header.Get("X-Artifact-Truncated") != "0" {
		t.Fatalf("nested binary download applied a preview cap or changed bytes: err=%v returned=%d expected=%d", err, len(body), len(payload))
	}
	if resp.Header.Get("Content-Disposition") != "attachment; filename="+filepath.Base(path) {
		t.Fatal("nested full-byte export is not an attachment")
	}
	for _, relative := range []string{path, receipt["arguments"].(string), receipt["metadata"].(string)} {
		resp, body, err := getRequest(app, base+relative+"?download=1", map[string]string{"X-Project-UUID": uuid.NewString()})
		if err != nil || resp.StatusCode != http.StatusNotFound || bytes.Contains(body, []byte(command)) || bytes.Contains(body, payload[:32]) {
			t.Fatal("archive hydration crossed project isolation")
		}
	}
	resp, body, err = getRequest(app, "/api/agent/sessions/"+run+"/artifacts", nil)
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(path)) {
		t.Fatal("nested tool archives are absent from session artifact inventory")
	}
}
