package server

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestArtifactEncodedNamesRoundTripExactlyOnce(t *testing.T) {
	for _, unescape := range []bool{false, true} {
		t.Run(fmt.Sprintf("fiber-unescape-%t", unescape), func(t *testing.T) {
			h, repo, _ := newAgentTestHandlers(t)
			app := fiber.New(fiber.Config{UnescapePath: unescape})
			app.Use(ProjectUUIDMiddleware(nil))
			app.Get("/api/agent/sessions/:id/artifacts/*", h.HandleAgentSessionArtifact)
			dir := t.TempDir()
			names := []string{
				"a b.log", "a%20b.log", "á#.log",
				"literal%2F.log", "literal%252F.log", "plus+.log", "nested/with space.log",
			}
			if runtime.GOOS != "windows" {
				names = append(names, "question?.log")
			}
			for i, name := range names {
				path := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				// Equal-sized files ensure byte-count verification cannot conceal
				// opening the wrong (percent-encoded) name.
				if err := os.WriteFile(path, []byte(fmt.Sprintf("body-%02d", i)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			run := seedAgentSession(t, repo, dir)
			base := "/api/agent/sessions/" + run + "/artifacts/"
			for i, name := range names {
				parts := strings.Split(name, "/")
				for j := range parts {
					parts[j] = url.PathEscape(parts[j])
				}
				for _, query := range []string{"?max_bytes=1024", "?download=1"} {
					resp, body, err := getRequest(app, base+strings.Join(parts, "/")+query, nil)
					want := fmt.Sprintf("body-%02d", i)
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != http.StatusOK || string(body) != want {
						t.Fatalf("name=%q query=%q status=%d body=%q want=%q", name, query, resp.StatusCode, body, want)
					}
				}
			}
			for _, encoded := range []string{"%2e%2e/outside.log", "%2Fetc/passwd", "nested/%2e%2e/%2e%2e/outside.log"} {
				resp, _, err := getRequest(app, base+encoded+"?download=1", nil)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode == http.StatusOK {
					t.Fatalf("encoded traversal %q was served", encoded)
				}
			}
		})
	}
}
