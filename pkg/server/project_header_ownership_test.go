package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
)

func TestProjectHeaderOwnsBytesBeforeRequestReuse(t *testing.T) {
	const project = "de9042c9-53c2-44e4-9e8e-7d2d6c6d224f"
	for _, header := range []string{project, "  " + project + "  "} {
		t.Run(header, func(t *testing.T) {
			app := fiber.New() // Default Immutable=false, like the production server.
			app.Use(func(c fiber.Ctx) error {
				c.Request().Header.Set("X-Project-UUID", header)
				return c.Next()
			})
			app.Use(ProjectUUIDMiddleware(nil))
			var retainedAfterReuse, localsAfterReuse string
			app.Get("/scope", func(c fiber.Ctx) error {
				retained := getProjectUUID(c)
				require.Equal(t, project, retained)
				// A config/status/map key or background closure retains this string
				// beyond the request. Simulate pooled header reuse deterministically,
				// without racing a real request or changing ownership in a database.
				backing := c.Request().Header.Peek("X-Project-UUID")
				for i := range backing {
					backing[i] = 'x'
				}
				retainedAfterReuse, localsAfterReuse = retained, getProjectUUID(c)
				return c.SendString(retained)
			})
			resp, body := doReq2(t, app, http.MethodGet, "/scope", "", nil)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, project, retainedAfterReuse, "retained scope aliases request header storage")
			require.Equal(t, project, localsAfterReuse, "locals must own the project identity")
			require.Equal(t, strings.TrimSpace(header), string(body))
		})
	}
}

func TestSwarmConfigRetainsProjectAfterHeaderReuse(t *testing.T) {
	const project = "de9042c9-53c2-44e4-9e8e-7d2d6c6d224f"
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, nil, nil, config.DefaultSettings())
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(nil))
	released := make(chan struct{})
	result := make(chan agent.SwarmConfig, 1)
	var before agent.SwarmConfig
	app.Get("/handoff", func(c fiber.Ctx) error {
		projectUUID := getProjectUUID(c)
		req := AgentSwarmRequest{URL: "https://diagnostic.invalid", ScanUUID: "native-pinned"}
		before = h.buildSwarmConfig(req, projectUUID)
		// No runner/provider/network is executed. Both builder timings model
		// the server's SSE/background handoff around reusable request storage.
		go func() {
			<-released
			result <- h.buildSwarmConfig(req, projectUUID)
		}()
		backing := c.Request().Header.Peek("X-Project-UUID")
		for i := range backing {
			backing[i] = 'x'
		}
		return c.SendStatus(http.StatusOK)
	})
	resp, _ := doReq2(t, app, http.MethodGet, "/handoff", "", map[string]string{"X-Project-UUID": project})
	close(released)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	select {
	case after := <-result:
		for _, cfg := range []agent.SwarmConfig{before, after} {
			require.Equal(t, project, cfg.ProjectUUID)
			require.Equal(t, "native-pinned", cfg.ScanUUID)
			require.Empty(t, cfg.AgenticScanUUID, "parent identity remains caller-owned and distinct")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("background config handoff did not complete")
	}
}
