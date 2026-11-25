package server

import (
	"context"
	"net/http"
	"testing"
	"unsafe"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestIngestSourceHeaderOwnsBytesBeforeWriterContinuation(t *testing.T) {
	const source = "burp"
	released := make(chan struct{})
	continued := make(chan string, 1)
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Request().Header.Set(IngestSourceHeader, source)
		err := c.Next()
		// ingestSource is passed to a RecordWriter whose shard goroutine can
		// retain the source after this request returns. Reuse the header only
		// after the handler has handed the value off.
		backing := c.Request().Header.Peek(IngestSourceHeader)
		backing[0] = 'x'
		close(released)
		return err
	})
	app.Post("/ingest", func(c fiber.Ctx) error {
		retained := ingestSource(c)
		go func() {
			<-released
			continued <- retained
		}()
		return c.SendStatus(http.StatusAccepted)
	})

	resp, _ := doReq2(t, app, http.MethodPost, "/ingest", "", nil)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Equal(t, source, <-continued, "writer source label must not alias Fiber's reusable header bytes")
}

// The resolver's returned UUID is retained by the session-log stream writer.
// Mutating the exact c.Params backing after the handler returns models Fiber's
// documented request-lifetime boundary without confusing it with URI().Path().
func TestSessionPathUUIDOwnsBytesBeforeReleasedContinuation(t *testing.T) {
	ctx := context.Background()
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, config.DefaultSettings())

	const runID = "session-a"
	sessionDir := t.TempDir()
	require.NoError(t, repo.CreateAgenticScan(ctx, &database.AgenticScan{
		UUID: runID, ProjectUUID: database.DefaultProjectUUID,
		Mode: "agent", Status: "completed", SessionDir: sessionDir,
	}))

	released := make(chan struct{})
	continued := make(chan string, 1)
	var rawParam string
	app := fiber.New() // Keep production-like Immutable=false.
	app.Use(func(c fiber.Ctx) error {
		err := c.Next()
		// Fiber documents Params strings as handler-lifetime only. Its mutable
		// mode returns a view into the route path scratch buffer. Mutate that
		// exact source (not URI().Path(), which is a different buffer) after the
		// handler returns and before releasing the continuation.
		paramBytes := unsafe.Slice(unsafe.StringData(rawParam), len(rawParam))
		paramBytes[0] = 'x'
		close(released)
		return err
	})
	app.Get("/sessions/:id", func(c fiber.Ctx) error {
		rawParam = c.Params("id")
		resolvedDir, resolvedID, answered, err := h.resolveSessionDirForRun(c)
		require.NoError(t, err)
		require.False(t, answered)
		require.Equal(t, sessionDir, resolvedDir)
		go func() {
			<-released
			continued <- resolvedID
		}()
		return c.SendStatus(http.StatusAccepted)
	})

	resp, _ := doReq2(t, app, http.MethodGet, "/sessions/"+runID, "", nil)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	require.Equal(t, runID, <-continued, "retained path UUID must not alias Fiber's reusable URI bytes")
}
