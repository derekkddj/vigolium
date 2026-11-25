package server

import (
	"io"
	"io/fs"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
)

func TestNextChunkFSBoundary(t *testing.T) {
	files := fstest.MapFS{
		"_next/static/app/[[...id]]/page.js": {Data: []byte("chunk")},
		"api/[private]":                      {Data: []byte("not a chunk")},
		"_next/static/app/%5B/page.js":       {Data: []byte("literal percent")},
	}
	assets := nextChunkFS{FS: files}
	for _, name := range []string{"../index.html", "/index.html", "_next/static/../index.html", "_next/static/\\\\index.html", "_next/static/\x00index.html"} {
		_, err := assets.Open(name)
		require.ErrorIs(t, err, fs.ErrInvalid)
	}
	for _, name := range []string{"api/%5Bprivate%5D", "_next/static/app/%255B/page.js", "_next/static/app/%2Fpage.js", "_next/static/app/%ZZpage.js"} {
		_, err := assets.Open(name)
		require.ErrorIs(t, err, fs.ErrNotExist, "only bracket aliases under _next/static are decoded")
	}
}

func TestUIStaticEncodedChunks(t *testing.T) {
	const chunk = "_next/static/chunks/app/findings/[[...id]]/page-test.js"
	files := fstest.MapFS{
		chunk:        {Data: []byte("window.chunkLoaded = true;")},
		"index.html": {Data: []byte("dashboard")},
	}
	app := fiber.New()
	app.Use("/", uiStaticMiddleware(files))
	app.Use(BearerAuth([]string{"test-only-key"}, nil))
	app.Get("/api/private", func(c fiber.Ctx) error { return c.SendString(c.OriginalURL()) })
	for _, path := range []string{
		"/" + chunk,
		"/_next/static/chunks/app/findings/%5B%5B...id%5D%5D/page-test.js",
		"/_next/static/chunks/app/findings/%5b%5b...id%5d%5d/page-test.js?cache=1",
	} {
		for _, method := range []string{"GET", "HEAD"} {
			t.Run(method+path, func(t *testing.T) {
				resp, err := app.Test(httptest.NewRequest(method, path, nil))
				require.NoError(t, err)
				defer resp.Body.Close()
				require.Equal(t, 200, resp.StatusCode)
				require.Contains(t, resp.Header.Get("Content-Type"), "javascript")
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				if method == "GET" {
					require.Equal(t, string(files[chunk].Data), string(body))
				} else {
					require.Empty(t, body)
				}
			})
		}
	}
	for _, path := range []string{
		"/api/private?target=%5Btest%5D",
		"/_next/static/missing.js",
		"/_next/static/chunks/app/findings/%255B%255B...id%255D%255D/page-test.js",
		"/_next/static/chunks/app/findings/%5B%5B...id%5D%5D%2Fpage-test.js",
		"/_next/static/%2e%2e/api/private",
		"/_next/static/%5Cindex.html",
		"/_next/static/%00index.html",
		"/_next/static/%ZZindex.html",
	} {
		t.Run("denied"+path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			// Opaque preserves malformed escapes on the wire; NewRequest's URL
			// parser would reject them before the server could validate them.
			req.URL.Opaque = path
			req.RequestURI = path
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, 401, resp.StatusCode)
		})
	}
	const target = "/api/private?target=%5Btest%5D"
	req := httptest.NewRequest("GET", target, nil)
	req.Header.Set("Authorization", "Bearer test-only-key")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, target, string(body), "static lookup must not rewrite the request target")
}
