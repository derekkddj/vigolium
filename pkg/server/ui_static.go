package server

import (
	"io/fs"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

// nextChunkFS resolves Next's bracketed route chunk names without rewriting the
// HTTP path. Fiber intentionally preserves reserved-character escapes during
// static lookup; browsers encode the literal brackets in Next's exported names.
// Only bracket escapes under the public chunk tree are aliases: never decode
// separators, dot segments, percent signs (double encoding), or API paths.
// Fiber's static middleware still validates the routed path before calling Open.
var nextChunkBrackets = strings.NewReplacer("%5B", "[", "%5b", "[", "%5D", "]", "%5d", "]")

type nextChunkFS struct {
	fs.FS
}

func (f nextChunkFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if strings.HasPrefix(name, "_next/static/") {
		name = nextChunkBrackets.Replace(name)
	}
	return f.FS.Open(name)
}

func uiStaticMiddleware(uiFS fs.FS) fiber.Handler {
	return static.New("", static.Config{
		FS:         nextChunkFS{FS: uiFS},
		IndexNames: []string{"index.html"},
	})
}
