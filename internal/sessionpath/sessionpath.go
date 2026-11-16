// Package sessionpath contains safe path helpers for per-run session directories.
package sessionpath

import (
	"fmt"
	"path/filepath"
	"strings"
)

const maxRunIDLength = 255

// RunDir returns the directory for runID under root. Run IDs are allowed to be
// historical, non-UUID identifiers, but must remain a single safe path segment.
func RunDir(root, runID string) (string, error) {
	if runID == "" || runID == "." || runID == ".." || len(runID) > maxRunIDLength ||
		filepath.Base(runID) != runID || strings.ContainsAny(runID, `/\\`) ||
		strings.Contains(runID, "..") || strings.IndexByte(runID, 0) >= 0 {
		return "", fmt.Errorf("invalid session run ID")
	}
	return filepath.Join(root, runID), nil
}
