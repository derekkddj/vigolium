package sessionpath

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDir(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"../escape", "..", ".", "/absolute", `nested\\run`, "nested/run", "run\x00id", "run..id", strings.Repeat("a", maxRunIDLength+1)} {
		if _, err := RunDir(root, id); err == nil {
			t.Errorf("RunDir(%q) accepted unsafe ID", id)
		}
	}

	for _, id := range []string{"scan-legacy-id", "setup-12345678", "api-a1b2c3d4"} {
		got, err := RunDir(root, id)
		if err != nil {
			t.Errorf("RunDir(%q): %v", id, err)
			continue
		}
		if want := filepath.Join(root, id); got != want {
			t.Errorf("RunDir(%q) = %q, want %q", id, got, want)
		}
	}
}
