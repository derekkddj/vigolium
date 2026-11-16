package authsession

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupSessionDirsPreservesOldRootsWithActiveDescendantWrites(t *testing.T) {
	base := t.TempDir()
	run := filepath.Join(base, "active-or-resumed", "nested")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(run)
	old := time.Now().Add(-7 * 24 * time.Hour)
	if err := os.Chtimes(root, old, old); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(run, "runtime.log")
	if err := os.WriteFile(evidence, []byte("active descendant write"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.ModTime().Before(time.Now().Add(-48*time.Hour)) {
		t.Fatalf("fixture must retain old top-level mtime: %v", err)
	}
	for _, age := range []time.Duration{48 * time.Hour, 0, -time.Hour} {
		n, err := CleanupSessionDirs(base, age)
		if n != 0 || !errors.Is(err, ErrUnsafeSessionRetention) {
			t.Fatalf("cleanup(%s) = %d, %v; want disabled", age, n, err)
		}
		data, err := os.ReadFile(evidence)
		if err != nil || string(data) != "active descendant write" {
			t.Fatalf("evidence was lost: %q, %v", data, err)
		}
	}
}
