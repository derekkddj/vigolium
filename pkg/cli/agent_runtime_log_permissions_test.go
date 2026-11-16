package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestNewAgentRuntimeLogPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX evidence permissions")
	}
	dir := filepath.Join(t.TempDir(), "session")
	writer, closer := teeToRuntimeLog(io.Discard, dir)
	if closer == nil {
		t.Fatal("runtime log not created")
	}
	if _, err := writer.Write([]byte("fixture progress\n")); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, filepath.Join(dir, config.RuntimeLogFilename)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("new runtime evidence allows other users: %s mode=%o", path, info.Mode().Perm())
		}
	}
}
