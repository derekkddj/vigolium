package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewSessionEvidencePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX evidence permissions")
	}
	dir, err := EnsureSessionDir(filepath.Join(t.TempDir(), "sessions"), "fixture-run")
	if err != nil {
		t.Fatal(err)
	}
	writeSessionArtifact(filepath.Join(dir, "result.md"), []byte("fixture result"))
	writePromptToSessionDir(dir, "prompt.md", "fixture prompt")
	writeInputsToSessionDir(dir, nil, "fixture source")
	writeSessionConfigToDir(&AgentSessionConfig{}, dir)
	if err := WriteCheckpointToDir(dir, &SwarmCheckpoint{}); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteExtensionsToSessionDir([]GeneratedExtension{{Filename: "fixture.js", Code: "// fixture"}}, dir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"", "extensions", "result.md", "prompt.md", "inputs.json", "session-config.json", "checkpoint.json", "extensions/fixture.js"} {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("new raw evidence %q permits other users: %o", rel, info.Mode().Perm())
		}
	}
}
