//go:build unix

package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAuditRetentionFIFOReadsDoNotBlockFinalization(t *testing.T) {
	for _, name := range []string{"audit-state.json", "findings/H1.md"} {
		t.Run(name, func(t *testing.T) {
			r := auditEvidenceFixture(t, t.TempDir())
			fifo := filepath.Join(r.cfg.SourcePath, "vigolium-results", name)
			if err := os.Remove(fifo); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				r.syncStateOnce(context.Background())
				r.syncFindingsIncremental()
				_ = r.readCurrentState()
				done <- r.archiveAndImport(context.Background())
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("FIFO source accepted")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("FIFO read or sync mutex blocked finalization")
			}
			if r.FindingStats().Parsed != 0 || r.lastStateHash != "" && name == "audit-state.json" {
				t.Fatal("FIFO source was imported or fingerprinted")
			}
			if _, err := os.Lstat(fifo); err != nil {
				t.Fatalf("FIFO source not retained: %v", err)
			}
		})
	}
}

func TestAuditRetentionNonblockingOpenRejectsFIFOReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Exercise the open used after validation: even a FIFO replacement cannot
	// block before the post-open regular-file check gets a chance to reject it.
	f, err := openAuditInRoot(root, "changed")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Mode().IsRegular() {
		t.Fatalf("FIFO mistaken for regular file: %v", err)
	}
}

func TestAuditRetentionPermissionErrorRetainsAndDoesNotImport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses fixture read permission denial")
	}
	r := auditEvidenceFixture(t, t.TempDir())
	name := filepath.Join(r.cfg.SourcePath, "vigolium-results", "findings", "H1.md")
	if err := os.Chmod(name, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(name, 0o600)
	err := r.archiveAndImport(context.Background())
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("permission error hidden: %v", err)
	}
	if r.FindingStats().Parsed != 0 {
		t.Fatal("permission-denied evidence silently skipped")
	}
	if _, err := os.Lstat(name); err != nil {
		t.Fatalf("unreadable source deleted: %v", err)
	}
}
