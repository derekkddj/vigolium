package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func writeAuditTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func auditEvidenceFixture(t *testing.T, session string) *AuditAgenticScanner {
	t.Helper()
	source := t.TempDir()
	root := filepath.Join(source, "vigolium-results")
	writeAuditTestFile(t, filepath.Join(root, "audit-state.json"), `{"audits":[{"audit_id":"t1","status":"complete","phases":{}}]}`)
	writeAuditTestFile(t, filepath.Join(root, "findings", "H1.md"), "## Q1-001: SQLi\n\n- **Severity**: High\n- **File**: api.py\n- **Line**: 42\n- **Verdict**: VALID\n")
	return NewAuditAgenticScanner(AuditAgentConfig{SourcePath: source, SessionDir: session}, nil)
}

func TestAuditArchiveAbsentSessionRetainsAndImportsSource(t *testing.T) {
	r := auditEvidenceFixture(t, "")
	core, logs := observer.New(zap.WarnLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	defer restore()
	if err := r.archiveAndImport(context.Background()); err == nil {
		t.Fatal("missing SessionDir must fail archival")
	}
	if r.archiveDir != "" || r.FindingStats().Parsed != 1 {
		t.Fatalf("must import authoritative source: archive=%q, stats=%+v", r.archiveDir, r.FindingStats())
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results", "findings", "H1.md")); err != nil {
		t.Fatalf("source removed without an archive: %v", err)
	}
	if logs.FilterMessage("Audit archive failed; retaining source and importing source evidence").Len() != 1 {
		t.Fatal("source fallback must emit an explicit warning")
	}
}

func TestAuditMonitorAbsentSessionSurfacesArchiveError(t *testing.T) {
	r := auditEvidenceFixture(t, "")
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.monitor(context.Background(), cmd, &syncBuffer{})
	if err := r.Wait(); err == nil {
		t.Fatal("successful subprocess must not hide evidence archive failure")
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); err != nil {
		t.Fatalf("monitor removed unarchived source: %v", err)
	}
}

func TestAuditArchiveImportFailureRetainsVerifiedSource(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	// Fail only finding insertion in this isolated SQLite store. Keep the
	// archive context live so cancellation-aware copies can still complete.
	if _, err := r.repo.DB().Exec(`CREATE TRIGGER fail_audit_finding BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'injected finding persistence failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := r.archiveAndImport(context.Background()); err == nil {
		t.Fatal("finding persistence error must be returned")
	}
	if r.archiveDir == "" {
		t.Fatal("archive should have succeeded before import failure")
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); err != nil {
		t.Fatalf("failed persistence removed source: %v", err)
	}
}

func TestAuditArchiveKeepSourceOutputDir(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.cfg.KeepSourceOutputDir = true
	if err := r.archiveAndImport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); err != nil {
		t.Fatalf("KeepSourceOutputDir was ignored: %v", err)
	}
}

func TestAuditArchiveFailureIgnoresPartialSessionCopy(t *testing.T) {
	session := t.TempDir()
	r := auditEvidenceFixture(t, session)
	// A regular file where a directory should be deterministically prevents
	// publication, even under root. The source remains the import authority.
	writeAuditTestFile(t, filepath.Join(session, "vigolium-results"), "broken archive destination")
	if err := r.archiveAndImport(context.Background()); err == nil {
		t.Fatal("expected archive publication error")
	}
	if r.archiveDir != "" || r.FindingStats().Parsed != 1 {
		t.Fatalf("partial archive imported: %q, %+v", r.archiveDir, r.FindingStats())
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); err != nil {
		t.Fatalf("source lost on copy failure: %v", err)
	}
}

func TestAuditArchiveVerifiedReplacesStaleTreeBeforeSourceRemoval(t *testing.T) {
	session := t.TempDir()
	r := auditEvidenceFixture(t, session)
	writeAuditTestFile(t, filepath.Join(session, "vigolium-results", "stale.md"), "not in source")
	if err := r.archiveAndImport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); !os.IsNotExist(err) {
		t.Fatalf("verified source should be removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.archiveDir, "stale.md")); !os.IsNotExist(err) {
		t.Fatalf("stale incremental file survived full archive: %v", err)
	}
	info, err := os.Stat(filepath.Join(r.archiveDir, "findings", "H1.md"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive files must be private: %v, %v", info, err)
	}
	if r.FindingStats().Parsed != 1 {
		t.Fatalf("verified findings not imported: %+v", r.FindingStats())
	}
}

func TestAuditArchiveRejectsSymlinkAndOverlappingPaths(t *testing.T) {
	for _, kind := range []string{"symlink", "overlap", "missing-source"} {
		t.Run(kind, func(t *testing.T) {
			r := auditEvidenceFixture(t, t.TempDir())
			source := filepath.Join(r.cfg.SourcePath, "vigolium-results")
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(source, "audit-state.json"), filepath.Join(source, "linked.json")); err != nil {
					t.Fatal(err)
				}
			case "overlap":
				r.cfg.SessionDir = source
			case "missing-source":
				r.cfg.SourcePath = filepath.Join(t.TempDir(), "missing")
			}
			if err := r.syncFolderFull(); err == nil || r.archiveDir != "" {
				t.Fatalf("unsafe archive accepted: %v, %q", err, r.archiveDir)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("failed archive removed source: %v", err)
			}
		})
	}
}

func TestAuditArchiveManifestDetectsIncompleteAndSameSizeCopies(t *testing.T) {
	for _, kind := range []string{"missing", "extra", "same-size-edit", "missing-empty-dir"} {
		t.Run(kind, func(t *testing.T) {
			src, dest := t.TempDir(), t.TempDir()
			writeAuditTestFile(t, filepath.Join(src, "report.md"), "aaaa")
			if err := os.Mkdir(filepath.Join(src, "empty"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := copyDir(src, dest); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(dest, "report.md")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				writeAuditTestFile(t, filepath.Join(dest, "stale.md"), "extra")
			case "same-size-edit":
				writeAuditTestFile(t, filepath.Join(dest, "report.md"), "bbbb")
			case "missing-empty-dir":
				if err := os.Remove(filepath.Join(dest, "empty")); err != nil {
					t.Fatal(err)
				}
			}
			a, err := auditFolderManifest(src)
			if err != nil {
				t.Fatal(err)
			}
			b, err := auditFolderManifest(dest)
			if err != nil {
				t.Fatal(err)
			}
			if equalAuditManifests(a, b) {
				t.Fatal("incomplete or corrupt archive passed verification")
			}
		})
	}
}

func TestAuditCopyDirPropagatesCopyError(t *testing.T) {
	src, dest := t.TempDir(), t.TempDir()
	writeAuditTestFile(t, filepath.Join(src, "nested", "report.md"), "source evidence")
	writeAuditTestFile(t, filepath.Join(dest, "nested"), "blocks directory creation")
	if err := copyDir(src, dest); err == nil {
		t.Fatal("copy must propagate destination errors")
	}
	data, err := os.ReadFile(filepath.Join(src, "nested", "report.md"))
	if err != nil || string(data) != "source evidence" {
		t.Fatalf("copy error damaged source: %q, %v", data, err)
	}
}

func TestAuditArtifactWriteFailureIsAtomicAndRetryable(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "report.md")
	writeAuditTestFile(t, dest, "old verified content")
	injected := errors.New("injected stream write failure")
	err := publishAuditArtifact(dest, func(out io.Writer) error {
		_, _ = io.WriteString(out, "partial")
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("write error lost: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "old verified content" {
		t.Fatalf("failed write replaced old evidence: %q, %v", data, err)
	}
	if err := writeAuditArtifact(dest, []byte("complete retry")); err != nil {
		t.Fatal(err)
	}
}

func TestAuditStateFailedWriteRetriesUnchangedContent(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	dest := filepath.Join(r.cfg.SessionDir, "vigolium-results", "audit-state.json")
	// Rename onto an existing directory fails reliably without permissions tricks.
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	r.syncStateOnce(context.Background())
	if r.lastStateHash != "" {
		t.Fatal("failed disk write advanced fingerprint")
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	r.syncStateOnce(context.Background())
	if r.lastStateHash == "" {
		t.Fatal("unchanged state did not retry")
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	}
}

func TestAuditStateFailedDBWriteRetriesUnchangedContent(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	// Missing catalog row makes progress persistence fail after the disk write.
	r.syncStateOnce(context.Background())
	if r.lastStateHash != "" {
		t.Fatal("failed DB update advanced fingerprint")
	}
	run := &database.AgenticScan{UUID: r.agenticScanUUID, Status: "running", ProjectUUID: database.DefaultProjectUUID}
	if err := r.repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	r.syncStateOnce(context.Background())
	got, err := r.repo.GetAgenticScan(context.Background(), run.UUID)
	if err != nil || got.Status != "completed" || r.lastStateHash == "" {
		t.Fatalf("progress did not retry: %+v, %v", got, err)
	}
}

func TestAuditDraftSameSizeSameMtimeEditAndFailedWriteRetry(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	src := filepath.Join(r.cfg.SourcePath, "vigolium-results", "findings-draft", "draft.md")
	writeAuditTestFile(t, src, "aaaa")
	dest := filepath.Join(r.cfg.SessionDir, "vigolium-results", "findings-draft", "draft.md")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	r.syncFindingsIncremental()
	if r.syncedFiles["draft.md"] != "" {
		t.Fatal("failed copy advanced fingerprint")
	}
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	r.syncFindingsIncremental()
	old := time.Now().Add(-time.Hour)
	writeAuditTestFile(t, src, "bbbb") // same size
	if err := os.Chtimes(src, old, old); err != nil {
		t.Fatal(err)
	}
	r.syncFindingsIncremental()
	writeAuditTestFile(t, src, "cccc")
	if err := os.Chtimes(src, old, old); err != nil {
		t.Fatal(err)
	}
	r.syncFindingsIncremental()
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "cccc" {
		t.Fatalf("same-size/same-mtime edit missed: %q, %v", data, err)
	}
}

func TestAuditFinalArchiveSerializesAndStopsPeriodicSync(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				r.syncStateOnce(context.Background())
				r.syncFindingsIncremental()
			}
		}()
	}
	if err := r.syncFolderFull(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	writeAuditTestFile(t, filepath.Join(r.cfg.SourcePath, "vigolium-results", "audit-state.json"), "changed after final archive")
	r.syncStateOnce(context.Background())
	data, err := os.ReadFile(filepath.Join(r.archiveDir, "audit-state.json"))
	if err != nil || string(data) == "changed after final archive" {
		t.Fatalf("periodic sync overwrote verified archive: %q, %v", data, err)
	}
}

func TestAuditFinalizeArchiveFailureRecordsWarningAndSourceState(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	run := &database.AgenticScan{UUID: r.agenticScanUUID, Status: "running", ProjectUUID: database.DefaultProjectUUID}
	if err := r.repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	writeAuditTestFile(t, filepath.Join(r.cfg.SessionDir, "vigolium-results", "audit-state.json"), "stale unverified state")
	evidenceErr := errors.New("archive failed")
	r.finalizeAgenticScan(context.Background(), nil, evidenceErr)
	got, err := r.repo.GetAgenticScan(context.Background(), run.UUID)
	if err != nil || got.Status != "completed_with_warnings" || got.ErrorMessage != evidenceErr.Error() || got.ResultJSON == "stale unverified state" || got.ResultJSON == "" {
		t.Fatalf("finalization trusted partial archive or hid failure: %+v, %v", got, err)
	}
}
