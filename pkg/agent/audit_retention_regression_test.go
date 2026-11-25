package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestAuditRetentionStartupRefusesUnrecoveredSource(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	enabled := true
	cfg := &config.AuditAgentConfig{Enable: &enabled}
	// Refusal happens before any binary/provider resolution or process launch.
	runner, wait, err := startAuditAgentBackground(context.Background(), cfg, DefaultAuditHarness(), r.cfg.SourcePath, r.cfg.SessionDir, "", "", "", nil, nil, nil)
	if !errors.Is(err, ErrAuditSourceNeedsRecovery) || runner != nil || wait != nil {
		t.Fatalf("startup must refuse recovery tree: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(r.cfg.SourcePath, "vigolium-results", "findings", "H1.md"))
	if err != nil || len(data) == 0 {
		t.Fatalf("startup lost source evidence: %v", err)
	}
	// A non-directory or inaccessible path must also fail closed, not launch.
	if err := checkAuditSourceReusable(filepath.Join(r.cfg.SourcePath, "vigolium-results", "audit-state.json", "child")); !errors.Is(err, ErrAuditSourceNeedsRecovery) {
		t.Fatalf("stat failure hidden: %v", err)
	}
}

func TestAuditRetentionFallbackRejectsExternalSymlinks(t *testing.T) {
	for _, kind := range []string{"file", "directory", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			r := auditEvidenceFixture(t, t.TempDir())
			external := t.TempDir()
			writeAuditTestFile(t, filepath.Join(external, "H1.md"), "## Q1-001: Outside evidence\n\n- **Severity**: High\n- **Verdict**: VALID\n")
			findings := filepath.Join(r.cfg.SourcePath, "vigolium-results", "findings")
			switch kind {
			case "file":
				if err := os.Remove(filepath.Join(findings, "H1.md")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(external, "H1.md"), filepath.Join(findings, "H1.md")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.RemoveAll(findings); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, findings); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				alias := filepath.Join(t.TempDir(), "source-alias")
				if err := os.Symlink(r.cfg.SourcePath, alias); err != nil {
					t.Fatal(err)
				}
				r.cfg.SourcePath = alias
			}
			if err := r.archiveAndImport(context.Background()); err == nil {
				t.Fatal("unsafe tree accepted")
			}
			if r.FindingStats().Parsed != 0 {
				t.Fatalf("imported rejected source: %+v", r.FindingStats())
			}
			if _, err := os.Lstat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); err != nil {
				t.Fatalf("rejected source lost: %v", err)
			}
		})
	}
}

func TestAuditRetentionParserLimitsPreserveRawEvidence(t *testing.T) {
	r := auditEvidenceFixture(t, "")
	large := filepath.Join(r.cfg.SourcePath, "vigolium-results", "findings", "H1.md")
	f, err := os.OpenFile(large, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAuditControlBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := r.archiveAndImport(context.Background()); err == nil {
		t.Fatal("oversized parser file accepted")
	}
	if r.FindingStats().Parsed != 0 {
		t.Fatal("oversized evidence imported")
	}
	info, err := os.Stat(large)
	if err != nil || info.Size() != maxAuditControlBytes+1 {
		t.Fatalf("raw evidence truncated/lost: %v", err)
	}
}

// appendingAuditWriter deterministically grows the source on each output write.
type appendingAuditWriter struct {
	file *os.File
	n    int64
}

func (w *appendingAuditWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	_, err := w.file.Write(p)
	return len(p), err
}

func TestAuditRetentionCopyConsumesOnlySnapshotLength(t *testing.T) {
	name := filepath.Join(t.TempDir(), "growing.md")
	body := bytes.Repeat([]byte("x"), 128*1024)
	if err := os.WriteFile(name, body, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := openAuditFile(name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	appender, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer appender.Close()
	writer := &appendingAuditWriter{file: appender}
	if err := copyAuditSnapshot(context.Background(), writer, reader, -1); err == nil {
		t.Fatal("growth must reject snapshot")
	}
	if writer.n != int64(len(body)) {
		t.Fatalf("copy followed appender past snapshot: %d", writer.n)
	}
}

func TestAuditRetentionExpiredBudgetRetainsSourceAndPersistsTerminalWarning(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	run := &database.AgenticScan{UUID: r.agenticScanUUID, Status: "running", ProjectUUID: database.DefaultProjectUUID}
	if err := r.repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	evidenceErr := r.archiveAndImport(ctx)
	if !errors.Is(evidenceErr, context.DeadlineExceeded) {
		t.Fatalf("deadline ignored: %v", evidenceErr)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.SourcePath, "vigolium-results")); err != nil {
		t.Fatal("expired budget removed source")
	}
	if err := r.persistAuditTerminalStatus(ctx, nil, evidenceErr); err != nil {
		t.Fatal(err)
	}
	got, err := r.repo.GetAgenticScan(context.Background(), run.UUID)
	if err != nil || got.Status != "completed_with_warnings" || got.CompletedAt.IsZero() {
		t.Fatalf("terminal write reused expired budget: %+v, %v", got, err)
	}
}

func TestAuditRetentionTerminalLookupFailureSurfaces(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	if err := r.persistAuditTerminalStatus(context.Background(), nil, nil); err == nil {
		t.Fatal("missing terminal catalog row silently accepted")
	}
}

func TestAuditRetentionTerminalUpdateFailureSurfacesInOutcome(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	run := &database.AgenticScan{UUID: r.agenticScanUUID, Status: "running", ProjectUUID: database.DefaultProjectUUID}
	if err := r.repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := r.repo.DB().Exec(`CREATE TRIGGER fail_audit_terminal BEFORE UPDATE ON agentic_scans BEGIN SELECT RAISE(ABORT, 'injected terminal persistence failure'); END`); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("true") // local fixture only
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.monitor(context.Background(), cmd, &syncBuffer{})
	out := AuditRunnerOutcome(r, r.Wait())
	if r.Wait() == nil || out.EvidenceErr == nil || out.ProcessErr != nil || out.Status != "completed_with_warnings" {
		t.Fatalf("terminal update failure lost or blamed on execution: %+v", out)
	}
	if out.ArchiveDir == "" {
		t.Fatal("durable raw archive missing after catalog failure")
	}
}

func TestAuditRetentionCleanExitWinsLateContextCancellation(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.monitor(ctx, cmd, &syncBuffer{})
	if err := r.Wait(); err != nil || r.Outcome().Status != "completed" {
		t.Fatalf("late cancellation relabelled successful execution: %+v, %v", r.Outcome(), err)
	}
}

func TestAuditRetentionContextOnlyCancellationIsDurable(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	r.repo = newAuditTestRepo(t)
	run := &database.AgenticScan{UUID: r.agenticScanUUID, Status: "running", ProjectUUID: database.DefaultProjectUUID}
	if err := r.repo.CreateAgenticScan(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sleep", "30") // local process only, no provider
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	cancel()
	r.monitor(ctx, cmd, &syncBuffer{})
	if r.Wait() == nil {
		t.Fatal("cancelled process returned success")
	}
	got, err := r.repo.GetAgenticScan(context.Background(), run.UUID)
	if err != nil || got.Status != "cancelled" || r.Outcome().Status != "cancelled" {
		t.Fatalf("context cancellation lost: %+v, %v", got, err)
	}
}

func TestAuditRetentionAutopilotSkipsUnverifiedIncrementalContext(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	writeAuditTestFile(t, filepath.Join(r.cfg.SessionDir, "vigolium-results", "findings", "H1.md"), "## Q1-001: Stale incremental evidence\n\n- **Severity**: High\n")
	// No published archive: even a parseable session draft is not authoritative.
	if ctx, err := completedBackgroundAuditContext(r); err == nil || ctx != nil {
		t.Fatal("autopilot accepted incremental evidence")
	}
	if err := r.syncFolderFull(); err != nil {
		t.Fatal(err)
	}
	if ctx, err := completedBackgroundAuditContext(r); err == nil || ctx != nil {
		t.Fatal("autopilot accepted archive before terminal import outcome")
	}
	r.mu.Lock()
	r.terminalStatus = "completed"
	r.mu.Unlock()
	if ctx, err := completedBackgroundAuditContext(r); err != nil || ctx == nil || len(ctx.Findings) != 1 {
		t.Fatalf("verified archive not consumed: %+v, %v", ctx, err)
	}
	r.mu.Lock()
	r.evidenceErr = errors.New("persistence failed")
	r.mu.Unlock()
	if ctx, err := completedBackgroundAuditContext(r); err == nil || ctx != nil {
		t.Fatal("autopilot ignored failed import")
	}
}

func TestAuditRetentionTemporarySourceCleanupFailsClosed(t *testing.T) {
	for _, kind := range []string{"retained", "permission-error", "empty"} {
		t.Run(kind, func(t *testing.T) {
			source := t.TempDir()
			if kind == "retained" {
				writeAuditTestFile(t, filepath.Join(source, "vigolium-results", "report.md"), "recover this")
			}
			if kind == "permission-error" {
				writeAuditTestFile(t, filepath.Join(source, "not-directory"), "blocks stat")
				source = filepath.Join(source, "not-directory", "child")
			}
			called := false
			var warning bytes.Buffer
			cleaned := CleanupAuditSource(source, func() { called = true }, &warning)
			want := kind == "empty"
			if called != want || cleaned != want {
				t.Fatalf("cleanup(%s) = %v, %v", kind, called, cleaned)
			}
			if !want && !bytes.Contains(warning.Bytes(), []byte(source)) {
				t.Fatal("recovery warning omitted retained local path")
			}
		})
	}
}

func TestAuditRetentionChainEvidenceFailureIsWarning(t *testing.T) {
	p := NewPioliumChainScanner(AuditAgentConfig{Modes: []string{"deep", "confirm"}}, nil)
	inner := auditEvidenceFixture(t, "")
	inner.evidenceErr = errors.New("recording failure")
	p.recordRan("deep", inner)
	p.finishChain(context.Background(), nil)
	close(p.done)
	out := AuditRunnerOutcome(p, p.Wait())
	if out.Status != "completed_with_warnings" || out.ProcessErr != nil || out.EvidenceErr == nil {
		t.Fatalf("recording became provider failure: %+v", out)
	}
}

func TestAuditRetentionRawFilesRemainUncapped(t *testing.T) {
	r := auditEvidenceFixture(t, t.TempDir())
	name := filepath.Join(r.cfg.SourcePath, "vigolium-results", "raw", "traffic.json")
	writeAuditTestFile(t, name, "")
	f, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAuditControlBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := r.archiveAndImport(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(r.archiveDir, "raw", "traffic.json"))
	if err != nil || info.Size() != maxAuditControlBytes+1 {
		t.Fatalf("raw archive was capped: %v", err)
	}
}

func TestAuditRetentionLeaseCancellationAndAliases(t *testing.T) {
	source := t.TempDir()
	key := filepath.Join(source, "vigolium-results")
	release, err := acquireAuditSourceLeaseContext(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	alias := filepath.Join(t.TempDir(), "source")
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if unlock, err := acquireAuditSourceLeaseContext(ctx, filepath.Join(alias, "vigolium-results")); !errors.Is(err, context.DeadlineExceeded) || unlock != nil {
		t.Fatalf("lease alias bypassed reservation/cancellation: %v", err)
	}
}

func TestAuditRetentionChainWarningIsPersisted(t *testing.T) {
	p := NewPioliumChainScanner(AuditAgentConfig{Modes: []string{"deep", "confirm"}, ProjectUUID: database.DefaultProjectUUID}, newAuditTestRepo(t))
	p.startedAt = time.Now()
	p.createAggregateRow(context.Background())
	p.evidenceErr = errors.New("incomplete evidence")
	p.finishChain(context.Background(), nil)
	got, err := p.repo.GetAgenticScan(context.Background(), p.agenticScanUUID)
	if err != nil || got.Status != "completed_with_warnings" || got.ErrorMessage == "" {
		t.Fatalf("chain warning was not durable: %+v, %v", got, err)
	}
}

func TestAuditRetentionReadCancellationPrecedesBytes(t *testing.T) {
	name := filepath.Join(t.TempDir(), "report.md")
	writeAuditTestFile(t, name, "do not read")
	f, err := openAuditFile(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyAuditSnapshot(ctx, io.Discard, f, -1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read continued: %v", err)
	}
}
