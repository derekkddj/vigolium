package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"go.uber.org/zap"
)

// AuditOutcome keeps execution failure separate from evidence degradation.
// Wait still returns both errors for compatibility, but callers must not retry
// successful tool work or report a provider failure to repair its recording.
type AuditOutcome struct {
	ProcessErr  error
	EvidenceErr error
	Status      string
	ArchiveDir  string // empty unless a complete, verified archive was published
}

func (r *AuditAgenticScanner) Outcome() AuditOutcome {
	r.mu.Lock()
	out := AuditOutcome{ProcessErr: r.processErr, EvidenceErr: r.evidenceErr, Status: r.terminalStatus}
	r.mu.Unlock()
	r.syncMu.Lock()
	out.ArchiveDir = r.archiveDir
	r.syncMu.Unlock()
	return out
}

// AuditRunnerOutcome is deliberately optional so existing AuditRunner clients
// and test doubles remain source compatible.
func AuditRunnerOutcome(runner AuditRunner, waitErr error) AuditOutcome {
	if r, ok := runner.(interface{ Outcome() AuditOutcome }); ok {
		if out := r.Outcome(); out.Status != "" {
			return out
		}
		// Start failures have no monitor/terminal outcome. Preserve the caller's
		// launch error instead of treating an uninitialized runner as success.
	}
	run := &database.AgenticScan{}
	applyAuditTerminalStatus(run, waitErr, errors.Is(waitErr, context.Canceled))
	return AuditOutcome{ProcessErr: waitErr, Status: run.Status}
}

var ErrAuditSourceNeedsRecovery = errors.New("audit source output already exists; recover retained evidence before starting a new background audit")

func checkAuditSourceReusable(dir string) error {
	_, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrAuditSourceNeedsRecovery, err)
	}
	return ErrAuditSourceNeedsRecovery
}

// CleanupAuditSource fails closed if any harness output remains (including a
// failed archive, explicit keep-source policy, or a permission/stat error).
// Owners of downloaded temporary sources must use this rather than unconditionally
// removing the parent tree. Only the local recovery path, not evidence/errors or
// credentials, is included in the operator warning.
func CleanupAuditSource(source string, cleanup func(), writer io.Writer, harnesses ...HarnessSpec) bool {
	if cleanup == nil {
		return false
	}
	if len(harnesses) == 0 {
		harnesses = []HarnessSpec{DefaultAuditHarness(), piolium.DefaultHarness()}
	}
	for _, h := range harnesses {
		if source == "" || !filepath.IsLocal(h.SourceFolder) {
			zap.L().Warn("Temporary audit source retained; recovery state unavailable")
			return false
		}
		_, err := os.Lstat(filepath.Join(source, h.SourceFolder))
		if !os.IsNotExist(err) {
			zap.L().Warn("Temporary audit source retained for recovery", zap.String("path", source))
			_ = WriteRuntimeProgress(writer, "audit", "evidence", "Temporary audit source retained for recovery at "+source)
			return false
		}
	}
	cleanup()
	return true
}
