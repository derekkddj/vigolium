package authsession

import (
	"errors"
	"time"
)

// ErrUnsafeSessionRetention means age-only cleanup cannot establish that evidence
// is safe to delete. Directory mtime misses descendant writes and resumed runs.
var ErrUnsafeSessionRetention = errors.New("automatic session evidence deletion is disabled: age alone cannot establish run inactivity or catalog dependencies")

// CleanupSessionDirs no longer removes evidence based on directory age. The
// signature is retained for compatibility, but it fails closed without touching
// the filesystem. A future opt-in retention policy must coordinate authoritative
// run status, project scope, the catalog, findings, and durable sections.
// This does not reclaim retained temporary audit sources: those require recovery
// and guarded owner cleanup (see docs/agentic-scan/evidence-retention.md).
//
// Deprecated: use an explicitly scoped, dependency-aware retention workflow.
func CleanupSessionDirs(sessionsDir string, maxAge time.Duration) (int, error) {
	return 0, ErrUnsafeSessionRetention
}
