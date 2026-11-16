package procutil

import "errors"

// Identity identifies one process incarnation, not merely a reusable PID. BootID
// and PIDNamespace bind PID and StartTicks to the environment that observed them.
// Persist all four fields together; a partial identity cannot prove death.
type Identity struct {
	PID          int    `json:"pid"`
	BootID       string `json:"boot_id"`
	PIDNamespace string `json:"pid_namespace"`
	StartTicks   uint64 `json:"start_ticks"`
}

// ProcessIdentityStatus describes whether the original process incarnation can
// still be observed. Unknown is the zero value and must not authorize cleanup.
type ProcessIdentityStatus uint8

const (
	// ProcessIdentityUnknown means there is insufficient comparable evidence.
	ProcessIdentityUnknown ProcessIdentityStatus = iota
	// ProcessIdentityAlive means the same incarnation is present in procfs. This
	// deliberately includes zombies; it does not assert that a process is running.
	ProcessIdentityAlive
	// ProcessIdentityDead means the PID disappeared or was reused within the
	// successfully verified, unchanged boot and PID namespace.
	ProcessIdentityDead
)

// ErrProcessIdentityUnavailable means a complete identity could not be captured,
// including on unsupported platforms. No PID-only fallback is safe evidence.
var ErrProcessIdentityUnavailable = errors.New("process identity unavailable")
