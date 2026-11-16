//go:build !linux

package procutil

// CaptureCurrentProcessIdentity cannot establish Linux procfs incarnation proof
// on this platform. It returns no partial or fabricated identity.
func CaptureCurrentProcessIdentity() (Identity, error) {
	return Identity{}, ErrProcessIdentityUnavailable
}

// ProbeProcessIdentity cannot prove either liveness or death on this platform.
func ProbeProcessIdentity(old Identity) ProcessIdentityStatus {
	return ProcessIdentityUnknown
}
