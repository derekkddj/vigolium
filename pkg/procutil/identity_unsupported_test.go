//go:build !linux

package procutil

import (
	"errors"
	"testing"
)

func TestProcessIdentityUnsupported(t *testing.T) {
	identity, err := CaptureCurrentProcessIdentity()
	if !errors.Is(err, ErrProcessIdentityUnavailable) {
		t.Fatalf("capture error = %v, want ErrProcessIdentityUnavailable", err)
	}
	if identity != (Identity{}) {
		t.Fatalf("unsupported capture returned partial identity: %+v", identity)
	}
	for _, old := range []Identity{
		{},
		{
			PID:          42,
			BootID:       "11111111-2222-4333-8444-555555555555",
			PIDNamespace: "pid:[4026531836]",
			StartTicks:   123456,
		},
	} {
		if got := ProbeProcessIdentity(old); got != ProcessIdentityUnknown {
			t.Fatalf("probe(%+v) = %v, want Unknown", old, got)
		}
	}
}
