package procutil

import (
	"encoding/json"
	"testing"
)

func TestIdentityJSONRoundTrip(t *testing.T) {
	identity := Identity{
		PID:          42,
		BootID:       "11111111-2222-4333-8444-555555555555",
		PIDNamespace: "pid:[4026531836]",
		StartTicks:   987654321,
	}
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"pid":42,"boot_id":"11111111-2222-4333-8444-555555555555","pid_namespace":"pid:[4026531836]","start_ticks":987654321}`
	if string(data) != want {
		t.Fatalf("JSON = %s, want %s", data, want)
	}
	var decoded Identity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != identity {
		t.Fatalf("decoded identity = %+v, want %+v", decoded, identity)
	}
}

func TestProcessIdentityUnknownIsZeroValue(t *testing.T) {
	var status ProcessIdentityStatus
	if status != ProcessIdentityUnknown {
		t.Fatalf("zero status = %v, want Unknown", status)
	}
}
