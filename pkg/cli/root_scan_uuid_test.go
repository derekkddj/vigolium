package cli

import "testing"

func TestValidateScanUUIDFlag(t *testing.T) {
	for _, scanUUID := range []string{
		"../outside",
		"3AF56732-9C75-4FC2-8ACE-A2E5655B725C",
		"3af567329c754fc28acea2e5655b725c",
		"   ",
	} {
		if err := validateScanUUIDFlag(scanUUID); err == nil {
			t.Errorf("validateScanUUIDFlag(%q) accepted invalid UUID", scanUUID)
		}
	}

	for _, scanUUID := range []string{"", "3af56732-9c75-4fc2-8ace-a2e5655b725c"} {
		if err := validateScanUUIDFlag(scanUUID); err != nil {
			t.Errorf("validateScanUUIDFlag(%q): %v", scanUUID, err)
		}
	}
}
