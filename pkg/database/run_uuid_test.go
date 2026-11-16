package database

import "testing"

func TestCanonicalUUID(t *testing.T) {
	canonical := "3af56732-9c75-4fc2-8ace-a2e5655b725c"
	for _, input := range []string{
		canonical,
		"3AF56732-9C75-4FC2-8ACE-A2E5655B725C",
		"{" + canonical + "}",
		"urn:uuid:" + canonical,
		"3af567329c754fc28acea2e5655b725c",
	} {
		got, err := CanonicalUUID(input)
		if err != nil || got != canonical {
			t.Errorf("CanonicalUUID(%q) = %q, %v; want %q, nil", input, got, err, canonical)
		}
	}
	if _, err := CanonicalUUID("not-a-uuid"); err == nil {
		t.Fatal("CanonicalUUID accepted a malformed UUID")
	}
}

func TestValidRunID(t *testing.T) {
	for _, id := range []string{
		"3af56732-9c75-4fc2-8ace-a2e5655b725c",
		"00000000-0000-0000-0000-000000000000",
	} {
		if !ValidRunID(id) {
			t.Errorf("ValidRunID(%q) = false, want true", id)
		}
	}

	for _, id := range []string{
		"",
		"../outside",
		"3AF56732-9C75-4FC2-8ACE-A2E5655B725C",
		"3af567329c754fc28acea2e5655b725c",
		"{3af56732-9c75-4fc2-8ace-a2e5655b725c}",
		"urn:uuid:3af56732-9c75-4fc2-8ace-a2e5655b725c",
	} {
		if ValidRunID(id) {
			t.Errorf("ValidRunID(%q) = true, want false", id)
		}
	}
}
