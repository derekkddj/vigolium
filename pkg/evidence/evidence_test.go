package evidence

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestExchangeIdentityIncludesResponseServiceAndAbsence(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	a := NewExchange("https://example.com:443", "https://example.com/", req, []byte("HTTP/1.1 200 OK\r\n\r\na"), ProvenanceCaptured)
	b := NewExchange(a.Service, a.URL, req, []byte("HTTP/1.1 403 Forbidden\r\n\r\nb"), ProvenanceCaptured)
	c := NewExchange("http://example.com:80", "http://example.com/", req, a.Response, ProvenanceCaptured)
	d := NewExchange(a.Service, a.URL, req, nil, ProvenanceCaptured)
	for _, x := range []*Exchange{b, c, d} {
		if a.ContentHash == x.ContentHash || a.ID == x.ID {
			t.Fatal("distinct exchange collapsed")
		}
	}
	same := NewExchange(a.Service, a.URL, req, a.Response, ProvenanceCaptured)
	if same.ID == a.ID || same.ContentHash != a.ContentHash {
		t.Fatal("execution identity must be separate from content identity")
	}
}

func TestExchangeOwnedBytesAndBinaryJSON(t *testing.T) {
	req, resp := []byte{0, 1, 0xff, '\n'}, []byte{0xff, 0, 0xfe}
	x := NewExchange("s", "u", req, resp, ProvenanceSupplied)
	entry := Select(x, RoleAttack, true, "binary")
	req[0], resp[0], x.Response[0] = 10, 20, 30
	if entry.Exchange.Validate() != nil {
		t.Fatal("selected receipt aliased source bytes")
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Entry
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Exchange.Response, []byte{0xff, 0, 0xfe}) || decoded.Exchange.Validate() != nil {
		t.Fatal("binary receipt corrupted by JSON")
	}
	if entry.Manifest().Exchange != nil {
		t.Fatal("manifest must not include raw bytes")
	}
	if x.Validate() == nil {
		t.Fatal("mutating a sealed receipt must be detected")
	}
}

func TestCaptureMetadataValidation(t *testing.T) {
	x := NewExchange("s", "u", []byte("request"), []byte("response"), ProvenanceCaptured)
	x.CapturedAt = time.Time{}
	if x.Validate() == nil {
		t.Fatal("captured receipt accepted unknown capture time")
	}
	x.Provenance = ProvenanceLegacy
	x.ContentHash = x.Hash()
	if err := x.Validate(); err != nil {
		t.Fatalf("legacy unknown time rejected: %v", err)
	}
	x.CapturedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if x.Validate() == nil {
		t.Fatal("non-JSON time accepted")
	}
	x = NewExchange("s", "u", nil, []byte("response"), ProvenanceSupplied)
	x.RequestState = StateComplete
	x.ContentHash = x.Hash()
	if x.Validate() == nil {
		t.Fatal("complete empty message accepted")
	}
}

func TestUnknownAndBaselineAreNotSelectedProof(t *testing.T) {
	x := NewExchange("s", "u", []byte("request"), []byte("response"), ProvenanceLegacy)
	for _, role := range []Role{RoleUnknown, RoleBaseline} {
		if HasSelectedEvidence([]Entry{Select(x, role, true, "")}) {
			t.Fatalf("%s promoted to proof", role)
		}
	}
}
