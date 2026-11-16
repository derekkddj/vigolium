package planting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestLiteralNonceEncodedBoundaries(t *testing.T) {
	const nonce = "abcdefghijklmnopqrst"
	for _, prefix := range []string{"", "/", "%2F", "%3A", "%2f"} {
		for _, suffix := range []string{"", "/", "%2F", ".cb.test"} {
			if !ContainsNonceToken([]byte(prefix+nonce+suffix), nonce) {
				t.Fatalf("literal nonce next to separators rejected: %q", prefix+nonce+suffix)
			}
		}
	}
	for _, raw := range []string{"x" + nonce, nonce + "x", "%41" + nonce, nonce + "%41", "%30" + nonce,
		"%" + fmt.Sprintf("%02X", nonce[0]) + nonce[1:], nonce[:len(nonce)-1] + "%74"} {
		if ContainsNonceToken([]byte(raw), nonce) {
			t.Fatalf("nonliteral/embedded nonce accepted: %q", raw)
		}
	}
}

func TestDeclaredSlotRejectsDecodedNonceBorrowedFromReferer(t *testing.T) {
	const nonce = "abcdefghijklmnopqrst"
	payload := "http://" + nonce + ".cb.test/"
	encodedNonce := strings.Replace(url.QueryEscape(payload), nonce, "%61"+nonce[1:], 1)
	for _, surface := range []string{"query", "form"} {
		for _, tc := range []struct{ name, value string }{
			{"escaped-nonce-character", encodedNonce},
			{"double-encoded-url", url.QueryEscape(url.QueryEscape(payload))},
			{"double-encoded-nonce-character", url.QueryEscape(encodedNonce)},
		} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				// Both the Referer and a different parameter contain genuine
				// planting intent. Neither may certify the declared url field.
				body := "url=" + tc.value + "&other=" + url.QueryEscape(payload)
				raw := []byte("GET /?" + body + " HTTP/1.1\r\nHost: target.test\r\nReferer: " + payload + "\r\n\r\n")
				if surface == "form" {
					raw = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: target.test\r\nReferer: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", payload, len(body), body))
				}
				original := bytes.Clone(raw)
				if !ContainsNonceToken(raw, nonce) {
					t.Fatal("fixture must contain genuine literal incidental token")
				}
				for _, intent := range []string{payload, ""} {
					if MatchesSlot(raw, nonce, "url", intent, false) {
						t.Fatal("decoding created planting proof from another slot's literal nonce")
					}
				}
				if !bytes.Equal(original, raw) {
					t.Fatal("matching rewrote captured request bytes")
				}
			})
		}
	}
	jsonRaw := []byte(`POST / HTTP/1.1` + "\r\nContent-Type: application/json\r\nReferer: " + payload + "\r\n\r\n" + `{"url":"http://\u0061bcdefghijklmnopqrst.cb.test/","other":"` + payload + `"}`)
	for _, intent := range []string{payload, ""} {
		if MatchesSlot(jsonRaw, nonce, "url", intent, false) {
			t.Fatal("JSON decoding synthesized a nonce in the declared slot")
		}
	}
}

func TestDeclaredParameterNamesDoNotBorrowDifferentCaseSlots(t *testing.T) {
	const nonce = "abcdefghijklmnopqrst"
	payload := "http://" + nonce + ".cb.test/"
	for _, surface := range []string{"query", "form", "json"} {
		t.Run(surface, func(t *testing.T) {
			body := "url=" + url.QueryEscape(payload) + "&URL=unmodified"
			raw := []byte("GET /?" + body + " HTTP/1.1\r\nHost: target.test\r\n\r\n")
			switch surface {
			case "form":
				raw = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			case "json":
				encoded, err := json.Marshal(map[string]string{"url": payload, "URL": "unmodified"})
				if err != nil {
					t.Fatal(err)
				}
				raw = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(encoded), encoded))
			}
			if MatchesSlot(raw, nonce, "URL", payload, false) {
				t.Fatal("case folding certified another parameter's planting")
			}
			if !MatchesSlot(raw, nonce, "url", payload, false) {
				t.Fatal("exact declared parameter was rejected")
			}
		})
	}
	// HTTP header names, unlike query/form/JSON parameter names, are caseless.
	raw := []byte("GET / HTTP/1.1\r\nHost: target.test\r\nX-Callback: " + payload + "\r\n\r\n")
	if !MatchesSlot(raw, nonce, "x-callback", payload, true) {
		t.Fatal("legitimate header case equivalence was rejected")
	}
}

func TestDeclaredSlotPreservesRawEncodingAndDecodesOnlyOneLayer(t *testing.T) {
	const nonce = "abcdefghijklmnopqrst"
	// Literal percent escapes and '+' in intent expose an accidental second
	// query/form decode. JSON exercises quotes, backslashes, CR/LF and HTML.
	payload := "http://" + nonce + ".cb.test/?literal=%2F&plus=+&text=\"\\\r\n<entity>"
	for _, surface := range []string{"query", "form", "json"} {
		t.Run(surface, func(t *testing.T) {
			body := "url=" + url.QueryEscape(payload)
			raw := []byte("GET /?" + body + " HTTP/1.1\r\nHost: target.test\r\n\r\n")
			switch surface {
			case "form":
				raw = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			case "json":
				encoded, err := json.Marshal(map[string]string{"url": payload})
				if err != nil {
					t.Fatal(err)
				}
				raw = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(encoded), encoded))
			}
			original := bytes.Clone(raw)
			if !MatchesSlot(raw, nonce, "url", payload, false) {
				t.Fatal("genuine encoded payload in the declared field was rejected")
			}
			if MatchesSlot(raw, nonce, "other", payload, false) {
				t.Fatal("a different declared field borrowed this field's nonce")
			}
			if !bytes.Equal(original, raw) {
				t.Fatal("comparison decoded or rewrote captured evidence")
			}
		})
	}
}
