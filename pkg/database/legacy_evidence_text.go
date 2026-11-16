package database

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

const legacyBinaryPreviewMarker = "[Non-authoritative escaped binary text preview; exact bytes are retained in evidence receipts]\n"

// legacyEvidenceTextProjection is a display-only compatibility projection. NUL
// cannot be interpolated into SQLite SQL or stored in PostgreSQL TEXT, and
// PostgreSQL also rejects invalid UTF-8. Keep ordinary text byte-for-byte; for
// binary text preserve readable Unicode/newlines, escape each invalid byte and
// NUL as \\xNN, and double literal backslashes to make the preview unambiguous.
// Never decode this projection into an HTTP message or a canonical receipt.
func legacyEvidenceTextProjection(raw string) string {
	if !needsLegacyEvidenceProjection(raw) {
		return raw
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(raw) + len(legacyBinaryPreviewMarker))
	b.WriteString(legacyBinaryPreviewMarker)
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		switch {
		case raw[i] == 0 || r == utf8.RuneError && size == 1:
			b.WriteString(`\x`)
			b.WriteByte(hex[raw[i]>>4])
			b.WriteByte(hex[raw[i]&15])
		case raw[i] == '\\':
			b.WriteString(`\\`)
		default:
			b.WriteString(raw[i : i+size])
		}
		i += size
	}
	return b.String()
}

func needsLegacyEvidenceProjection(raw string) bool {
	return strings.IndexByte(raw, 0) >= 0 || !utf8.ValidString(raw)
}

// prepareFindingLegacyText runs only on incoming producer data, never historical
// rows. Save paths call it before SQL; event conversion also calls it before
// windowing/capping legacy text so original binary producer bytes cannot be lost.
// Byte equality only avoids duplicate storage: it assigns no proof role, service
// or execution URL. New receipts are explicitly supplied, unknown and non-primary.
func prepareFindingLegacyText(f *Finding) {
	preserve := func(request, response, label string) {
		if request == "" && response == "" {
			return
		}
		for _, entry := range f.Evidence {
			if x := entry.Exchange; x != nil && bytes.Equal(x.Request, []byte(request)) && bytes.Equal(x.Response, []byte(response)) {
				return
			}
		}
		// A finding URL is assertion attribution, not evidence of the service or
		// URL that produced these bytes. Leave both receipt fields unknown.
		x := evidence.NewExchange("", "", []byte(request), []byte(response), evidence.ProvenanceSupplied)
		// Legacy strings make no fidelity declaration. Retain their exact supplied
		// bytes without asserting that an HTTP message is complete or was sent.
		if len(x.Request) > 0 {
			x.RequestState = evidence.StateUnknown
		}
		if len(x.Response) > 0 {
			x.ResponseState = evidence.StateUnknown
		}
		x.ContentHash = x.Hash()
		f.Evidence = append(f.Evidence, evidence.Entry{ExchangeID: x.ID, Role: evidence.RoleUnknown, Label: label, Exchange: x})
	}
	if needsLegacyEvidenceProjection(f.Request) || needsLegacyEvidenceProjection(f.Response) {
		preserve(f.Request, f.Response, "Unclassified producer-supplied binary HTTP bytes")
		f.Request = legacyEvidenceTextProjection(f.Request)
		f.Response = legacyEvidenceTextProjection(f.Response)
	}
	// Take an owned slice before replacing elements; converter inputs and direct
	// finding callers may reuse the original AdditionalEvidence slice.
	var supporting []string
	for i, raw := range f.AdditionalEvidence {
		if !needsLegacyEvidenceProjection(raw) {
			continue
		}
		pair := output.ParseEvidence(raw)
		if pair.IsPair() && !needsLegacyEvidenceProjection(pair.Label) {
			// Split only the explicit legacy pair format, never parse/repair HTTP
			// framing or infer a role from an informal label.
			preserve(pair.Request, pair.Response, "Unclassified producer-supplied binary supporting pair")
		} else {
			// Free-form supporting bytes (or an unsafe label) have no reliable
			// HTTP split. Preserve the entire producer entry as an opaque payload,
			// not a claim that it was an executed request.
			preserve(raw, "", "Opaque producer-supplied supporting bytes; not parsed HTTP")
		}
		if supporting == nil {
			supporting = append([]string(nil), f.AdditionalEvidence...)
		}
		supporting[i] = legacyEvidenceTextProjection(raw)
	}
	if supporting != nil {
		f.AdditionalEvidence = supporting
	}
}
