package dbimport

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestImportJSONLBinaryLegacyTextAndCanonicalReceipts(t *testing.T) {
	for _, typed := range []bool{false, true} {
		name := "legacy-nul"
		if typed {
			name = "typed-binary"
		}
		t.Run(name, func(t *testing.T) {
			r, ctx := newTestRepo(t), context.Background()
			// JSON strings can preserve NUL and valid Unicode, not invalid UTF-8.
			// Invalid raw message bytes must travel in the typed base64 receipt.
			request := "POST / HTTP/1.1\r\nContent-Length: 999\r\n\r\n\x00πshort"
			response := "HTTP/1.1 200 OK\r\n\r\n\x00πanswer"
			f := &database.Finding{FindingHash: "binary-import", ModuleID: "binary-import", ModuleName: "Binary import", Severity: "low",
				URL: "https://assertion.example/vulnerability", Request: request, Response: response,
				AdditionalEvidence: []string{output.BuildEvidence("informal attack", "control\x00request", "control\x00response")}}
			var captured *evidence.Exchange
			if typed {
				captured = evidence.NewExchange("http://probe.example:8081", "http://probe.example:8081/actual",
					[]byte("POST /actual HTTP/1.1\r\nContent-Length: 999\r\n\r\n\x00\xffshort"), []byte("HTTP/1.1 200 OK\r\n\r\n\x00\xffanswer"), evidence.ProvenanceCaptured)
				captured.RequestState = evidence.StateTruncated
				captured.ContentHash = captured.Hash()
				f.Request, f.Response = string(captured.Request), string(captured.Response)
				f.Evidence, f.EvidenceStatus = []evidence.Entry{evidence.Select(captured, evidence.RoleAttack, true, "capture")}, "selected"
			}
			result, err := ImportJSONL(ctx, r, strings.NewReader(jsonlEnvelope(t, "finding", f)), "", Options{})
			if err != nil || result.FindingsSaved != 1 || result.FindingsFailed != 0 {
				t.Fatalf("binary import failed: %+v %v", result, err)
			}
			got, err := r.GetFindingByHash(ctx, f.FindingHash, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range append([]string{got.Request, got.Response}, got.AdditionalEvidence...) {
				if !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 || !strings.Contains(text, "Non-authoritative escaped binary text preview") || !strings.Contains(text, `\x00`) {
					t.Fatalf("imported legacy text is not a marked SQL-safe preview: %q", text)
				}
			}
			if err := r.HydrateFindingEvidenceForExport(ctx, got); err != nil {
				t.Fatal(err)
			}
			if typed {
				x, err := r.GetEvidenceExchange(ctx, captured.ID, "")
				if err != nil || !bytes.Equal(x.Request, captured.Request) || !bytes.Equal(x.Response, captured.Response) || x.RequestState != evidence.StateTruncated || x.ContentHash != captured.ContentHash || x.Service != captured.Service || !x.CapturedAt.Equal(captured.CapturedAt) {
					t.Fatalf("typed import changed canonical binary/framing/state: %+v %v", x, err)
				}
			} else {
				found := false
				for _, entry := range got.Evidence {
					x := entry.Exchange
					if x == nil || entry.Role != evidence.RoleUnknown || entry.Primary || x.Provenance != evidence.ProvenanceSupplied || x.Service != "" || x.URL != "" {
						t.Fatalf("legacy import inferred an execution/proof role: %+v", entry)
					}
					if string(x.Request) == request && string(x.Response) == response {
						found = true
					}
				}
				if !found {
					t.Fatal("original legacy producer bytes lost before SQL projection")
				}
			}
			// Exported preview text is valid JSON; re-import must retain the
			// original base64 receipt, not decode the preview into a new capture.
			dest := newTestRepo(t)
			result, err = ImportJSONL(ctx, dest, strings.NewReader(jsonlEnvelope(t, "finding", got)), "", Options{})
			if err != nil || result.FindingsSaved != 1 || result.FindingsFailed != 0 {
				t.Fatalf("binary export/re-import: %+v %v", result, err)
			}
			for _, entry := range got.Evidence {
				x, err := dest.GetEvidenceExchange(ctx, entry.ExchangeID, "")
				if err != nil || !bytes.Equal(x.Request, entry.Exchange.Request) || !bytes.Equal(x.Response, entry.Exchange.Response) || x.ContentHash != entry.Exchange.ContentHash {
					t.Fatalf("preview became authoritative or receipt changed: %+v %v", x, err)
				}
			}
		})
	}
}
