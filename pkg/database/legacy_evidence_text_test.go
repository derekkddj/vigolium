package database

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestLegacyEvidenceTextProjection(t *testing.T) {
	for _, raw := range []string{"", "plain 'quoted' HTTP\r\n", "Unicode π and �", `literal \x00 and \xff`} {
		if got := legacyEvidenceTextProjection(raw); got != raw {
			t.Fatalf("ordinary text changed: %q -> %q", raw, got)
		}
	}
	raw := "POST / HTTP/1.1\r\n\r\nπ\x00\xff\xc0\xaf\\literal�"
	want := legacyBinaryPreviewMarker + "POST / HTTP/1.1\r\n\r\nπ" + `\x00\xff\xc0\xaf\\literal` + "�"
	got := legacyEvidenceTextProjection(raw)
	if got != want || !utf8.ValidString(got) || strings.IndexByte(got, 0) >= 0 {
		t.Fatalf("unsafe projection: got %q, want %q", got, want)
	}
	if again := legacyEvidenceTextProjection(got); again != got {
		t.Fatal("projection is not idempotent")
	}
}

func scenarioLegacyBinaryFindingText(t *testing.T, db *DB) {
	t.Helper()
	r, ctx := NewRepository(db), context.Background()
	request := []byte("POST /actual HTTP/1.1\r\nHost: probe.example\r\nContent-Length: 999\r\n\r\n\x00\xffshort")
	response := []byte("HTTP/1.1 200 OK\r\n\r\n\x00\xffanswer")
	controlRequest, controlResponse := "control\x00\xffrequest", "control\x00\xferesponse"
	opaque := "opaque supporting bytes\x00\xff"
	for _, path := range []string{"direct", "direct-batch", "event", "event-batch"} {
		for _, typed := range []bool{false, true} {
			name := path + "-legacy"
			if typed {
				name = path + "-captured"
			}
			t.Run(name, func(t *testing.T) {
				f := &Finding{FindingHash: "binary-text-" + name, ModuleID: "binary-text", ModuleName: "Binary text", Severity: "high",
					URL: "https://assertion.example/vulnerability", Request: string(request), Response: string(response),
					AdditionalEvidence: []string{output.BuildEvidence("informal attack", controlRequest, controlResponse), opaque}}
				originalSupporting := append([]string(nil), f.AdditionalEvidence...)
				var captured *evidence.Exchange
				if typed {
					captured = evidence.NewExchange("http://probe.example:8081", "http://probe.example:8081/actual", request, response, evidence.ProvenanceCaptured)
					captured.RequestState = evidence.StateTruncated
					captured.ContentHash = captured.Hash()
					control := evidence.NewExchange("http://probe.example:8081", "http://probe.example:8081/control", []byte(controlRequest), []byte(controlResponse), evidence.ProvenanceCaptured)
					f.Evidence = []evidence.Entry{evidence.Select(captured, evidence.RoleAttack, true, "actual execution"), evidence.Select(control, evidence.RoleControl, false, "declared control")}
					f.EvidenceStatus = "selected"
				}
				var event *output.ResultEvent
				switch path {
				case "direct":
					if err := r.SaveFindingDirect(ctx, f); err != nil {
						t.Fatal(err)
					}
				case "direct-batch":
					results, err := r.SaveFindingsDirectBatch(ctx, []*Finding{f})
					if err != nil || !results[0].Inserted {
						t.Fatalf("direct batch: %+v %v", results, err)
					}
				default:
					event = makeFindingEvent("binary-text-"+name, "/actual", severity.High)
					event.URL, event.Request, event.Response = f.URL, f.Request, f.Response
					event.AdditionalEvidence, event.Evidence, event.EvidenceStatus = originalSupporting, f.Evidence, f.EvidenceStatus
					f.FindingHash = event.ID()
					if path == "event" {
						if err := r.SaveFinding(ctx, event, nil, "", ""); err != nil {
							t.Fatal(err)
						}
					} else {
						results := r.SaveFindingsBatchResults(ctx, []FindingWrite{{Event: event}})
						if results[0].Err != nil || !results[0].Inserted {
							t.Fatalf("event batch: %+v", results)
						}
					}
				}
				got, err := r.GetFindingByHash(ctx, f.FindingHash, "")
				if err != nil {
					t.Fatal(err)
				}
				if got.Request != legacyEvidenceTextProjection(string(request)) || got.Response != legacyEvidenceTextProjection(string(response)) || len(got.AdditionalEvidence) != 2 {
					t.Fatalf("compatibility projections changed unexpectedly: %+v", got)
				}
				for i, raw := range got.AdditionalEvidence {
					if raw != legacyEvidenceTextProjection(originalSupporting[i]) || strings.IndexByte(raw, 0) >= 0 || !utf8.ValidString(raw) {
						t.Fatalf("supporting projection %d is not SQL-safe: %q", i, raw)
					}
				}
				if err := r.HydrateFindingEvidenceForExport(ctx, got); err != nil {
					t.Fatal(err)
				}
				// Both cases have three receipts: primary pair, control pair and
				// opaque support. Typed evidence must not be duplicated or repaired.
				if len(got.Evidence) != 3 {
					t.Fatalf("lost/duplicated receipts: %+v", got.Evidence)
				}
				var primary, control, opaqueFound bool
				for _, entry := range got.Evidence {
					x := entry.Exchange
					if x == nil {
						t.Fatal("receipt missing")
					}
					switch {
					case bytes.Equal(x.Request, request) && bytes.Equal(x.Response, response):
						primary = true
						if typed && (x.ID != captured.ID || !equalEvidenceExchanges(x, captured) || entry.Role != evidence.RoleAttack || !entry.Primary) {
							t.Fatalf("canonical capture/framing/state changed: %+v", x)
						}
					case string(x.Request) == controlRequest && string(x.Response) == controlResponse:
						control = true
						if typed && (entry.Role != evidence.RoleControl || entry.Primary) {
							t.Fatal("informal label changed the declared control role")
						}
					case string(x.Request) == opaque && len(x.Response) == 0:
						opaqueFound = true
					}
					if !typed || x.Provenance == evidence.ProvenanceSupplied {
						if entry.Role != evidence.RoleUnknown || entry.Primary || x.Provenance != evidence.ProvenanceSupplied || x.Service != "" || x.URL != "" {
							t.Fatalf("legacy producer bytes gained inferred proof/transport attribution: %+v %+v", entry, x)
						}
					}
				}
				if !primary || !control || !opaqueFound {
					t.Fatal("original producer bytes were not retained")
				}
				if event != nil && (event.Request != string(request) || event.Response != string(response) || event.AdditionalEvidence[0] != originalSupporting[0]) {
					t.Fatal("conversion mutated producer-owned text")
				}
				// Saving the owned, projected finding again must not create new
				// synthetic execution identities or associations.
				if err := r.SaveFindingDirect(ctx, got); err != nil {
					t.Fatal(err)
				}
				again, err := r.GetFindingByID(ctx, got.ID)
				if err != nil || len(again.Evidence) != 3 {
					t.Fatalf("repeated preparation duplicated receipts: %+v %v", again, err)
				}
			})
		}
	}
}

func TestLegacyBinaryFindingText_SQLite(t *testing.T) {
	scenarioLegacyBinaryFindingText(t, newTestDB(t))
}

func TestPg_LegacyBinaryFindingText(t *testing.T) {
	scenarioLegacyBinaryFindingText(t, openPGTestDB(t))
}

func TestLegacyBinaryPreparationDoesNotAlterDeclaredMissingProofOrMetadata(t *testing.T) {
	x := evidence.NewExchange("https://actual.example:8443", "https://actual.example/a", []byte("request"), nil, evidence.ProvenanceCaptured)
	f := &Finding{URL: "https://assertion.example/", Request: "unrelated\x00\xffrequest", Response: "unrelated\x00\xffresponse",
		Description: "metadata\x00\xff", Payload: "payload\x00\xff", Tags: []string{"tag\x00\xff"}, EvidenceStatus: "selected",
		Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "declared")}}
	if err := prepareFindingEvidence(f); err != nil {
		t.Fatal(err)
	}
	if len(f.Evidence) != 2 || !equalEvidenceExchanges(f.Evidence[0].Exchange, x) || f.Evidence[0].Role != evidence.RoleAttack || !f.Evidence[0].Primary ||
		f.Evidence[1].Role != evidence.RoleUnknown || f.Evidence[1].Primary || f.EvidenceStatus != "selected" {
		t.Fatalf("legacy normalization replaced/filled declared missing proof: %+v", f)
	}
	if f.Description != "metadata\x00\xff" || f.Payload != "payload\x00\xff" || f.Tags[0] != "tag\x00\xff" {
		t.Fatal("normalization changed arbitrary metadata")
	}
}

func TestLegacyBinaryTextPreparationPreservesOpaqueUnsafeLabels(t *testing.T) {
	raw := output.BuildEvidence("label\x00\xff", "request", "response")
	f := &Finding{AdditionalEvidence: []string{raw}}
	if err := prepareFindingEvidence(f); err != nil {
		t.Fatal(err)
	}
	if len(f.Evidence) != 1 || string(f.Evidence[0].Exchange.Request) != raw || len(f.Evidence[0].Exchange.Response) != 0 || f.Evidence[0].Role != evidence.RoleUnknown || f.Evidence[0].Primary || f.Evidence[0].Exchange.RequestState != evidence.StateUnknown {
		t.Fatalf("unsafe label/opaque producer bytes lost or interpreted as proof: %+v", f.Evidence)
	}
	if f.AdditionalEvidence[0] != legacyEvidenceTextProjection(raw) || needsLegacyEvidenceProjection(f.Evidence[0].Label) {
		t.Fatal("unsafe original label reached a SQL TEXT association")
	}
}

func TestLegacyBinaryTextPreparationDoesNotRewriteHistoricSQLiteRows(t *testing.T) {
	db, ctx := newTestDB(t), context.Background()
	request, response := []byte("historic\x00\xffrequest"), []byte("historic\x00\xffresponse")
	// SQLite can contain historic binary TEXT inserted via BLOB casts even though
	// Bun's interpolated TEXT literal cannot write these incoming strings safely.
	if _, err := db.ExecContext(ctx, `INSERT INTO findings
		(project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash, request, response)
		VALUES (?, '[]', 'historic', 'Historic', 'low', 'historic-binary-text', CAST(? AS TEXT), CAST(? AS TEXT))`, DefaultProjectUUID, request, response); err != nil {
		t.Fatal(err)
	}
	r := NewRepository(db)
	if err := r.SaveFindingDirect(ctx, &Finding{FindingHash: "new-safe-text", ModuleID: "new", ModuleName: "New", Severity: "low", Request: "incoming\x00\xff"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var gotRequest, gotResponse []byte
	if err := db.QueryRowContext(ctx, "SELECT CAST(request AS BLOB), CAST(response AS BLOB) FROM findings WHERE finding_hash = 'historic-binary-text'").Scan(&gotRequest, &gotResponse); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRequest, request) || !bytes.Equal(gotResponse, response) {
		t.Fatal("incoming normalization/migration changed historic binary text")
	}
	if n := scalarInt(t, db, `SELECT COUNT(*) FROM finding_evidence fe JOIN findings f ON f.id = fe.finding_id WHERE f.finding_hash = 'historic-binary-text'`); n != 0 {
		t.Fatal("historic binary text gained inferred evidence associations")
	}
}

func TestLegacyBinaryEventPreservedBeforeWindowAndSupportingCap(t *testing.T) {
	request := "GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + strings.Repeat("binary\x00\xff", 128*1024)
	ev := makeFindingEvent("binary-window", "/app.js", severity.High)
	ev.Request, ev.Response = request, response
	for i := 0; i <= maxAdditionalEvidence; i++ {
		ev.AdditionalEvidence = append(ev.AdditionalEvidence, output.BuildEvidence("support", "request\x00"+strings.Repeat("x", i), "response\x00\xff"))
	}
	var f Finding
	if err := f.FromResultEvent(ev); err != nil {
		t.Fatal(err)
	}
	if len(f.AdditionalEvidence) != maxAdditionalEvidence || len(f.Evidence) != maxAdditionalEvidence+2 {
		t.Fatalf("binary producer bytes lost before text cap: support=%d receipts=%d", len(f.AdditionalEvidence), len(f.Evidence))
	}
	if f.Evidence[0].Role != evidence.RoleUnknown || f.Evidence[0].Primary || string(f.Evidence[0].Exchange.Request) != request || string(f.Evidence[0].Exchange.Response) != response {
		t.Fatal("static legacy binary response was windowed before receipt capture")
	}
	if !utf8.ValidString(f.Response) || strings.IndexByte(f.Response, 0) >= 0 || ev.Response != response || strings.IndexByte(ev.AdditionalEvidence[0], 0) < 0 {
		t.Fatal("SQL projection is unsafe or producer event was mutated")
	}
}
