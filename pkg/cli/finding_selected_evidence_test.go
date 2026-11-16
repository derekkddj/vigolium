package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestFindingSelectedEvidenceCurlRolesOrderAndAbsence(t *testing.T) {
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("POST /proof HTTP/1.1\r\nHost: app.test\r\nContent-Length: 3\r\n\r\n\x00\xffA"), []byte("HTTP/1.1 200 OK\r\n\r\nproof"), evidence.ProvenanceCaptured)
	base := evidence.NewExchange(x.Service, "https://app.test/base", []byte("GET /base HTTP/1.1\r\nHost: app.test\r\n\r\n"), x.Response, evidence.ProvenanceCaptured)
	f := &database.Finding{URL: "https://app.test/finding", Request: "GET /legacy HTTP/1.1\r\nHost: app.test\r\n\r\n", EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(base, evidence.RoleBaseline, true, "baseline"), evidence.Select(x, evidence.RoleAttack, true, "attack")}}
	it, ok := findingEvidenceCurl(f)
	if !ok || it.ExchangeID != x.ID || it.EvidenceRole != "attack" || it.RequestSource != "selected_exchange" || !strings.Contains(it.URL, "/proof") || it.StdinBase64 == "" {
		t.Fatalf("not exact binary selected reproduction: %+v %v", it, ok)
	}
	f.EvidenceStatus = "unclassified" // original status survives a later selected occurrence
	f.Evidence = append(f.Evidence, evidence.Entry{ExchangeID: "historical", Role: evidence.RoleUnknown, Primary: true, OccurrenceID: "historic-occurrence"})
	it, ok = findingEvidenceCurl(f)
	if !ok || it.ExchangeID != x.ID || f.EvidenceStatus != "unclassified" || f.Evidence[2].Role != evidence.RoleUnknown {
		t.Fatal("historical status hid later selection or original occurrence was reclassified")
	}
	f.Evidence[0], f.Evidence[1] = f.Evidence[1], f.Evidence[0]
	it, ok = findingEvidenceCurl(f)
	if !ok || it.ExchangeID != x.ID {
		t.Fatal("ordering changed explicit selection")
	}
	f.Evidence[0].Exchange = nil
	if _, ok := findingEvidenceCurl(f); ok {
		t.Fatal("missing selected receipt replaced with legacy/baseline")
	}
	f.Evidence[0] = evidence.Select(x, evidence.RoleUnknown, true, "unknown")
	if _, ok := findingEvidenceCurl(f); ok {
		t.Fatal("unknown role promoted to proof")
	}
	f.Evidence = []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "one"), evidence.Select(base, evidence.RoleConfirmation, true, "two")}
	if _, ok := findingEvidenceCurl(f); ok {
		t.Fatal("first primary occurrence was guessed")
	}
	f.Evidence, f.EvidenceStatus = nil, ""
	it, ok = findingEvidenceCurl(f)
	if !ok || it.EvidenceRole != "unknown" || it.RequestSource != "legacy_inline" {
		t.Fatal("legacy reproduction not classified unknown")
	}
}

func TestFindingSelectedEvidenceCLIBinaryReplayAndHandoffUseCapturedService(t *testing.T) {
	raw := []byte("POST https://absolute-target.example/proof HTTP/1.1\r\nHost: virtual-host.example\r\nContent-Length: 900\r\n\r\n\x00\xffBINARY\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 700\r\n\r\n\xff\x00response")
	x := evidence.NewExchange("http://destination.example:8080", "https://finding-url.example/proof", raw, response, evidence.ProvenanceCaptured)
	f := &database.Finding{ID: 7, ProjectUUID: database.DefaultProjectUUID, Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "proof")}}
	src, err := sourceFromSelectedFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if src.Hostname != "destination.example" || src.Port != 8080 || src.Scheme != "http" || src.URL != "http://destination.example:8080/proof" {
		t.Fatalf("CLI inferred receipt destination: %+v", src)
	}
	if !bytes.Equal(src.BaselineRequest, raw) || !bytes.Equal(src.BaselineResponse, response) {
		t.Fatal("CLI replay repaired captured bytes/lengths")
	}
	req, resp, target := findingPushEvidence(f, nil)
	if !bytes.Equal(req, raw) || !bytes.Equal(resp, response) || target != src.URL {
		t.Fatal("Burp substituted URL authority or repaired raw bytes")
	}
	it, ok := findingEvidenceCurl(f)
	if !ok || it.URL != src.URL {
		t.Fatalf("curl ignored captured service: %+v", it)
	}
	body, err := base64.StdEncoding.DecodeString(it.StdinBase64)
	if err != nil || !bytes.Equal(body, []byte("\x00\xffBINARY\r\n")) {
		t.Fatal("curl reproduction lost binary body")
	}
	// Curl remains a reproduction, not an exact raw-wire sender: its shared
	// renderer intentionally recomputes framing. Replay/Burp keep raw framing.
	f.Evidence[0].Exchange.Request[0] = 'X'
	if !bytes.Equal(src.BaselineRequest, raw) {
		t.Fatal("CLI replay borrowed receipt request buffer")
	}
}

func TestFindingSelectedEvidenceReplayLoaderUsesReceiptAndNeverLegacyFallback(t *testing.T) {
	resetProjectScopeGlobals(t)
	globalStateless, globalProjectUUID = true, database.DefaultProjectUUID
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	seedRecordWithBodies(t, db, "legacy-replay")
	if _, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).Set("project_uuid = ?", database.DefaultProjectUUID).Where("uuid = ?", "rec-legacy-replay").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)
	raw := []byte("POST https://absolute-target.example/proof HTTP/1.1\r\nHost: virtual-host.example\r\nContent-Length: 900\r\n\r\n\x00\xffBINARY")
	x := evidence.NewExchange("http://destination.example:8080", "https://finding-url.example/proof", raw, []byte("HTTP/1.1 200 OK\r\n\r\nreceipt"), evidence.ProvenanceCaptured)
	primary := evidence.Select(x, evidence.RoleAttack, true, "primary")
	primary.OccurrenceID = "one-occurrence"
	confirmation := evidence.Select(x, evidence.RoleConfirmation, true, "confirmation")
	confirmation.OccurrenceID = primary.OccurrenceID
	for _, tc := range []struct {
		name    string
		entries []evidence.Entry
		linked  bool
		allowed bool
	}{
		{"receipt-only", []evidence.Entry{primary}, false, true},
		{"receipt-before-legacy-link", []evidence.Entry{primary}, true, true},
		{"unavailable-primary", []evidence.Entry{{ExchangeID: "missing", Role: evidence.RoleAttack, Primary: true}}, true, false},
		{"ambiguous-primary", []evidence.Entry{primary, confirmation}, true, false},
		{"empty-nonlegacy-manifest", nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "replay-loader-" + tc.name, ModuleID: "test", EvidenceStatus: "missing", Evidence: tc.entries,
				URL: "http://legacy.example/fallback", Request: "GET /fallback HTTP/1.1\r\nHost: legacy.example\r\n\r\n"}
			if tc.linked {
				f.HTTPRecordUUIDs = []string{"rec-legacy-replay"}
			}
			if err := repo.SaveFindingDirect(ctx, f); err != nil {
				t.Fatal(err)
			}
			src, err := sourceFromFinding(ctx, repo, f.ID)
			if !tc.allowed {
				if err == nil || src != nil {
					t.Fatalf("selected evidence recovered from legacy fields/link: %+v", src)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if src.InputType != "selected_exchange" || src.Hostname != "destination.example" || src.Port != 8080 || src.Scheme != "http" || !bytes.Equal(src.BaselineRequest, raw) {
				t.Fatalf("replay loader bypassed or repaired authoritative receipt: %+v", src)
			}
		})
	}
}

func TestFindingSelectedEvidenceCLIMissingServiceDoesNotRecoverCapturedURL(t *testing.T) {
	for _, provenance := range []evidence.Provenance{evidence.ProvenanceCaptured, evidence.ProvenanceSupplied} {
		x := evidence.NewExchange("", "https://app.test/proof", []byte("GET /proof HTTP/1.1\r\nHost: app.test\r\n\r\n"), nil, provenance)
		f := &database.Finding{Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "observation")}}
		_, replayErr := sourceFromSelectedFinding(f)
		_, curlOK := findingEvidenceCurl(f)
		req, _, _ := findingPushEvidence(f, nil)
		allowed := provenance == evidence.ProvenanceSupplied
		if (replayErr == nil) != allowed || curlOK != allowed || (len(req) != 0) != allowed {
			t.Fatalf("service-less %s receipt incorrectly recovered or rejected", provenance)
		}
	}
}

func TestFindingSelectedEvidenceJSONAndEventRetainBinaryManifest(t *testing.T) {
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleObservation, true, "observation")
	entry.OccurrenceID, entry.FindingURL, entry.ScanUUID = "occurrence", "https://app.test/finding", "scan"
	f := &database.Finding{ProjectUUID: "project-a", URL: "https://app.test/finding", Evidence: []evidence.Entry{entry}, EvidenceStatus: "selected", AdditionalEvidence: []string{"legacy unknown"}, ModuleID: "test"}
	for _, fullBody := range []bool{true, false} {
		v := compactFindingView(f, nil, agentViewOptions{fullBody: fullBody})
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var got database.Finding
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.EvidenceStatus != "selected" || len(got.Evidence) != 1 || !bytes.Equal(got.Evidence[0].Exchange.Response, x.Response) || got.Evidence[0].OccurrenceID != "occurrence" {
			t.Fatalf("JSON lost selected bytes/manifest: %s", data)
		}
	}
	v := compactFindingView(f, nil, agentViewOptions{noBodies: true})
	if entries := v["evidence"].([]evidence.Entry); len(entries) != 1 || entries[0].Exchange != nil || entries[0].Role != evidence.RoleObservation {
		t.Fatal("compact dropped manifest roles or retained raw bodies")
	}
	ev := convertFindingToEvent(f, &database.HTTPRecord{URL: "https://app.test/unrelated"})
	if ev.Host != f.URL || ev.EvidenceStatus != f.EvidenceStatus || !bytes.Equal(ev.Evidence[0].Exchange.Request, x.Request) || len(ev.AdditionalEvidence) != 1 {
		t.Fatal("JSONL event conversion dropped contract")
	}
	data, _ := json.Marshal(ev)
	loaded, err := tryParseSingleResultEvent(string(data), "", "project-a")
	if err != nil || len(loaded.Evidence) != 1 || !bytes.Equal(loaded.Evidence[0].Exchange.Response, x.Response) {
		t.Fatalf("load lost JSONL contract: %+v %v", loaded, err)
	}
	for _, wrapper := range []any{map[string]any{"type": "finding", "data": f}, map[string]any{"items": []*database.Finding{f}}} {
		wrapped, _ := json.Marshal(wrapper)
		findings, _, err := detectAndParse(string(wrapped), "", "project-a")
		if err != nil || len(findings) != 1 || len(findings[0].Evidence) != 1 || !bytes.Equal(findings[0].Evidence[0].Exchange.Response, x.Response) {
			t.Fatalf("load lost wrapped manifest: %s err=%v", wrapped, err)
		}
	}
}

func TestFindingSelectedEvidenceReaderHydrationKeepsBytesInAllViews(t *testing.T) {
	ctx := context.Background()
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	repo := database.NewRepository(db)
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("POST /proof HTTP/1.1\r\nHost: app.test\r\nContent-Length: 8\r\n\r\n\x00\xffPROOF!"), []byte("HTTP/1.1 200 OK\r\n\r\nSELECTED-BINARY\xff\x00"), evidence.ProvenanceCaptured)
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "reader-hydration", ModuleID: "test", Severity: "high", Confidence: "firm", URL: "https://app.test/finding", Request: "GET /legacy HTTP/1.1\r\n\r\n", Response: "legacy response", EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "proof")}}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"curl", "burp", "markdown", "raw", "finding-json"} {
		t.Run(view, func(t *testing.T) {
			page, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{ProjectUUID: f.ProjectUUID, FindingID: int(f.ID)}).Execute(ctx)
			if err != nil || len(page) != 1 {
				t.Fatalf("list query: %v count=%d", err, len(page))
			}
			got := page[0]
			if got.Evidence[0].Exchange != nil {
				t.Fatal("fixture did not exercise manifest-only list")
			}
			if err := hydrateFindingReaderEvidence(ctx, repo, page, true, true); err != nil {
				t.Fatal(err)
			}
			if got.Request != f.Request || got.Evidence[0].Exchange == nil || !bytes.Equal(got.Evidence[0].Exchange.Response, x.Response) {
				t.Fatal("legacy hydration cleared receipt bytes")
			}
			switch view {
			case "curl":
				it, ok := findingEvidenceCurl(got)
				if !ok || it.ExchangeID != x.ID || it.StdinBase64 == "" {
					t.Fatalf("curl lost selected request: %+v", it)
				}
			case "burp":
				req, resp, url := findingPushEvidence(got, nil)
				// The restored locator omits HTTPS's default port; raw receipt
				// bytes and the effective captured destination remain unchanged.
				if !bytes.Equal(req, x.Request) || !bytes.Equal(resp, x.Response) || url != "https://app.test/proof" {
					t.Fatal("Burp handoff lost exact selected bytes or destination")
				}
				out := captureStdout(t, func() { printSelectedEvidence(got, true) })
				if !strings.Contains(out, "SELECTED-BINARY") {
					t.Fatal("Burp preview lost selected receipt")
				}
			case "markdown":
				var out bytes.Buffer
				renderFindingMarkdown(got, nil, &out, false)
				if !strings.Contains(out.String(), "SELECTED-BINARY") || !strings.Contains(out.String(), "role attack") {
					t.Fatal("Markdown lost selected receipt")
				}
			case "raw":
				out := captureStdout(t, func() { printSelectedEvidence(got, false) })
				if !strings.Contains(out, string(x.Response)) {
					t.Fatal("raw reader lost receipt")
				}
			case "finding-json":
				data, err := json.Marshal(compactFindingView(got, nil, agentViewOptions{}))
				if err != nil {
					t.Fatal(err)
				}
				var decoded database.Finding
				if err := json.Unmarshal(data, &decoded); err != nil {
					t.Fatal(err)
				}
				if decoded.Evidence[0].Exchange == nil || !bytes.Equal(decoded.Evidence[0].Exchange.Request, x.Request) || !bytes.Equal(decoded.Evidence[0].Exchange.Response, x.Response) {
					t.Fatal("finding -j lost base64 bytes")
				}
			}
		})
	}
}

func TestFindingSelectedEvidenceMissingProjectNoRecovery(t *testing.T) {
	// A stateless in-memory finding can carry supplied bytes, but a manifest with
	// no captured project must never be looked up in the database's default scope.
	f := &database.Finding{Evidence: []evidence.Entry{{ExchangeID: "missing", Role: evidence.RoleAttack, Primary: true}}}
	if err := hydrateSelectedFindingEvidence(context.Background(), nil, f, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := findingEvidenceCurl(f); ok {
		t.Fatal("missing manifest request was rendered")
	}
}
