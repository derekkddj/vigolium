package oast

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
)

func plantingTestExchange(nonce string) *evidence.Exchange {
	return evidence.NewExchange("https://victim.example:8443", "https://victim.example:8443/plant", []byte("POST /plant HTTP/1.1\r\nHost: victim.example\r\nCookie: actual=sent\r\nX-OAST: "+nonce+".cb.example\r\n\r\nentity=http://"+nonce+".cb.example"), []byte("HTTP/1.1 202 Accepted\r\n\r\nactual planting answer\x00\xff"), evidence.ProvenanceCaptured)
}

func primaryPlanting(t *testing.T, entries []evidence.Entry) *evidence.Exchange {
	t.Helper()
	for _, e := range entries {
		if e.Primary {
			if e.Role != evidence.RoleAttack || e.Exchange == nil {
				t.Fatalf("unexpected primary evidence: %+v", e)
			}
			return e.Exchange
		}
	}
	t.Fatal("missing planting primary")
	return nil
}

func TestOASTPlantingReceiptOwnsOnlyActualExchange(t *testing.T) {
	s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
	callback := s.GenerateURLFor(oastclass.XXE, "https://victim.example/old", "body", "xxe", "xxe", "original-hash")
	nonce := s.NonceForCallback(callback)
	x := plantingTestExchange(nonce)
	original := x.Clone()
	if err := s.RegisterPlantingReceipt(nonce, x); err != nil {
		t.Fatal(err)
	}
	// A producer may close/reuse/edit its chain immediately after handoff.
	x.Request[0] = 'X'
	x.Response[0] = 'X'
	in := &server.Interaction{UniqueID: nonce, Protocol: "http", RawRequest: "GET /entity HTTP/1.1\r\nHost: " + callback + "\r\n\r\n", RawResponse: "HTTP/1.1 204 No Content\r\n\r\n", Timestamp: time.Unix(100, 123).UTC()}
	result := s.reportCorrelated(in, nonce, PayloadContext{TargetURL: "https://victim.example/old", Class: oastclass.XXE, ModuleID: "xxe", CallbackURL: callback})
	if result == nil || result.EvidenceStatus != "selected" {
		t.Fatalf("actual planting was not selected: %+v", result)
	}
	proof := primaryPlanting(t, result.Evidence)
	if proof.ID != original.ID || proof.ContentHash != original.ContentHash || !bytes.Equal(proof.Request, original.Request) || !bytes.Equal(proof.Response, original.Response) || proof.Service != original.Service || proof.URL != original.URL {
		t.Fatalf("planting pair mixed with callback/intent: %+v", proof)
	}
	if result.Request != string(original.Request) || result.Response != string(original.Response) {
		t.Fatal("legacy primary did not project the same owned exchange")
	}
	for _, e := range result.Evidence {
		if e.Role == evidence.RoleObservation && (e.Primary || string(e.Exchange.Response) != in.RawResponse || e.Exchange.Service != "http://"+callback) {
			t.Fatalf("callback exchange was mixed or selected as target proof: %+v", e)
		}
		if e.OccurrenceID == "" || e.FindingURL != result.URL || e.ScanUUID != "s" {
			t.Fatalf("OAST direct save omitted occurrence attribution: %+v", e)
		}
	}
	proof.Response[0] = 'Y'
	if retained := s.plantingReceipt(nonce); retained.Response[0] != original.Response[0] {
		t.Fatal("result selection mutated the stored sender receipt")
	}
}

func TestOASTMissingPlantingKeepsHTTPCallbackSeparate(t *testing.T) {
	s := &Service{}
	in := &server.Interaction{Protocol: "http", UniqueID: "n", RawResponse: "HTTP/1.1 200 OK\r\n\r\ncollector", Timestamp: time.Unix(1, 0).UTC()}
	r := s.reportCorrelated(in, "n", PayloadContext{Class: oastclass.XXE, ModuleID: "xxe", TargetURL: "https://victim.example", CallbackURL: "n.cb.example"})
	if r.EvidenceStatus != "missing" || r.Request != "" || r.Response != "" || evidence.HasSelectedEvidence(r.Evidence) {
		t.Fatalf("response-only callback became target proof: %+v", r)
	}
	if len(r.Evidence) != 1 || r.Evidence[0].Exchange.RequestState != evidence.StateMissing || r.Evidence[0].Exchange.ResponseState != evidence.StateUnknown || r.Evidence[0].Exchange.Provenance != evidence.ProvenanceSupplied {
		t.Fatalf("callback fidelity/absence not explicit: %+v", r.Evidence)
	}
	if !strings.Contains(r.Info.Description, "planting exchange unavailable") {
		t.Fatal("missing planting receipt not disclosed")
	}
}

func TestOASTNonHTTPAndAccessLogNeverBecomeHTTPPairs(t *testing.T) {
	for _, in := range []*server.Interaction{
		{Protocol: "dns", UniqueID: "n", RawRequest: "DNS query n.cb.example IN A", RawResponse: "DNS answer"},
		{Protocol: "smtp", UniqueID: "n", RawRequest: "MAIL FROM:<a@example>", RawResponse: "250 OK"},
		{Protocol: "http", UniqueID: "n", RawRequest: `203.0.113.2 - - [10/Oct/2026:10:00:00 +0000] "GET /n HTTP/1.1" 200 0`},
	} {
		s := &Service{}
		r := s.reportCorrelated(in, "n", PayloadContext{Class: oastclass.XXE, ModuleID: "xxe", TargetURL: "https://victim.example"})
		if r.Request != "" || r.Response != "" || len(r.Evidence) != 0 || r.EvidenceStatus != "missing" {
			t.Fatalf("non-HTTP data became an HTTP exchange: %+v", r)
		}
		if len(r.AdditionalEvidence) != 1 || output.ParseEvidence(r.AdditionalEvidence[0]).IsPair() || !strings.Contains(r.AdditionalEvidence[0], strconv.Quote(in.RawRequest)) {
			t.Fatalf("raw interaction not retained as separate data: %+v", r)
		}
	}
}

func TestOASTPlantingRejectsMissingCachedUnknownAndChangedBindings(t *testing.T) {
	s := newFixedService(t, nil, "https://cb.example/{nonce}", "p", "s")
	callback := s.GenerateURL("https://victim.example", "body", "ssrf", "ssrf", "h")
	nonce := s.NonceForCallback("http://" + callback)
	if nonce == "" {
		t.Fatal("fixed path nonce extraction failed")
	}
	original := plantingTestExchange(nonce)
	for _, variant := range []string{"unknown nonce", "missing request", "cached", "legacy", "supplied", "nonce omitted"} {
		t.Run(variant, func(t *testing.T) {
			x, n := original.Clone(), nonce
			switch variant {
			case "unknown nonce":
				n = "unknown"
			case "missing request":
				x.Request = nil
				x.RequestState = evidence.StateMissing
			case "cached":
				x.Provenance = evidence.ProvenanceCached
			case "legacy":
				x.Provenance = evidence.ProvenanceLegacy
			case "supplied":
				x.Provenance = evidence.ProvenanceSupplied
			case "nonce omitted":
				x.Request = []byte("GET / HTTP/1.1\r\nHost: victim.example\r\n\r\n")
			}
			x.ContentHash = x.Hash()
			if err := s.RegisterPlantingReceipt(n, x); err == nil {
				t.Fatalf("accepted %s", variant)
			}
		})
	}
	if err := s.RegisterPlantingReceipt(nonce, original); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterPlantingReceipt(nonce, original.Clone()); err != nil {
		t.Fatal(err)
	}
	other := plantingTestExchange(nonce) // same content, different execution
	if err := s.RegisterPlantingReceipt(nonce, other); err == nil {
		t.Fatal("one nonce silently replaced by a different execution")
	}
}

func TestOASTPersistedPlantingLateIngestAndProjectIsolation(t *testing.T) {
	ctx := context.Background()
	repo := newOASTTestRepo(t)
	s := newFixedService(t, repo, "https://cb.example/{nonce}", "project-a", "scan-a")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example", "body", "xxe", "xxe", "baseline-hash")
	nonce := s.NonceForCallback(cb)
	x := plantingTestExchange(nonce)
	if err := s.ObservePlantingReceipt(x); err != nil {
		t.Fatal(err)
	}
	s.Close() // drains asynchronous sender handoff and persists the mint context
	late := &Service{repo: repo, projectUUID: "project-a", scanUUID: "scan-a"}
	late.trackerCache().Purge()
	if pctx, found := late.payloadContextForNonce(nonce); !found || pctx.RequestHash != "baseline-hash" {
		t.Fatalf("late nonce context missing: %+v %v", pctx, found)
	}
	persisted := late.plantingReceipt(nonce)
	if persisted == nil || persisted.ID != x.ID || !bytes.Equal(persisted.Response, x.Response) || !persisted.CapturedAt.Equal(x.CapturedAt) {
		t.Fatalf("late receipt changed or disappeared: %+v", persisted)
	}
	for _, foreign := range []*Service{{repo: repo, projectUUID: "project-b", scanUUID: "scan-a"}, {repo: repo, projectUUID: "project-a", scanUUID: "scan-b"}, {repo: repo, scanUUID: "scan-a"}} {
		if foreign.plantingReceipt(nonce) != nil {
			t.Fatal("planting receipt escaped project/scan scope")
		}
	}
	in := server.Interaction{Protocol: "http", RawRequest: "GET /" + nonce + " HTTP/1.1\r\nHost: cb.example\r\n\r\n", RawResponse: "HTTP/1.1 200 OK\r\n\r\ncollector answer", Timestamp: time.Unix(20, 0).UTC()}
	callbacks := []Callback{{Interaction: in, Where: []string{cb}}}
	res, err := Ingest(ctx, repo, "project-a", callbacks)
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("late ingest: %+v %v", res, err)
	}
	f, err := repo.GetFindingByHash(ctx, res.Findings[0].FindingHash, "project-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.HydrateFindingEvidenceForExport(ctx, f); err != nil {
		t.Fatal(err)
	}
	proof := primaryPlanting(t, f.Evidence)
	if proof.ID != x.ID || !bytes.Equal(proof.Request, x.Request) || !bytes.Equal(proof.Response, x.Response) || f.EvidenceStatus != "selected" {
		t.Fatalf("ingest paired planting intent with collector/baseline: %+v", f)
	}
	other, err := Ingest(ctx, repo, "project-b", callbacks)
	if err != nil || other.Matched != 0 {
		t.Fatalf("foreign ingest claimed nonce: %+v %v", other, err)
	}
	if _, err := repo.GetEvidenceExchange(ctx, x.ID, "project-b"); err == nil {
		t.Fatal("selected receipt escaped evidence project scope")
	}
}

func TestOASTUpgradePreservesReceiptHistoryAndFindingIdentity(t *testing.T) {
	repo := newOASTTestRepo(t)
	s := newFixedService(t, repo, "https://{nonce}.cb.example", "p", "s")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example", "body", "xxe", "xxe", "")
	nonce := s.NonceForCallback(cb)
	x := plantingTestExchange(nonce)
	if err := s.RegisterPlantingReceipt(nonce, x); err != nil {
		t.Fatal(err)
	}
	pctx, _ := s.trackerCache().Get(nonce)
	dns := s.reportCorrelated(&server.Interaction{Protocol: "dns", UniqueID: nonce, RawRequest: "DNS data"}, nonce, pctx)
	f1, err := repo.GetFindingByHash(context.Background(), dns.ID(), "p")
	if err != nil {
		t.Fatal(err)
	}
	httpResult := s.reportCorrelated(&server.Interaction{Protocol: "http", UniqueID: nonce, RawRequest: "GET / HTTP/1.1\r\nHost: " + cb + "\r\n\r\n", RawResponse: "HTTP/1.1 200 OK\r\n\r\n", Timestamp: time.Unix(2, 0).UTC()}, nonce, pctx)
	f2, err := repo.GetFindingByHash(context.Background(), httpResult.ID(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if f1.ID != f2.ID || len(f2.Evidence) != 3 { // first planting, callback observation, second planting association
		t.Fatalf("upgrade deleted finding or occurrence history: before=%+v after=%+v", f1, f2)
	}
	if f1.Evidence[0].OccurrenceID == f2.Evidence[len(f2.Evidence)-1].OccurrenceID {
		t.Fatal("upgrade lost separate occurrence identity")
	}
	s.Close()
}

func TestOASTOriginResolverCannotLinkForeignBaseline(t *testing.T) {
	repo := newOASTTestRepo(t)
	ctx := context.Background()
	foreign := &database.HTTPRecord{UUID: "foreign", ProjectUUID: "other", Scheme: "https", Hostname: "victim.example", Port: 443, Method: "GET", Path: "/", URL: "https://victim.example/", HTTPVersion: "HTTP/1.1", RequestHash: "h", RawRequest: []byte("GET / HTTP/1.1\r\nHost: victim.example\r\n\r\n")}
	if _, err := repo.DB().NewInsert().Model(foreign).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	s := &Service{repo: repo, projectUUID: "mine", resolveRequestUUID: func(string) string { return "foreign" }}
	id, origin := s.originRecord("h")
	if id != "" || origin != nil {
		t.Fatalf("foreign resolver became baseline: %q %+v", id, origin)
	}
}
