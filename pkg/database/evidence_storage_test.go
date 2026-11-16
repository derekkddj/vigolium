package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func receiptFinding(hash, project string, entries ...evidence.Entry) *Finding {
	return &Finding{FindingHash: hash, ProjectUUID: project, ModuleID: "evidence-test", ModuleName: "Evidence test",
		Severity: "low", URL: "https://example.com/a", EvidenceStatus: "selected", Evidence: entries}
}

func TestEvidenceStorageBinaryIdentityAndScope(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	request := []byte("POST / HTTP/1.1\r\n\r\n\x00\xffrequest")
	response := []byte("HTTP/1.1 200 OK\r\n\r\n\x00\xffresponse")
	x := evidence.NewExchange("https://example.com:443", "https://example.com/a", request, response, evidence.ProvenanceCaptured)
	x2 := evidence.NewExchange(x.Service, x.URL, request, []byte("different response\x00"), evidence.ProvenanceCaptured)
	x3 := evidence.NewExchange("https://example.com:8443", x.URL, request, response, evidence.ProvenanceCaptured)
	if x.ContentHash == x2.ContentHash || x.ContentHash == x3.ContentHash {
		t.Fatal("receipt hash ignores response/service")
	}
	f := receiptFinding("binary", "project-a", evidence.Select(x, evidence.RoleAttack, true, "attack"),
		evidence.Select(x2, evidence.RoleControl, false, "control"), evidence.Select(x3, evidence.RoleConfirmation, true, "confirmation"))
	if err := r.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	manifest, err := r.GetFindingByID(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Evidence) != 3 {
		t.Fatalf("manifest: %+v", manifest.Evidence)
	}
	for _, e := range manifest.Evidence {
		if e.Exchange != nil {
			t.Fatal("detail loaded raw receipts")
		}
	}
	got, err := r.GetEvidenceExchange(ctx, x.ID, "project-a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Request, request) || !bytes.Equal(got.Response, response) || !got.CapturedAt.Equal(x.CapturedAt) {
		t.Fatal("binary receipt/timestamp changed")
	}
	var requestType, responseType string
	if err := db.QueryRowContext(ctx, "SELECT typeof(raw_request), typeof(raw_response) FROM evidence_exchanges WHERE id = ?", x.ID).Scan(&requestType, &responseType); err != nil {
		t.Fatal(err)
	}
	if requestType != "blob" || responseType != "blob" {
		t.Fatalf("raw evidence is %s/%s, not BLOB", requestType, responseType)
	}
	for _, project := range []string{"", "project-b"} {
		if _, err := r.GetEvidenceExchange(ctx, x.ID, project); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("project %q leaked: %v", project, err)
		}
	}
	foreign := &Finding{ID: f.ID, ProjectUUID: "project-b"}
	if err := r.HydrateFindingEvidenceManifest(ctx, []*Finding{foreign}); err != nil || len(foreign.Evidence) != 0 {
		t.Fatalf("foreign manifest: %+v %v", foreign.Evidence, err)
	}
	// An execution identity can exist independently in different projects.
	other := x.Clone()
	other.Response = []byte("project b bytes")
	other.ContentHash = other.Hash()
	if err := r.SaveFindingDirect(ctx, receiptFinding("binary", "project-b", evidence.Select(other, evidence.RoleObservation, true, "b"))); err != nil {
		t.Fatal(err)
	}
	got, err = r.GetEvidenceExchange(ctx, x.ID, "project-a")
	if err != nil || !bytes.Equal(got.Response, response) {
		t.Fatal("foreign write changed receipt")
	}
}

func TestEvidenceStorageImmutableRollbackAndBatch(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("req\x00"), []byte("resp\x00"), evidence.ProvenanceSupplied)
	f := receiptFinding("first", "", evidence.Select(x, evidence.RoleObservation, true, "original"))
	if err := r.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	timeChanged := x.Clone()
	timeChanged.CapturedAt = timeChanged.CapturedAt.Add(time.Nanosecond)
	if err := r.SaveFindingDirect(ctx, receiptFinding("timestamp-mismatch", "", evidence.Select(timeChanged, evidence.RoleObservation, true, "time changed"))); err == nil {
		t.Fatal("accepted immutable timestamp-only mismatch")
	}
	changed := x.Clone()
	changed.Response = []byte("new response")
	changed.ContentHash = changed.Hash() // valid receipt, but reused execution ID
	bad := receiptFinding("first", "", evidence.Select(changed, evidence.RoleAttack, true, "changed"))
	bad.ScanUUID = "must-roll-back"
	if err := r.SaveFindingDirect(ctx, bad); err == nil {
		t.Fatal("accepted immutable ID mismatch")
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence WHERE finding_id = ?", f.ID); n != 1 {
		t.Fatal("failed save appended association")
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'must-roll-back'"); n != 0 {
		t.Fatal("observation escaped rollback")
	}
	invalid := x.Clone()
	invalid.Request[0] = 'X' // stale hash must reject, even for new finding
	badNew := receiptFinding("bad-new", "", evidence.Select(invalid, evidence.RoleAttack, true, "invalid"))
	good := receiptFinding("good-batch", "", evidence.Select(x, evidence.RoleBaseline, false, "baseline"))
	results, err := r.SaveFindingsDirectBatch(ctx, []*Finding{bad, good, badNew})
	if err == nil || results[0].Err == nil || results[1].Err != nil || results[2].Err == nil {
		t.Fatalf("batch outcomes: %+v %v", results, err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings"); n != 2 {
		t.Fatalf("batch isolation: %d findings", n)
	}
	// Reusing the same prepared occurrence is idempotent.
	if err := r.SaveFindingDirect(ctx, good); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence WHERE finding_id = ?", good.ID); n != 1 {
		t.Fatal("idempotent occurrence duplicated")
	}
}

func TestEvidenceStorageDuplicateAndGroupedOccurrenceRoles(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("req"), []byte("resp"), evidence.ProvenanceCaptured)
	var survivor *Finding
	roles := []evidence.Role{evidence.RoleBaseline, evidence.RoleAttack, evidence.RoleControl, evidence.RoleConfirmation, evidence.RoleObservation}
	for i, role := range roles {
		e := evidence.Select(x, role, true, fmt.Sprintf("label-%d", i))
		e.OccurrenceID, e.FindingURL, e.ScanUUID = fmt.Sprintf("occurrence-%d", i), fmt.Sprintf("https://example.com/%d", i), fmt.Sprintf("scan-%d", i)
		hash := "same-hash"
		if i > 1 {
			hash = fmt.Sprintf("distinct-hash-%d", i)
		}
		f := receiptFinding(hash, "", e)
		if i == 0 {
			f.EvidenceStatus = "unclassified"
		}
		if err := r.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
		if survivor == nil {
			survivor = f
		}
	}
	deleted, _, err := r.GroupFindingsByValue(ctx, "", GroupFindingOptions{ByModule: []string{"evidence-test"}, MaxURLs: 1})
	if err != nil || deleted != 3 {
		t.Fatalf("group: %d %v", deleted, err)
	}
	got, err := r.GetFindingByID(ctx, survivor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != len(roles) || got.EvidenceStatus != "selected" {
		t.Fatalf("history lost or latest occurrence status not reflected: %+v", got)
	}
	for i, e := range got.Evidence {
		if e.Role != roles[i] || !e.Primary || e.OccurrenceID != fmt.Sprintf("occurrence-%d", i) || e.Label != fmt.Sprintf("label-%d", i) || e.ScanUUID != fmt.Sprintf("scan-%d", i) || e.FindingURL != fmt.Sprintf("https://example.com/%d", i) {
			t.Fatalf("association %d changed: %+v", i, e)
		}
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"); n != 1 {
		t.Fatal("same receipt duplicated")
	}
	if err := r.DeleteFinding(ctx, survivor.ID); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence"); n != 0 {
		t.Fatal("orphaned associations")
	}
}

func TestEvidenceStorageMissingLegacyAndExport(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	legacy := receiptFinding("legacy", "")
	legacy.EvidenceStatus, legacy.Request, legacy.Response = "", "legacy request", "legacy response"
	if err := r.SaveFindingDirect(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	missing := receiptFinding("missing", "", evidence.Entry{ExchangeID: "not-captured", Role: evidence.RoleUnknown, Label: "unavailable"})
	missing.EvidenceStatus = "missing"
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("request\x00\xff"), nil, evidence.ProvenanceSupplied)
	missing.Evidence = append(missing.Evidence, evidence.Select(x, evidence.RoleObservation, true, "missing response"))
	if err := r.SaveFindingDirect(ctx, missing); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetFindingByID(ctx, legacy.ID)
	if err != nil || len(got.Evidence) != 0 || got.EvidenceStatus != "" {
		t.Fatalf("inferred legacy proof: %+v %v", got, err)
	}
	if err := r.HydrateFindingEvidenceForExport(ctx, missing); err != nil {
		t.Fatal(err)
	}
	if missing.Evidence[0].Exchange != nil || missing.Evidence[1].Exchange.ResponseState != evidence.StateMissing {
		t.Fatal("missing evidence fabricated")
	}
	b, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	var imported Finding
	if err := json.Unmarshal(b, &imported); err != nil {
		t.Fatal(err)
	}
	imported.ID = 0
	dest := newTestDB(t)
	dr := NewRepository(dest)
	if err := dr.SaveFindingDirect(ctx, &imported); err != nil {
		t.Fatal(err)
	}
	gotX, err := dr.GetEvidenceExchange(ctx, x.ID, "")
	if err != nil || !bytes.Equal(gotX.Request, x.Request) || gotX.ResponseState != evidence.StateMissing {
		t.Fatalf("export/import bytes: %+v %v", gotX, err)
	}
}

func TestEvidenceStorageMergeRemappingAndImmutable(t *testing.T) {
	src, path := newFileDB(t, "evidence-source.db")
	dst, _ := newFileDB(t, "evidence-dest.db")
	sr, dr, ctx := NewRepository(src), NewRepository(dst), context.Background()
	if err := dr.SaveFindingDirect(ctx, receiptFinding("unrelated", "")); err != nil {
		t.Fatal(err)
	}
	x := evidence.NewExchange("https://example.com:8443", "https://example.com/a", []byte("req\x00\xff"), []byte("resp\x00\xff"), evidence.ProvenanceCaptured)
	e := evidence.Select(x, evidence.RoleAttack, true, "source")
	e.OccurrenceID = "original-occurrence"
	f := receiptFinding("merged", "", e, evidence.Entry{ExchangeID: "missing", Role: evidence.RoleControl, OccurrenceID: "original-occurrence"})
	if err := sr.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	historicX := evidence.NewExchange("https://example.com", x.URL, x.Request, []byte("historic"), evidence.ProvenanceSupplied)
	historic := receiptFinding("merged", "", evidence.Select(historicX, evidence.RoleBaseline, true, "historic-primary"))
	historic.EvidenceStatus = "unclassified"
	if err := dr.SaveFindingDirect(ctx, historic); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := MergeSQLiteFileWithOptions(ctx, dst, path, MergeOptions{SkipHTTPRecords: true}); err != nil {
			t.Fatal(err)
		}
	}
	var got Finding
	if err := dst.NewSelect().Model(&got).Where("finding_hash = ?", "merged").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if got.ID == f.ID {
		t.Fatal("test failed to force ID remap")
	}
	if err := dr.HydrateFindingEvidenceForExport(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != 3 || got.EvidenceStatus != "unclassified" || got.Evidence[0].Label != "historic-primary" || !got.Evidence[0].Primary ||
		got.Evidence[1].OccurrenceID != e.OccurrenceID || !bytes.Equal(got.Evidence[1].Exchange.Response, x.Response) || got.Evidence[2].Exchange != nil {
		t.Fatalf("merge lost receipts/historic primary/status: %+v", got.Evidence)
	}
	// A valid but different receipt with the same execution ID rejects the merge
	// atomically instead of silently keeping the destination's bytes.
	changed := x.Clone()
	changed.Response = []byte("changed")
	changed.ContentHash = changed.Hash()
	mustExec(t, src, "UPDATE evidence_exchanges SET raw_response = ?, content_hash = ? WHERE id = ?", changed.Response, changed.ContentHash, x.ID)
	if _, err := MergeSQLiteFile(ctx, dst, path); err == nil {
		t.Fatal("merge accepted immutable ID mismatch")
	}
	gotX, err := dr.GetEvidenceExchange(ctx, x.ID, "")
	if err != nil || !bytes.Equal(gotX.Response, x.Response) {
		t.Fatal("merge altered historic bytes")
	}
}

func TestEvidenceStorageProjectReassignmentAndPurge(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("req\x00"), []byte("resp\x00"), evidence.ProvenanceCaptured)
	f := receiptFinding("project-lifecycle", "source-project", evidence.Select(x, evidence.RoleAttack, true, "selected"))
	if err := r.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := r.ReassignProjectData(ctx, "source-project", "target-project"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetEvidenceExchange(ctx, x.ID, "source-project"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("receipt stayed in old project")
	}
	got, err := r.GetFindingByID(ctx, f.ID)
	if err != nil || got.ProjectUUID != "target-project" || len(got.Evidence) != 1 {
		t.Fatalf("reassigned association: %+v %v", got, err)
	}
	if _, err := r.GetEvidenceExchange(ctx, x.ID, "target-project"); err != nil {
		t.Fatal(err)
	}
	if err := r.PurgeProjectData(ctx, "target-project"); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence"); n != 0 {
		t.Fatal("purge orphaned association")
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"); n != 0 {
		t.Fatal("purge retained project receipt")
	}
}

func TestEvidenceStorageEventConversionAndAdditiveMigration(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	ev := makeFindingEvent("static-receipt", "/app.js", severity.Low)
	ev.Response = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + strings.Repeat("x", 512*1024)
	x := evidence.NewExchange("https://example.com", ev.URL, []byte("request\x00"), []byte(ev.Response), evidence.ProvenanceCaptured)
	ev.Evidence, ev.EvidenceStatus = []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "static")}, "selected"
	if err := r.SaveFinding(ctx, ev, nil, "scan", ""); err != nil {
		t.Fatal(err)
	}
	f, err := r.GetFindingByHash(ctx, ev.ID(), "")
	if err != nil {
		t.Fatal(err)
	}
	if f.EvidenceStatus != "selected" || len(f.Evidence) != 1 || f.Evidence[0].Exchange != nil {
		t.Fatalf("event conversion: %+v", f)
	}
	got, err := r.GetEvidenceExchange(ctx, x.ID, "")
	if err != nil || !bytes.Equal(got.Response, []byte(ev.Response)) {
		t.Fatal("static response receipt was windowed")
	}
	// Simulate the previous schema. Migration must neither reinterpret inline
	// text nor infer receipts from existing crawl/reference inventory.
	mustExec(t, db, "DROP TABLE finding_evidence")
	mustExec(t, db, "DROP TABLE evidence_exchanges")
	mustExec(t, db, "ALTER TABLE findings DROP COLUMN evidence_status")
	mustExec(t, db, "UPDATE schema_meta SET version = 5")
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	f, err = r.GetFindingByHash(ctx, ev.ID(), "")
	if err != nil || f.EvidenceStatus != "" || len(f.Evidence) != 0 {
		t.Fatalf("migration invented proof: %+v %v", f, err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"); n != 0 {
		t.Fatal("migration backfilled raw receipts")
	}
}

func TestEvidenceStorageFindingWriterOwnsSnapshot(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	got := make(chan *output.ResultEvent, 1)
	w := NewFindingWriter(nil, FindingWriterConfig{BatchSize: 1, FlushInterval: time.Hour,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			close(entered)
			<-release
			got <- writes[0].Event
			return []FindingSaveResult{{Inserted: true}}
		}})
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("request"), []byte("response"), evidence.ProvenanceCaptured)
	ev := makeFindingEvent("snapshot", "/a", severity.Low)
	ev.Evidence = []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "original")}
	ev.AdditionalEvidence = []string{"original-support"}
	if err := w.Save(context.Background(), ev, []string{"record"}, "scan", ""); err != nil {
		t.Fatal(err)
	}
	<-entered
	ev.Evidence[0].Exchange.Request[0] = 'X'
	ev.Evidence[0].Label = "changed"
	ev.AdditionalEvidence[0] = "changed"
	close(release)
	snapshot := <-got
	if snapshot.Evidence[0].Label != "original" || string(snapshot.Evidence[0].Exchange.Request) != "request" || snapshot.AdditionalEvidence[0] != "original-support" {
		t.Fatal("writer retained producer-owned bytes/slices")
	}
	w.Close()
}
