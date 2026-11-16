package database

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"testing"

	"github.com/uptrace/bun"
)

func assertFindingLinkUnion(t *testing.T, db *DB, id int64, want []string) {
	t.Helper()
	f, err := NewRepository(db).GetFindingByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var links []string
	if err := db.NewRaw("SELECT record_uuid FROM finding_records WHERE finding_id = ? ORDER BY record_uuid", id).Scan(context.Background(), &links); err != nil {
		t.Fatal(err)
	}
	got := slices.Clone(f.HTTPRecordUUIDs)
	slices.Sort(got)
	want = slices.Clone(want)
	slices.Sort(want)
	if !slices.Equal(got, want) || !slices.Equal(links, want) {
		t.Fatalf("array=%v junction=%v want=%v", got, links, want)
	}
}

func TestFindingLinkageMigrationUnionAndRollback(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	survivor := insertFinding(t, db, DefaultProjectUUID, "survivor-links", "array-s")
	dup := insertFinding(t, db, DefaultProjectUUID, "dup-links", "array-d")
	mustExec(t, db, "INSERT INTO finding_records VALUES (?, ?), (?, ?)", survivor, "junction-s", dup, "junction-d")
	rollback := fmt.Errorf("rollback")
	err := db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if err := migrateFindingRecordsTx(ctx, tx, survivor, []int64{dup}); err != nil {
			return err
		}
		return rollback
	})
	if err != rollback {
		t.Fatal(err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_records WHERE finding_id = ?", survivor); n != 1 {
		t.Fatal("migration escaped rollback")
	}
	err = db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		if err := migrateFindingRecordsTx(ctx, tx, survivor, []int64{dup}); err != nil {
			return err
		}
		return deleteFindingsByIDsTx(ctx, tx, []int64{dup})
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFindingLinkUnion(t, db, survivor, []string{"array-s", "array-d", "junction-s", "junction-d"})
}

func TestFindingLinkageConflictSupportingPairsAndActualID(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	original := &Finding{FindingHash: "proof-hash", ModuleID: "m", ModuleName: "M", Severity: "low", Status: "fixed", OriginRecordUUID: "historic-origin", AgenticScanUUID: "historic-parent", Request: "request-1", Response: "response-1", HTTPRecordUUIDs: []string{"ghost-old"}}
	if err := repo.SaveFindingDirect(ctx, original); err != nil {
		t.Fatal(err)
	}
	incoming := &Finding{ID: 9999, FindingHash: original.FindingHash, ModuleID: "m", ModuleName: "M", Severity: "low", Status: "draft", OriginRecordUUID: "new-origin", AgenticScanUUID: "new-parent", Request: "request-2", Response: "response-2", Remediation: "fill empty", AdditionalEvidence: []string{"support-1", "support-2"}, HTTPRecordUUIDs: []string{"ghost-new"}}
	// Candidate ids should not be reused by INSERT in normal saves; deliberately
	// stale id exercises conflict's returned canonical identity.
	inserted, err := repo.SaveFindingReported(ctx, incoming)
	if err != nil || inserted {
		t.Fatalf("inserted=%v err=%v", inserted, err)
	}
	if incoming.ID != original.ID {
		t.Fatalf("returned id %d, want %d", incoming.ID, original.ID)
	}
	got, err := repo.GetFindingByID(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{buildEvidence(incoming.Request, incoming.Response), "support-1", "support-2"}
	if !slices.Equal(got.AdditionalEvidence, want) {
		t.Fatalf("support=%v want=%v", got.AdditionalEvidence, want)
	}
	// A re-detected fixed finding is reopened for triage; the rest of its
	// history is kept.
	if got.Status != "triaged" || got.OriginRecordUUID != "historic-origin" || got.AgenticScanUUID != "historic-parent" || got.Remediation != "fill empty" {
		t.Fatalf("historic fields/enrichment changed: %+v", got)
	}
	for i := 0; i < maxAdditionalEvidence+3; i++ {
		f := &Finding{FindingHash: original.FindingHash, ModuleID: "m", ModuleName: "M", Severity: "low", AdditionalEvidence: []string{fmt.Sprintf("support-%d", i+3)}}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	got, _ = repo.GetFindingByID(ctx, original.ID)
	if len(got.AdditionalEvidence) != maxAdditionalEvidence || !slices.Equal(got.AdditionalEvidence[:3], want) {
		t.Fatal("cap must retain earliest supporting pairs")
	}
	assertFindingLinkUnion(t, db, original.ID, []string{"ghost-old", "ghost-new"})
}

func TestFindingLinkageConflictPreservesUniqueTail(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	original := &Finding{FindingHash: "unique-tail", ModuleID: "m", ModuleName: "M", Severity: "low", Request: "primary-request", Response: "primary-response"}
	for i := 0; i < maxAdditionalEvidence-1; i++ {
		original.AdditionalEvidence = append(original.AdditionalEvidence, buildEvidence(fmt.Sprintf("request-%d", i), fmt.Sprintf("response-%d", i)))
	}
	if err := repo.SaveFindingDirect(ctx, original); err != nil {
		t.Fatal(err)
	}
	want := append(slices.Clone(original.AdditionalEvidence), buildEvidence("new-request", "new-response"))
	incoming := &Finding{FindingHash: original.FindingHash, ModuleID: "m", ModuleName: "M", Severity: "low"}
	incoming.AdditionalEvidence = append(slices.Clone(original.AdditionalEvidence), buildEvidence(original.Request, original.Response), want[len(want)-1], "later-pair")
	inserted, err := repo.SaveFindingReported(ctx, incoming)
	if err != nil || inserted || incoming.ID != original.ID {
		t.Fatalf("inserted=%v id=%d err=%v", inserted, incoming.ID, err)
	}
	got, err := repo.GetFindingByID(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AdditionalEvidence, want) {
		t.Fatalf("duplicate prefix consumed the sample: got %v want %v", got.AdditionalEvidence, want)
	}
}

func TestFindingLinkageFreshSupportingPairCap(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	f := &Finding{FindingHash: "fresh-cap", ModuleID: "m", ModuleName: "M", Severity: "low", Request: "primary", Response: "response"}
	f.AdditionalEvidence = []string{"", buildEvidence(f.Request, f.Response)}
	var want []string
	for i := 0; i < maxAdditionalEvidence+2; i++ {
		pair := buildEvidence(fmt.Sprintf("request-%d", i), "response")
		f.AdditionalEvidence = append(f.AdditionalEvidence, pair, pair)
		if i < maxAdditionalEvidence {
			want = append(want, pair)
		}
	}
	if err := repo.SaveFindingDirect(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetFindingByID(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AdditionalEvidence, want) || !slices.Equal(f.AdditionalEvidence, want) {
		t.Fatalf("fresh sample: stored=%v returned=%v want=%v", got.AdditionalEvidence, f.AdditionalEvidence, want)
	}
	if f.RecordKind != got.RecordKind || f.Status != got.Status || f.Confidence != got.Confidence || !f.FoundAt.Equal(got.FoundAt) || !f.CreatedAt.Equal(got.CreatedAt) {
		t.Fatal("fresh insert did not return Bun-populated defaults to the caller")
	}
}

func TestFindingLinkageForeignWriteAndScopedHydration(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	insertHTTPRecord(t, db, "foreign-record", "foreign-project")
	f := &Finding{ProjectUUID: DefaultProjectUUID, FindingHash: "foreign-proof", ModuleID: "m", ModuleName: "M", Severity: "low", HTTPRecordUUIDs: []string{"foreign-record"}}
	if err := repo.SaveFindingDirect(ctx, f); err == nil {
		t.Fatal("existing foreign reference accepted")
	}
	f.HTTPRecordUUIDs = []string{"not-imported-yet"}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatalf("soft ref rejected: %v", err)
	}
	records, err := repo.GetFindingRecordsScoped(ctx, DefaultProjectUUID, []string{"foreign-record", "not-imported-yet"})
	if err != nil || len(records) != 0 {
		t.Fatalf("foreign record loaded: %v %v", records, err)
	}
	insertHTTPRecord(t, db, "own-inventory-record", DefaultProjectUUID)
	refs := []string{"foreign-record", "not-imported-yet", "own-inventory-record"}
	for project, want := range map[string][]string{"": {"own-inventory-record"}, "foreign-project": {"foreign-record"}} {
		available, err := repo.GetFindingRecordUUIDsScoped(ctx, project, refs)
		if err != nil || !slices.Equal(available, want) {
			t.Fatalf("inventory project=%q got=%v want=%v err=%v", project, available, want, err)
		}
	}
}

func TestFindingLinkageGroupingHistory(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	var findings []*Finding
	for i := 0; i < 2; i++ {
		f := &Finding{FindingHash: fmt.Sprintf("group-%d", i), ModuleID: "m", ModuleName: "M", Severity: "low", ScanUUID: fmt.Sprintf("scan-%d", i), ExtractedResults: []string{"same-secret"}, MatchedAt: []string{fmt.Sprintf("https://example.com/%d", i)}, HTTPRecordUUIDs: []string{fmt.Sprintf("ghost-%d", i)}}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
		findings = append(findings, f)
	}
	mustExec(t, db, "INSERT INTO finding_status_events (finding_id, project_uuid, to_status) VALUES (?, ?, 'fixed')", findings[1].ID, DefaultProjectUUID)
	deleted, _, err := repo.GroupFindingsByValue(ctx, DefaultProjectUUID, GroupFindingOptions{})
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	assertFindingLinkUnion(t, db, findings[0].ID, []string{"ghost-0", "ghost-1"})
	if scans := observationScans(t, db, findings[0].ID); !slices.Equal(scans, []string{"scan-0", "scan-1"}) {
		t.Fatalf("lost observations: %v", scans)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_status_events WHERE finding_id = ?", findings[0].ID); n != 1 {
		t.Fatal("lost status history")
	}
}

func TestFindingLinkageSQLiteMergePreservesReferenceOrder(t *testing.T) {
	ctx := context.Background()
	src, srcPath := newFileDB(t, "order-src.sqlite")
	dst, _ := newFileDB(t, "order-dst.sqlite")
	sourceID := insertFinding(t, src, DefaultProjectUUID, "ordered-hash", "z-source")
	destID := insertFinding(t, dst, DefaultProjectUUID, "ordered-hash", "z-dest")
	freshID := insertFinding(t, src, DefaultProjectUUID, "fresh-ordered-hash", "z-first")
	untouchedID := insertFinding(t, dst, DefaultProjectUUID, "untouched", "z-untouched")
	mustExec(t, src, `UPDATE findings SET http_record_uuids = '["z-source","b-source"]' WHERE id = ?`, sourceID)
	mustExec(t, dst, `UPDATE findings SET http_record_uuids = '["z-dest","b-dest"]' WHERE id = ?`, destID)
	mustExec(t, src, `UPDATE findings SET http_record_uuids = '["z-first","a-second","z-first"]' WHERE id = ?`, freshID)
	mustExec(t, dst, `UPDATE findings SET http_record_uuids = '["z-untouched","a-untouched"]' WHERE id = ?`, untouchedID)
	mustExec(t, src, "INSERT INTO finding_records VALUES (?, ?)", sourceID, "a-source-junction")
	mustExec(t, dst, "INSERT INTO finding_records VALUES (?, ?)", destID, "a-dest-junction")
	want := []string{"z-dest", "b-dest", "z-source", "b-source", "a-dest-junction", "a-source-junction"}
	for i := 0; i < 2; i++ {
		if _, err := MergeSQLiteFileWithOptions(ctx, dst, srcPath, MergeOptions{}); err != nil {
			t.Fatal(err)
		}
		f, err := NewRepository(dst).GetFindingByID(ctx, destID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(f.HTTPRecordUUIDs, want) {
			t.Fatalf("merge %d reordered refs: got %v want %v", i, f.HTTPRecordUUIDs, want)
		}
		assertFindingLinkUnion(t, dst, destID, want)
	}
	var fresh Finding
	if err := dst.NewSelect().Model(&fresh).Where("finding_hash = ?", "fresh-ordered-hash").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if freshID == 0 || !slices.Equal(fresh.HTTPRecordUUIDs, []string{"z-first", "a-second"}) {
		t.Fatalf("fresh refs reordered or not deduplicated: %v", fresh.HTTPRecordUUIDs)
	}
	assertFindingLinkUnion(t, dst, fresh.ID, []string{"z-first", "a-second"})
	untouched, err := NewRepository(dst).GetFindingByID(ctx, untouchedID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(untouched.HTTPRecordUUIDs, []string{"z-untouched", "a-untouched"}) || scalarInt(t, dst, "SELECT COUNT(*) FROM finding_records WHERE finding_id = ?", untouchedID) != 0 {
		t.Fatal("merge repaired an untouched destination finding")
	}
}

func TestFindingLinkageSQLiteMergeUnion(t *testing.T) {
	ctx := context.Background()
	src, srcPath := newFileDB(t, "link-src.sqlite")
	dst, _ := newFileDB(t, "link-dst.sqlite")
	sourceID := insertFinding(t, src, DefaultProjectUUID, "same-hash", "source-array")
	destID := insertFinding(t, dst, DefaultProjectUUID, "same-hash", "dest-array")
	mustExec(t, src, "INSERT INTO finding_records VALUES (?, ?)", sourceID, "source-junction")
	mustExec(t, dst, "INSERT INTO finding_records VALUES (?, ?)", destID, "dest-junction")
	mustExec(t, src, `UPDATE findings SET request = 'new-request', response = 'new-response', additional_evidence = '["support"]' WHERE id = ?`, sourceID)
	mustExec(t, dst, `UPDATE findings SET request = 'historic-request', response = 'historic-response', status = 'fixed' WHERE id = ?`, destID)
	for i := 0; i < 2; i++ {
		if _, err := MergeSQLiteFileWithOptions(ctx, dst, srcPath, MergeOptions{}); err != nil {
			t.Fatal(err)
		}
		assertFindingLinkUnion(t, dst, destID, []string{"dest-array", "dest-junction", "source-array", "source-junction"})
	}
	f, err := NewRepository(dst).GetFindingByID(ctx, destID)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != "fixed" || f.Request != "historic-request" || !slices.Equal(f.AdditionalEvidence, []string{buildEvidence("new-request", "new-response"), "support"}) {
		t.Fatalf("merge lost proof/history: %+v", f)
	}
}
