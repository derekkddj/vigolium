package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestFindingLinkageCLIInlineScopedAndLazy(t *testing.T) {
	db := newInventoryTestDB(t)
	ctx := context.Background()
	repo := database.NewRepository(db)
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "inline-proof", ModuleID: "m", ModuleName: "M", Severity: "high", Request: "GET /actual HTTP/1.1\r\nHost: app.test\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nINLINE-PROOF", ExtractedResults: []string{"INLINE-PROOF"}}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	findings, _, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}).ExecuteWithCount(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%v err=%v", findings, err)
	}
	if findings[0].Request != "" || findings[0].Response != "" {
		t.Fatal("list eagerly hydrated proof")
	}
	for _, opts := range []agentViewOptions{{noBodies: true}, {fields: []string{"id", "severity"}}} {
		if findingJSONNeedsInline(opts) {
			t.Fatal("metadata-only mode wants heavy proof")
		}
	}
	if !findingJSONNeedsInline(agentViewOptions{fullBody: true}) {
		t.Fatal("full-body mode misses proof")
	}
	if err := repo.HydrateFindingEvidence(ctx, findings); err != nil {
		t.Fatal(err)
	}
	view := compactFindingView(findings[0], nil, agentViewOptions{fullBody: true})
	if view["request"] != f.Request || view["response"] != f.Response {
		t.Fatalf("full-body proof omitted: %v", view)
	}
	var md strings.Builder
	renderFindingMarkdown(findings[0], nil, &md, false)
	if !strings.Contains(md.String(), "INLINE-PROOF") {
		t.Fatal("markdown misses hydrated inline proof")
	}
	wrong := &database.Finding{ID: f.ID, ProjectUUID: "wrong-project"}
	if err := repo.HydrateFindingEvidence(ctx, []*database.Finding{wrong}); err != nil {
		t.Fatal(err)
	}
	if wrong.Request != "" || wrong.Response != "" {
		t.Fatal("inline project mismatch loaded bodies")
	}
}

func TestFindingLinkageCLIRecordsProjectScoped(t *testing.T) {
	db := newInventoryTestDB(t)
	ctx := context.Background()
	repo := database.NewRepository(db)
	own := seedInventoryRecord(t, db, "own-record", database.DefaultProjectUUID, "", "GET", "/own", "GET /own HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	foreign := seedInventoryRecord(t, db, "foreign-record", "foreign-project", "", "GET", "/foreign", "FOREIGN-SECRET-BODY")
	f := &database.Finding{FindingHash: "linked-proof", ModuleID: "m", ModuleName: "M", Severity: "high", HTTPRecordUUIDs: []string{own.UUID}}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	// Deliberate legacy corruption bypassing the writer policy.
	f.HTTPRecordUUIDs = []string{foreign.UUID, "ghost-record"}
	views := findingViews(ctx, db, []*database.Finding{f}, agentViewOptions{}, true)
	doc, _ := json.Marshal(views)
	if strings.Contains(string(doc), "FOREIGN-SECRET-BODY") {
		t.Fatal("foreign body exposed")
	}
	if !strings.Contains(string(doc), "own-record") || !strings.Contains(string(doc), "ghost-record") || !strings.Contains(string(doc), "unavailable") {
		t.Fatalf("proof/ghost refs absent: %s", doc)
	}
	// Mixed-project page cannot let a corrupt foreign ref borrow another row's
	// legitimately loaded evidence through the shared UUID map.
	other := &database.Finding{ProjectUUID: "foreign-project", HTTPRecordUUIDs: []string{foreign.UUID}}
	byUUID, err := batchLoadFindingRecords(ctx, db, []*database.Finding{f, other}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if byUUID[foreign.UUID] != nil {
		t.Fatal("contested UUID unsafe in shared human renderer map")
	}
	// Matching URLs are not evidence identities. A ghost link remains ghost
	// even when a different, unlinked exchange exists at the finding's URL.
	ghost := &database.Finding{ProjectUUID: database.DefaultProjectUUID, URL: own.URL, HTTPRecordUUIDs: []string{"missing-exact-ref"}}
	byUUID, err = batchLoadFindingRecords(ctx, db, []*database.Finding{ghost}, 0)
	if err != nil || len(byUUID) != 0 {
		t.Fatalf("fabricated URL-based proof: %v %v", byUUID, err)
	}
}

func TestFindingLinkageCLIGlobScopesBeforeBodyLoad(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	writeFindingGlobFixture(t, dir, "b.example")
	t.Cleanup(resetDBCacheForTest)
	db, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"), globDBSkipSet{Records: true, RecordFileMap: true})
	findings[0].HTTPRecordUUIDs = append(findings[0].HTTPRecordUUIDs, "rec-b.example", "ghost-record")
	views := findingViews(context.Background(), db, findings[:1], agentViewOptions{fullBody: true}, true)
	doc, _ := json.Marshal(views)
	if strings.Contains(string(doc), "body-of-b.example") {
		t.Fatal("foreign source-file proof loaded")
	}
	if !strings.Contains(string(doc), "body-of-a.example") || !strings.Contains(string(doc), "unavailable") {
		t.Fatalf("missing own proof/unavailable refs: %s", doc)
	}
}
