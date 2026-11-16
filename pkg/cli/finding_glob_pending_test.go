package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingLinkageCLIGlobStopsWhenResolved(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	unrelated := writeFindingGlobFixture(t, dir, "b.example")
	t.Cleanup(resetDBCacheForTest)
	db, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"), globDBSkipSet{Records: true, RecordFileMap: true})
	// The unrelated source disappearing after the merge must not affect a
	// selected finding whose exact proof was already found in its own file.
	if err := os.Remove(unrelated); err != nil {
		t.Fatal(err)
	}
	byUUID, err := batchLoadFindingRecords(context.Background(), db, findings[:1], 0)
	if err != nil || byUUID["rec-a.example"] == nil {
		t.Fatalf("resolved evidence lost to an unrelated source: records=%v err=%v", byUUID, err)
	}
	// The pending set must respect the display cap too, not trigger a corpus
	// sweep for references that were never requested.
	findings[0].HTTPRecordUUIDs = append(findings[0].HTTPRecordUUIDs, "unrequested-ghost")
	byUUID, err = batchLoadFindingRecords(context.Background(), db, findings[:1], 1)
	if err != nil || len(byUUID) != 1 {
		t.Fatalf("unrequested reference triggered a source sweep: records=%v err=%v", byUUID, err)
	}
}

func TestFindingLinkageCLIGlobRecoveredProofStillReportsSourceFailure(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	failed := writeFindingGlobFixture(t, dir, "b.example")
	fallback := writeFindingGlobFixture(t, dir, "c.example")
	t.Cleanup(resetDBCacheForTest)
	db, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"), globDBSkipSet{Records: true, RecordFileMap: true})
	// Move the selected finding's proof into a later source after the merge:
	// its attributed source fails, but a fallback supplies the exact same ref.
	if err := os.Rename(failed, fallback); err != nil {
		t.Fatal(err)
	}
	byUUID, err := batchLoadFindingRecords(context.Background(), db, findings[1:2], 0)
	if err == nil || !strings.Contains(err.Error(), failed) || byUUID["rec-b.example"] == nil {
		t.Fatalf("recovered proof concealed the failed source: records=%v err=%v", byUUID, err)
	}
	views := findingViews(context.Background(), db, findings[1:2], agentViewOptions{fullBody: true}, true)
	if len(views) != 1 || views[0]["records_error"] == nil || views[0]["records_truncated"] == true {
		t.Fatalf("recovered bundle hid source failure or mislabeled it: %v", views)
	}
}

func TestFindingLinkageCLIGlobPreservesPartialResultsAndErrors(t *testing.T) {
	dir := t.TempDir()
	writeFindingGlobFixture(t, dir, "a.example")
	failed := writeFindingGlobFixture(t, dir, "b.example")
	writeFindingGlobFixture(t, dir, "c.example")
	t.Cleanup(resetDBCacheForTest)
	db, findings := mergedFindings(t, filepath.Join(dir, "scan-*.sqlite"), globDBSkipSet{Records: true, RecordFileMap: true})
	if err := os.Remove(failed); err != nil {
		t.Fatal(err)
	}
	byUUID, err := batchLoadFindingRecords(context.Background(), db, findings, 0)
	if err == nil || !strings.Contains(err.Error(), failed) {
		t.Fatalf("failed source hidden: err=%v", err)
	}
	if len(byUUID) != 2 || byUUID["rec-a.example"] == nil || byUUID["rec-c.example"] == nil || byUUID["rec-b.example"] != nil {
		t.Fatalf("partial proof discarded or later source not visited: %v", byUUID)
	}
	views := findingViews(context.Background(), db, findings, agentViewOptions{fullBody: true}, true)
	doc, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []string{"body-of-a.example", "body-of-c.example", "rec-b.example", "unavailable", failed} {
		if !strings.Contains(string(doc), proof) {
			t.Fatalf("partial bundle omits %q: %s", proof, doc)
		}
	}
	for _, view := range views {
		if view["records_error"] == nil {
			t.Fatal("partial result concealed the failed corpus source")
		}
		if view["records_truncated"] == true {
			t.Fatal("source failure mislabeled as display truncation")
		}
	}
}
