package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestUpsertSnapshotRecordVersionsChangedResponse(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	first := snapshotPair(t, 200, "first")
	uuid, outcome, err := repo.UpsertSnapshotRecord(ctx, first, "burp-sitemap", "")
	if err != nil || outcome != "inserted" {
		t.Fatalf("first upsert = %q, %v", outcome, err)
	}
	second := snapshotPair(t, 403, "changed")
	uuid2, outcome, err := repo.UpsertSnapshotRecord(ctx, second, "burp-sitemap", "")
	// Unreferenced rows are immutable too: a pending finding can link the first
	// UUID after this call, so reference-check-then-update is never safe.
	if err != nil || outcome != "inserted" || uuid2 == uuid {
		t.Fatalf("second upsert uuid=%q outcome=%q err=%v", uuid2, outcome, err)
	}
	record, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if record.StatusCode != 200 || string(record.RawResponse) != string(first.Response().Raw()) {
		t.Fatalf("original exchange was rewritten: %+v", record)
	}
	version, err := repo.GetRecordByUUID(ctx, uuid2)
	if err != nil {
		t.Fatal(err)
	}
	if version.StatusCode != 403 || string(version.RawResponse) != string(second.Response().Raw()) {
		t.Fatalf("new exchange was not stored exactly: %+v", version)
	}
	_, outcome, err = repo.UpsertSnapshotRecord(ctx, second, "burp-sitemap", "")
	if err != nil || outcome != "unchanged" {
		t.Fatalf("third upsert = %q, %v", outcome, err)
	}
}

func snapshotPair(t *testing.T, status int, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.ParseRawRequestWithURL(
		"GET /snapshot HTTP/1.1\r\nHost: example.test\r\n\r\n", "https://example.test/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	response := httpmsg.NewHttpResponse([]byte("HTTP/1.1 " + statusText(status) + "\r\nContent-Type: text/plain\r\n\r\n" + body))
	return rr.WithResponse(response)
}

func statusText(status int) string {
	if status == 403 {
		return "403 Forbidden"
	}
	return "200 OK"
}
