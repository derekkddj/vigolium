package database

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func redirectRR(t *testing.T, status int, location string) *httpmsg.HttpRequestResponse {
	t.Helper()
	raw := "HTTP/1.1 " + map[int]string{301: "301 Moved Permanently", 302: "302 Found", 200: "200 OK", 304: "304 Not Modified"}[status] + "\r\n"
	if location != "" {
		raw += "Location: " + location + "\r\n"
	}
	raw += "Content-Length: 0\r\n\r\n"

	req := httpmsg.NewHttpRequest([]byte("GET /go HTTP/1.1\r\nHost: example.com\r\n\r\n")).
		WithService(httpmsg.NewServiceSecure("example.com", 443, true))
	return httpmsg.NewHttpRequestResponse(req, httpmsg.NewHttpResponse([]byte(raw)))
}

// A redirect's destination is parsed once at ingestion, so the tree never has to
// read raw_response back to find it.
func TestConversionStoresRedirectLocation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		location string
		want     string
	}{
		{"absolute", 302, "https://example.com/after", "https://example.com/after"},
		{"relative stays relative", 301, "/after", "/after"},
		{"whitespace trimmed", 302, "  /after  ", "/after"},
		{"redirect without a location", 302, "", ""},
		{"not a redirect", 200, "/after", ""},
		{"304 is not a redirect", 304, "/after", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &HTTPRecord{}
			if err := rec.FromHttpRequestResponse(redirectRR(t, tc.status, tc.location)); err != nil {
				t.Fatalf("convert: %v", err)
			}
			if rec.ResponseLocation != tc.want {
				t.Fatalf("ResponseLocation = %q, want %q", rec.ResponseLocation, tc.want)
			}
		})
	}
}

// Each immutable version's destination must describe its own captured response.
// New redirects and non-redirects cannot rewrite an earlier version's location.
func TestRecordResponseVersionKeepsLocationConsistent(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	const project = DefaultProjectUUID

	first := redirectRR(t, 302, "https://example.com/first")
	uuid, err := repo.SaveRecord(ctx, first, "scanner", project)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, uuid); got != "https://example.com/first" {
		t.Fatalf("stored location = %q", got)
	}

	// Replay to a different destination.
	moved := []byte("HTTP/1.1 302 Found\r\nLocation: https://example.com/second\r\nContent-Length: 0\r\n\r\n")
	versionUUID, err := repo.SaveRecordVersion(ctx, uuid, first.WithResponse(httpmsg.NewHttpResponse(moved)))
	if err != nil || versionUUID == uuid {
		t.Fatalf("SaveRecordVersion: uuid=%q err=%v", versionUUID, err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, uuid); got != "https://example.com/first" {
		t.Fatalf("original redirect destination was rewritten: %q", got)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, versionUUID); got != "https://example.com/second" {
		t.Fatalf("after replay, stored location = %q, want the new destination", got)
	}

	// Replay to a non-redirect: the destination must be cleared, not kept.
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	okUUID, err := repo.SaveRecordVersion(ctx, versionUUID, first.WithResponse(httpmsg.NewHttpResponse(ok)))
	if err != nil || okUUID == versionUUID {
		t.Fatalf("SaveRecordVersion: uuid=%q err=%v", okUUID, err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, versionUUID); got != "https://example.com/second" {
		t.Fatalf("previous version destination was rewritten: %q", got)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, okUUID); got != "" {
		t.Fatalf("a record that is no longer a redirect kept location %q", got)
	}
}

// A fetched version must have complete derived data, including the destination,
// while a legacy stub stays request-only.
func TestStubResponseVersionStoresLocation(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)

	insertHTTPRecord(t, db, "stub", DefaultProjectUUID)
	versionUUID, err := repo.SaveRecordVersion(ctx, "stub", redirectRR(t, 301, "/elsewhere"))
	if err != nil || versionUUID == "stub" {
		t.Fatalf("SaveRecordVersion: uuid=%q err=%v", versionUUID, err)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = 'stub'`); got != "" {
		t.Fatalf("stub's response location was rewritten: %q", got)
	}
	if got := scalarStr(t, db, `SELECT COALESCE(response_location, '') FROM http_records WHERE uuid = ?`, versionUUID); got != "/elsewhere" {
		t.Fatalf("backfilled location = %q, want /elsewhere", got)
	}
}

func scalarStr(t *testing.T, db *DB, q string, args ...any) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(context.Background(), q, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return s
}
