package database

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// provRR parses a raw request against url, with a response when resp != "".
func provRR(t *testing.T, raw, url, resp string) *httpmsg.HttpRequestResponse {
	t.Helper()
	rr, err := httpmsg.ParseRawRequestWithURL(raw, url)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	if resp != "" {
		rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte(resp)))
	}
	return rr
}

const provOK = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"

// drainDA serves every record a risk-prioritized source yields and returns
// their (method, path) keys.
func drainDA(t *testing.T, src *RiskPrioritizedDBInputSource) []string {
	t.Helper()
	var got []string
	for {
		item, err := src.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, item.Request.Request().Method()+" "+item.Request.Request().Path())
		item.Complete()
	}
}

// The write gate reads first-write provenance: an ingested POST/DELETE
// template is held back, and so is the exchange fetched from it, a
// captured POST (stored with its response) is served, safe methods always
// are, and --allow-writes serves everything. The held-back count is reported.
func TestRiskPrioritizedSourceWriteTemplateGate(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	host := "api.gate.test"
	base := "https://" + host

	save := func(raw, path, resp string) string {
		t.Helper()
		id, err := repo.SaveRecord(ctx, provRR(t, raw, base+path, resp), RecordSourceIngestCLI, DefaultProjectUUID)
		if err != nil {
			t.Fatalf("SaveRecord: %v", err)
		}
		return id
	}
	save("GET /items HTTP/1.1\r\nHost: "+host+"\r\n\r\n", "/items", "")
	save("POST /items HTTP/1.1\r\nHost: "+host+"\r\nContent-Type: application/json\r\n\r\n{\"a\":1}", "/items", "")
	del := save("DELETE /items/1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n", "/items/1", "")
	save("PUT /captured HTTP/1.1\r\nHost: "+host+"\r\n\r\n", "/captured", provOK)

	// Stored exchanges are immutable: the executor saves a baseline it fetched
	// from a stub as its own observation row, carrying the template's
	// provenance. Observations are not assessment inputs, but a later crawl
	// dedup can promote the row to a crawl source; it must still be a template.
	tmpl, err := repo.GetRecordByUUID(ctx, del)
	if err != nil || tmpl.RequestOnlyAtStore == nil {
		t.Fatalf("template: request_only_at_store=%v err=%v", tmpl.RequestOnlyAtStore, err)
	}
	fetched, err := repo.SaveRecordWithLineage(ctx,
		provRR(t, "DELETE /items/1 HTTP/1.1\r\nHost: "+host+"\r\n\r\n", base+"/items/1", provOK),
		RecordKindObservation, DefaultProjectUUID, RecordLineage{TemplateAt: tmpl.RequestOnlyAtStore})
	if err != nil || fetched == del {
		t.Fatalf("fetched version: %s %v", fetched, err)
	}
	rec, err := repo.GetRecordByUUID(ctx, fetched)
	if err != nil || !rec.HasResponse || rec.RequestOnlyAtStore == nil {
		t.Fatalf("fetched template version: has_response=%v request_only_at_store=%v err=%v", rec.HasResponse, rec.RequestOnlyAtStore, err)
	}

	scopes := []HostTarget{{Hostname: host}}
	gated := NewRiskPrioritizedDBInputSource(db, repo, createTestScan(t, repo)).WithHostScopes(scopes)
	got := strings.Join(drainDA(t, gated), ",")
	for _, want := range []string{"GET /items", "PUT /captured"} {
		if !strings.Contains(got, want) {
			t.Errorf("gated source did not serve %s: %s", want, got)
		}
	}
	for _, held := range []string{"POST /items", "DELETE /items/1"} {
		if strings.Contains(got, held) {
			t.Errorf("gated source served the write template %s: %s", held, got)
		}
	}
	if n := gated.SkippedUnsafeMethod(); n != 2 {
		t.Errorf("SkippedUnsafeMethod = %d, want 2", n)
	}

	open := NewRiskPrioritizedDBInputSource(db, repo, createTestScan(t, repo)).WithHostScopes(scopes).WithAllowWrites(true)
	if got := drainDA(t, open); len(got) != 4 {
		t.Errorf("--allow-writes served %v, want the 4 stored inputs (fetched observations are not inputs)", got)
	}
	if n := open.SkippedUnsafeMethod(); n != 0 {
		t.Errorf("SkippedUnsafeMethod with writes allowed = %d, want 0", n)
	}
}

// A row first stored without a response carries request_only_at_store; one
// stored with its response does not.
func TestRequestOnlyAtStoreSetOnFirstWriteOnly(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	stub, err := repo.SaveRecord(ctx, provRR(t, "GET /a HTTP/1.1\r\nHost: p.test\r\n\r\n", "https://p.test/a", ""), RecordSourceIngestCLI, "")
	if err != nil {
		t.Fatal(err)
	}
	full, err := repo.SaveRecord(ctx, provRR(t, "GET /b HTTP/1.1\r\nHost: p.test\r\n\r\n", "https://p.test/b", provOK), RecordSourceIngestCLI, "")
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := repo.GetRecordByUUID(ctx, stub); r.RequestOnlyAtStore == nil {
		t.Error("request-only row has no request_only_at_store")
	}
	if r, _ := repo.GetRecordByUUID(ctx, full); r.RequestOnlyAtStore != nil {
		t.Errorf("row stored with a response has request_only_at_store %v", r.RequestOnlyAtStore)
	}
}

// Write-time dedup keeps principals apart: a body-less GET with another
// Authorization or Cookie is a new row, the same principal with other headers
// is the same row, and replay/fuzz/param-mining dedup on the exact bytes.
func TestDedupIsIdentityAware(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	url := "https://id.test/me"
	get := func(headers string) *httpmsg.HttpRequestResponse {
		return provRR(t, "GET /me HTTP/1.1\r\nHost: id.test\r\n"+headers+"\r\n", url, provOK)
	}
	save := func(rr *httpmsg.HttpRequestResponse, source string) string {
		t.Helper()
		id, err := repo.SaveRecord(ctx, rr, source, "")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	alice := save(get("Cookie: sid=alice\r\n"), "scanner")
	if bob := save(get("Cookie: sid=bob\r\n"), "scanner"); bob == alice {
		t.Error("principal B's GET landed on principal A's row")
	}
	if bearer := save(get("Authorization: Bearer x\r\n"), "scanner"); bearer == alice {
		t.Error("a bearer GET landed on a cookie principal's row")
	}
	anon := save(get(""), "scanner")
	if anon == alice {
		t.Error("an anonymous GET landed on a principal's row")
	}
	// Identity is the exact exchange for every source: the same principal with
	// another User-Agent is a different stored exchange, never an alias.
	if again := save(get("Cookie: sid=alice\r\nUser-Agent: other\r\n"), "scanner"); again == alice {
		t.Error("a header-varied request aliased another stored exchange")
	}
	if same := save(get("Cookie: sid=alice\r\n"), "scanner"); same != alice {
		t.Error("an identical exchange did not dedup onto its row")
	}

	// The batched writer's cache key agrees with the lookup.
	w := NewRecordWriter(repo, RecordWriterConfig{})
	defer w.Close()
	if id, err := w.Write(ctx, get("Cookie: sid=alice\r\n"), "scanner", ""); err != nil || id != alice {
		t.Errorf("writer: alice = %q (%v), want %q", id, err, alice)
	}
	if id, err := w.Write(ctx, get("Cookie: sid=carol\r\n"), "scanner", ""); err != nil || id == alice || id == anon {
		t.Errorf("writer: carol = %q (%v) reused another principal's row", id, err)
	}

	first := save(get("Cookie: sid=alice\r\nX-Probe: 1\r\n"), RecordSourceReplay)
	if second := save(get("Cookie: sid=alice\r\nX-Probe: 2\r\n"), RecordSourceReplay); second == first {
		t.Error("two replays differing in a header collapsed into one row")
	}
}

// A bridge capture keeps its capture time in sent_at; created_at is the
// insert time; the importing scan is stamped on the new row.
func TestUpsertCapturedRecordKeepsCaptureTime(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	captured := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	before := time.Now().Add(-time.Minute)
	id, outcome, err := repo.UpsertCapturedRecord(ctx,
		provRR(t, "GET /x HTTP/1.1\r\nHost: b.test\r\n\r\n", "https://b.test/x", provOK),
		RecordSourceBurp, "", Capture{SentAt: captured, ScanUUID: "scan-import"})
	if err != nil || outcome != "inserted" {
		t.Fatalf("insert: %s %v", outcome, err)
	}
	rec, err := repo.GetRecordByUUID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.SentAt.Equal(captured) {
		t.Errorf("sent_at = %v, want the capture time %v", rec.SentAt, captured)
	}
	if rec.CreatedAt.Before(before) {
		t.Errorf("created_at = %v, want the insert time", rec.CreatedAt)
	}
	if rec.ScanUUID != "scan-import" {
		t.Errorf("scan_uuid = %q, want the importing scan", rec.ScanUUID)
	}

	// Stored exchanges are immutable: a later capture with a new response is
	// its own row carrying its own capture time; the first row is untouched.
	later := captured.Add(time.Hour)
	id2, outcome, err := repo.UpsertCapturedRecord(ctx,
		provRR(t, "GET /x HTTP/1.1\r\nHost: b.test\r\n\r\n", "https://b.test/x", "HTTP/1.1 500 Oops\r\n\r\nno"),
		RecordSourceBurp, "", Capture{SentAt: later})
	if err != nil || outcome != "inserted" || id2 == id {
		t.Fatalf("later capture: %s %s %v", id2, outcome, err)
	}
	if rec2, _ := repo.GetRecordByUUID(ctx, id2); !rec2.SentAt.Equal(later) {
		t.Errorf("later capture sent_at = %v, want %v", rec2.SentAt, later)
	}
	if rec, _ = repo.GetRecordByUUID(ctx, id); !rec.SentAt.Equal(captured) {
		t.Errorf("first capture sent_at changed to %v", rec.SentAt)
	}
}

// An initialized store that is behind is refused with schema_outdated naming
// `vigolium db migrate --db <path>` and left untouched; VIGOLIUM_AUTO_MIGRATE=1
// lets the open migrate it. A fresh file is still initialized.
func TestEnsureSchemaReadyRefusesImplicitMigration(t *testing.T) {
	t.Setenv(config.AutoMigrateEnvVar, "")
	db, path := tempSchemaDB(t)
	if _, err := db.ExecContext(t.Context(), "UPDATE schema_meta SET version = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}

	err := db.EnsureSchemaReady(t.Context())
	var outdated *SchemaOutdatedError
	if !errors.As(err, &outdated) {
		t.Fatalf("EnsureSchemaReady = %v, want *SchemaOutdatedError", err)
	}
	if outdated.Code() != apicontract.CodeSchemaOutdated {
		t.Errorf("code = %s", outdated.Code())
	}
	if want := "vigolium db migrate --db " + path; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not name %q: %v", want, err)
	}
	if got := db.schemaVersion(t.Context()); got != 1 {
		t.Errorf("refused open still migrated: version %d", got)
	}
	if err := db.EnsureSchemaCurrent(t.Context()); err != nil {
		// Columns are all present, so the column-only check passes; nothing
		// to refuse.
		t.Errorf("EnsureSchemaCurrent on a store with every column: %v", err)
	}

	t.Setenv(config.AutoMigrateEnvVar, "1")
	if err := db.EnsureSchemaReady(t.Context()); err != nil {
		t.Fatalf("EnsureSchemaReady with VIGOLIUM_AUTO_MIGRATE=1: %v", err)
	}
	if got := db.schemaVersion(t.Context()); got < currentSchemaVersion {
		t.Errorf("version %d after an allowed migration", got)
	}

	t.Setenv(config.AutoMigrateEnvVar, "")
	fresh, err := NewDB(writableConfig(t.TempDir() + "/fresh.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fresh.Close() }()
	if err := fresh.EnsureSchemaReady(t.Context()); err != nil {
		t.Errorf("a fresh file must still be initialized: %v", err)
	}
}

// A missing column on a writable handle is refused the same way through
// EnsureSchemaCurrent.
func TestEnsureSchemaCurrentRefusesMissingColumn(t *testing.T) {
	t.Setenv(config.AutoMigrateEnvVar, "")
	db, _ := tempSchemaDB(t)
	if _, err := db.ExecContext(t.Context(), "ALTER TABLE http_records DROP COLUMN request_identity_hash"); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureSchemaCurrent(t.Context()); !errors.Is(err, ErrSchemaOutdated) {
		t.Fatalf("EnsureSchemaCurrent = %v, want ErrSchemaOutdated", err)
	}
}
