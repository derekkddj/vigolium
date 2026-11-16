package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

type v8GlobArchiveSnapshot struct {
	bytes        []byte
	columns      []database.ColumnInfo
	version      int
	schemaCookie int
	journalMode  string
}

// This is a real result store with finding_records linkage and every v8 record
// column, not a current-schema database with only its version number changed.
// All fixture writes finish before it becomes the readonly archived source.
func writeV8GlobArchive(t *testing.T) (string, *database.HTTPRecord, v8GlobArchiveSnapshot) {
	t.Helper()
	ctx := context.Background()
	path := writeFindingGlobFixture(t, t.TempDir(), "v8.example")
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = path
	cfg.SQLite.JournalMode = "DELETE"
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	request := []byte("POST / HTTP/1.1\r\nHost: v8.example\r\nContent-Length: 4\r\n\r\n\x00\xff\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\xff\x00\r\n")
	_, err = db.ExecContext(ctx, `UPDATE http_records SET method = 'POST', raw_request = ?, raw_response = ?,
		request_content_length = 4, response_content_length = 4, source = 'burp', surface_score = 31,
		response_location = '/legacy-location' WHERE uuid = 'rec-v8.example'`, request, response)
	require.NoError(t, err)
	stored, err := database.NewRepository(db).GetRecordsByUUIDs(ctx, []string{"rec-v8.example"})
	require.NoError(t, err)
	require.Len(t, stored, 1)
	columns, err := database.ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	// Only the v9 columns are absent: earlier evidence/retention fields remain.
	for _, column := range []string{"capture_request_state", "capture_response_state"} {
		_, err := db.ExecContext(ctx, "ALTER TABLE http_records DROP COLUMN "+column)
		require.NoError(t, err)
	}
	_, err = db.ExecContext(ctx, "UPDATE schema_meta SET version = 9 WHERE id = 1")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	stored[0].CaptureRequestState, stored[0].CaptureResponseState = "", ""
	snapshot := snapshotV8GlobArchive(t, path)
	require.Equal(t, 9, snapshot.version)
	require.Len(t, snapshot.columns, len(columns)-2)
	return path, stored[0], snapshot
}

func snapshotV8GlobArchive(t *testing.T, path string) v8GlobArchiveSnapshot {
	t.Helper()
	ctx := context.Background()
	beforeBytes, err := os.ReadFile(path)
	require.NoError(t, err)
	db, closeDB, err := openGlobSourceFile(ctx, path)
	require.NoError(t, err)
	defer closeDB()
	var snapshot v8GlobArchiveSnapshot
	snapshot.columns, err = database.ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT version FROM schema_meta WHERE id = 1").Scan(&snapshot.version))
	require.NoError(t, db.QueryRowContext(ctx, "PRAGMA schema_version").Scan(&snapshot.schemaCookie))
	require.NoError(t, db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&snapshot.journalMode))
	closeDB()
	snapshot.bytes, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, beforeBytes, snapshot.bytes, "even the first readonly source open/close must leave archive bytes unchanged")
	return snapshot
}

func assertV8GlobArchiveUnchanged(t *testing.T, path string, before v8GlobArchiveSnapshot) {
	t.Helper()
	require.Equal(t, before, snapshotV8GlobArchive(t, path), "archive bytes, schema, version and journal mode must not change")
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_, err := os.Stat(path + suffix)
		require.True(t, os.IsNotExist(err), "readonly archive use left a sidecar: %s (%v)", suffix, err)
	}
}

func assertV8GlobRecord(t *testing.T, want, got *database.HTTPRecord) {
	t.Helper()
	require.Equal(t, want, got, "v8 raw bytes and all existing metadata must survive hydration")
	require.Empty(t, got.CaptureRequestState)
	require.Empty(t, got.CaptureResponseState)
	rr, err := database.RecordToHttpRequestResponse(got)
	require.NoError(t, err)
	require.Nil(t, rr.Evidence(), "archived legacy traffic must not acquire an inferred capture receipt")
}

func TestReadOnlyV8GlobSourceFullRecords(t *testing.T) {
	path, want, before := writeV8GlobArchive(t)
	ctx := context.Background()
	db, closeDB, err := openGlobSourceFile(ctx, path)
	require.NoError(t, err)
	repo := database.NewRepository(db)
	single, err := repo.GetRecordByUUID(ctx, want.UUID)
	require.NoError(t, err)
	assertV8GlobRecord(t, want, single)
	single, err = repo.GetRecordByUUIDOrPrefix(ctx, want.UUID[:database.MinUUIDPrefix])
	require.NoError(t, err)
	assertV8GlobRecord(t, want, single)
	records, err := repo.GetRecordsByUUIDs(ctx, []string{want.UUID})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assertV8GlobRecord(t, want, records[0])
	records, err = database.NewQueryBuilder(db, database.QueryFilters{HostPattern: want.Hostname}).Execute(ctx)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assertV8GlobRecord(t, want, records[0])
	closeDB()
	assertV8GlobArchiveUnchanged(t, path, before)
}

func TestReadOnlyV8FindingGlobLinkedRecords(t *testing.T) {
	path, want, before := writeV8GlobArchive(t)
	t.Cleanup(resetDBCacheForTest)
	merged, findings := mergedFindings(t, filepath.Join(filepath.Dir(path), "scan-*.sqlite"),
		globDBSkipSet{Records: true, RecordFileMap: true})
	require.Len(t, findings, 1)
	require.Equal(t, []string{want.UUID}, findings[0].HTTPRecordUUIDs)
	n, err := merged.NewSelect().Table("http_records").Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, n, "finding merge must not copy the source traffic")
	linked := loadGlobFindingRecords(context.Background(), findings, []string{want.UUID})
	require.Len(t, linked, 1)
	assertV8GlobRecord(t, want, linked[want.UUID])
	// The actual --with-records view path uses scoped source-file hydration,
	// unlike the legacy unscoped loadGlobFindingRecords helper above.
	linked, err = batchLoadFindingRecords(context.Background(), merged, findings, 0)
	require.NoError(t, err)
	require.Len(t, linked, 1)
	assertV8GlobRecord(t, want, linked[want.UUID])
	views := findingViews(context.Background(), merged, findings, agentViewOptions{fullBody: true}, true)
	require.Len(t, views, 1)
	require.NotContains(t, views[0], "records_error")
	require.Len(t, views[0]["records"], 1)
	assertV8GlobArchiveUnchanged(t, path, before)
}

func TestReadOnlyV8FindingSourceRawReaders(t *testing.T) {
	path, want, before := writeV8GlobArchive(t)
	ctx := context.Background()
	// Exercise a single readonly --db source, not the glob scratch database.
	savedSources, savedSkip := globDBSources, globDBSkipped
	globDBSources, globDBSkipped = nil, globDBSkipSet{}
	t.Cleanup(func() { globDBSources, globDBSkipped = savedSources, savedSkip })
	db, closeDB, err := openGlobSourceFile(ctx, path)
	require.NoError(t, err)
	defer closeDB()
	var findings []*database.Finding
	require.NoError(t, db.NewSelect().Model(&findings).Scan(ctx))
	require.Len(t, findings, 1)
	records := loadFindingRecords(ctx, database.NewRepository(db), findings[0])
	require.Len(t, records, 1)
	assertV8GlobRecord(t, want, records[0])
	linked, err := batchLoadFindingRecords(ctx, db, findings, 0)
	require.NoError(t, err)
	require.Len(t, linked, 1)
	assertV8GlobRecord(t, want, linked[want.UUID])
	views := findingViews(ctx, db, findings, agentViewOptions{fullBody: true}, true)
	require.Len(t, views, 1)
	require.NotContains(t, views[0], "records_error")
	require.Len(t, views[0]["records"], 1)
	closeDB()
	assertV8GlobArchiveUnchanged(t, path, before)
}

func TestReadOnlyV8TrafficGlobBurpExport(t *testing.T) {
	path, want, before := writeV8GlobArchive(t)
	// A buffered channel lets the HTTP goroutine publish exact bridge bytes
	// without sharing an unsynchronized slice with the test goroutine.
	payloads := make(chan map[string]string, 1)
	bridge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/burp-bridge/sitemap" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode sitemap payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case payloads <- payload:
		default:
			t.Error("unexpected extra sitemap record")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"added": 1, "url": payload["url"]})
	}))
	defer bridge.Close()
	savedURL, savedJSON := trafficBurpBridgeURL, globalJSON
	trafficBurpBridgeURL, globalJSON = bridge.URL, false
	t.Cleanup(func() { trafficBurpBridgeURL, globalJSON = savedURL, savedJSON })
	records, err := readTrafficSourceFile(context.Background(), path,
		database.QueryFilters{HostPattern: want.Hostname, SearchTerms: []string{"Content-Length: 4"}}, 1)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assertV8GlobRecord(t, want, records[0])
	require.NoError(t, saveGlobToBurp(context.Background(), trafficCmd,
		filepath.Join(filepath.Dir(path), "scan-*.sqlite"),
		database.QueryFilters{HostPattern: want.Hostname, SearchTerms: []string{"Content-Length: 4"}, Limit: 1}))
	select {
	case payload := <-payloads:
		require.Equal(t, want.URL, payload["url"])
		require.Equal(t, "burp_base64", payload["input_mode"])
		request, err := base64.StdEncoding.DecodeString(payload["http_request_base64"])
		require.NoError(t, err)
		response, err := base64.StdEncoding.DecodeString(payload["http_response_base64"])
		require.NoError(t, err)
		require.Equal(t, want.RawRequest, request, "Burp export must not normalize or repair archived request bytes")
		require.Equal(t, want.RawResponse, response, "Burp export must not normalize or repair archived response bytes")
	default:
		t.Fatal("v8 archive record did not reach the Burp bridge")
	}
	assertV8GlobArchiveUnchanged(t, path, before)
}
