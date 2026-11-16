package database

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// readonlyV8RecordFixture keeps every v8 column, but physically removes the two
// v9 capture-state columns. Merely lowering schema_meta would miss the broken
// full-model SELECT: readonly archive opens deliberately do not run migrations.
func readonlyV8RecordFixture(t *testing.T) (string, *HTTPRecord, []ColumnInfo) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v8-archive.sqlite")
	cfg := sqliteSettings(path, false)
	cfg.SQLite.JournalMode = "DELETE"
	db, err := NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(ctx))
	timestamp := time.Date(2025, 4, 3, 2, 1, 0, 0, time.UTC)
	record := &HTTPRecord{
		UUID: "v8-record", ProjectUUID: DefaultProjectUUID, ScanUUID: "v8-scan",
		Scheme: "https", Hostname: "archive.example", Port: 8443, IP: "192.0.2.1",
		Method: "POST", Path: "/legacy", URL: "https://archive.example:8443/legacy", HTTPVersion: "HTTP/1.1",
		RequestContentType: "application/octet-stream", RequestContentLength: 4,
		RawRequest:  []byte("POST /legacy HTTP/1.1\r\nHost: archive.example:8443\r\nContent-Length: 4\r\n\r\n\x00\xff\r\n"),
		RequestHash: "v8-request-hash", RequestAuthorization: "Bearer legacy",
		StatusCode: 200, StatusPhrase: "OK", ResponseHTTPVersion: "HTTP/1.1",
		ResponseContentType: "application/octet-stream", ResponseContentLength: 4,
		RawResponse:  []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\xff\x00\r\n"),
		ResponseHash: "v8-response-hash", ResponseNormHash: "v8-normalized-hash",
		ResponseTimeMs: 23, ResponseWords: 2, HasResponse: true, ResponseTitle: "legacy title",
		ResponseLocation: "/old-location", SentAt: timestamp, ReceivedAt: timestamp.Add(time.Second), CreatedAt: timestamp,
		Source: "burp", Technology: []string{"legacy-tech"}, ContentHash: "v8-content-hash", IsAuthenticated: true,
		ParentUUID: "v8-parent", RootUUID: "v8-root", Target: "https://archive.example:8443", ChainTruncated: true,
		Parameters: []EmbeddedParam{{Name: "legacy", Value: "value", Type: "body"}},
		Remarks:    []string{"legacy remark"}, RiskScore: 17, SurfaceScore: 29,
		BodyCompaction: &BodyCompaction{Version: 1, CompactedAt: timestamp, KeepHead: 4,
			Response: &CompactedBody{OriginalLength: 12, KeptLength: 4, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}},
		CaptureRequestState: evidence.StateComplete, CaptureResponseState: evidence.StateComplete,
	}
	_, err = db.NewInsert().Model(record).Exec(ctx)
	require.NoError(t, err)
	before, err := NewRepository(db).GetRecordByUUID(ctx, record.UUID)
	require.NoError(t, err)
	require.NoError(t, NewRepository(db).SaveFindingDirect(ctx, &Finding{
		ProjectUUID: record.ProjectUUID, HTTPRecordUUIDs: []string{record.UUID},
		ModuleID: "v8-module", ModuleName: "V8 module", Severity: "high", Confidence: "firm", FindingHash: "v8-finding",
	}))
	currentColumns, err := ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	for _, column := range recordCaptureStateColumns {
		_, err := db.ExecContext(ctx, "ALTER TABLE http_records DROP COLUMN "+column)
		require.NoError(t, err)
	}
	forceSchemaVersion(t, db, 8)
	columns, err := ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	require.Len(t, columns, len(currentColumns)-len(recordCaptureStateColumns))
	before.CaptureRequestState, before.CaptureResponseState = "", ""
	require.NoError(t, db.Close())
	return path, before, columns
}

func TestReadOnlyV8FullRecordQueries(t *testing.T) {
	path, want, columns := readonlyV8RecordFixture(t)
	ctx := context.Background()
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	entries := dirEntries(t, filepath.Dir(path))
	db, err := NewDB(sqliteSettings(path, true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.True(t, db.readOnly)
	require.Equal(t, 8, db.schemaVersion(ctx))
	var schemaCookie int
	require.NoError(t, db.QueryRowContext(ctx, "PRAGMA schema_version").Scan(&schemaCookie))
	assertRecords := func(records []*HTTPRecord) {
		t.Helper()
		require.Equal(t, []*HTTPRecord{want}, records, "full reads must preserve all historical fields and raw bytes")
		rr, err := RecordToHttpRequestResponse(records[0])
		require.NoError(t, err)
		require.Nil(t, rr.Evidence(), "missing states must retain legacy behavior, not infer a captured receipt")
	}
	repo := NewRepository(db)
	require.Equal(t, "r", db.Dialect().Tables().Get(reflect.TypeFor[HTTPRecord]()).Alias, "readonly wildcard must use the model's Bun alias")
	single, err := repo.GetRecordByUUID(ctx, want.UUID)
	require.NoError(t, err)
	assertRecords([]*HTTPRecord{single})
	for _, ref := range []string{want.UUID, want.UUID[:MinUUIDPrefix]} {
		single, err = repo.GetRecordByUUIDOrPrefix(ctx, ref)
		require.NoError(t, err)
		assertRecords([]*HTTPRecord{single})
	}
	single, err = repo.GetRecordByUUID(ctx, "missing")
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.Nil(t, single)
	single, err = repo.GetRecordByUUIDOrPrefix(ctx, "missing-prefix")
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.Nil(t, single)
	// Raw finding/view readers use the project-scoped full-row helper too.
	for _, project := range []string{want.ProjectUUID, ""} {
		scoped, err := repo.GetFindingRecordsScoped(ctx, project, []string{want.UUID, "missing"})
		require.NoError(t, err)
		assertRecords(scoped)
	}
	foreign, err := repo.GetFindingRecordsScoped(ctx, "foreign-project", []string{want.UUID})
	require.NoError(t, err)
	require.Empty(t, foreign, "readonly compatibility must not relax finding ownership")
	records, err := repo.GetRecordsByUUIDs(ctx, []string{want.UUID, "missing"})
	require.NoError(t, err)
	assertRecords(records)
	// The last page also uses the full stored-row projection.
	ids := make([]string, SQLChunkSize+1)
	for i := range ids {
		ids[i] = "missing"
	}
	ids[len(ids)-1] = want.UUID
	records, err = repo.GetRecordsByUUIDs(ctx, ids)
	require.NoError(t, err)
	assertRecords(records)
	for _, filters := range []QueryFilters{
		{ProjectUUID: want.ProjectUUID, HostPattern: want.Hostname, SearchTerms: []string{"legacy"}},
		{ProjectUUID: want.ProjectUUID, Severity: []string{"high"}}, // r.* must not hydrate joined finding columns.
	} {
		qb := NewQueryBuilder(db, filters)
		records, err = qb.Execute(ctx)
		require.NoError(t, err)
		assertRecords(records)
		var count int64
		records, count, err = qb.ExecuteWithCount(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, count)
		assertRecords(records)
		var direct []*HTTPRecord
		require.NoError(t, qb.BuildRecordsQuery().Scan(ctx, &direct))
		assertRecords(direct)
		rows, err := qb.BuildRecordsQuery().Rows(ctx)
		require.NoError(t, err)
		require.True(t, rows.Next())
		var streamed HTTPRecord
		require.NoError(t, db.ScanRow(ctx, rows, &streamed))
		require.Equal(t, want, &streamed)
		require.False(t, rows.Next())
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
	}
	// UUID-only consumers must clear the full-row wildcard before projecting.
	var selected []string
	require.NoError(t, NewQueryBuilder(db, QueryFilters{}).BuildRecordsQuery().
		ExcludeColumn("*").Column("uuid").Scan(ctx, &selected))
	require.Equal(t, []string{want.UUID}, selected)
	records, err = repo.getRecordsByUUIDs(ctx, []string{want.UUID}, "uuid", "raw_request")
	require.NoError(t, err)
	require.Equal(t, []*HTTPRecord{{UUID: want.UUID, RawRequest: want.RawRequest}}, records)

	afterColumns, err := ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	require.Equal(t, columns, afterColumns)
	require.Equal(t, 8, db.schemaVersion(ctx))
	var afterCookie int
	require.NoError(t, db.QueryRowContext(ctx, "PRAGMA schema_version").Scan(&afterCookie))
	require.Equal(t, schemaCookie, afterCookie, "no archive DDL may run")
	require.NoError(t, db.Close())
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after, "readonly queries must leave the archive byte-identical")
	require.Equal(t, entries, dirEntries(t, filepath.Dir(path)))
}

func TestReadOnlyFullRecordWildcardRetainsV9CaptureStates(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v9-archive.sqlite")
	cfg := sqliteSettings(path, false)
	cfg.SQLite.JournalMode = "DELETE"
	db, err := NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(ctx))
	record := &HTTPRecord{
		UUID: "v9-record", ProjectUUID: DefaultProjectUUID, Scheme: "https", Hostname: "archive.example", Port: 443,
		Method: "GET", Path: "/", URL: "https://archive.example/", HTTPVersion: "HTTP/1.1", RequestHash: "v9-hash",
		RawRequest:          []byte("GET / HTTP/1.1\r\nHost: archive.example\r\n\r\n"),
		CaptureRequestState: evidence.StateComplete, CaptureResponseState: evidence.StateUnknown,
	}
	_, err = db.NewInsert().Model(record).Exec(ctx)
	require.NoError(t, err)
	want, err := NewRepository(db).GetRecordByUUID(ctx, record.UUID)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	archive, err := NewDB(sqliteSettings(path, true))
	require.NoError(t, err)
	defer archive.Close()
	single, err := NewRepository(archive).GetRecordByUUID(ctx, record.UUID)
	require.NoError(t, err)
	require.Equal(t, want, single, "readonly singular reads must retain present v9 capture states")
	byID, err := NewRepository(archive).GetRecordsByUUIDs(ctx, []string{record.UUID})
	require.NoError(t, err)
	require.Equal(t, []*HTTPRecord{want}, byID)
	queried, err := NewQueryBuilder(archive, QueryFilters{}).Execute(ctx)
	require.NoError(t, err)
	require.Equal(t, byID, queried, "wildcard full reads must retain new fields when present")
}
