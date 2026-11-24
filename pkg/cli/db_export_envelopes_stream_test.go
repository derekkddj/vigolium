package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func isolatedDBJSONLFlags(t *testing.T, table string) {
	t.Helper()
	withDBExportTable(t, "jsonl", table)
	swapGlobal(t, &globalProjectUUID, database.DefaultProjectUUID)
	swapGlobal(t, &globalProjectName, "")
	swapGlobal(t, &exportHost, "")
	swapGlobal(t, &exportMethods, []string(nil))
	swapGlobal(t, &exportStatus, []int(nil))
	swapGlobal(t, &exportPath, "")
	swapGlobal(t, &exportScanUUID, "")
	swapGlobal(t, &exportRecordUUID, "")
	swapGlobal(t, &exportSeverity, "")
	swapGlobal(t, &dbSearch, "")
	swapGlobal(t, &exportLimit, 0)
	swapGlobal(t, &exportOffset, 0)
}

func TestDBJSONLProductionStreamsEvidenceAcrossPagesAndRoundTrips(t *testing.T) {
	isolatedDBJSONLFlags(t, "")
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, suffix := range []string{"one", "two", "three"} {
		seedSelectedEvidenceDBRecord(t, db, suffix)
	}
	repo := database.NewRepository(db)
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("GET / HTTP/1.1\r\n\r\n\x00\xff"), []byte("HTTP/1.1 200 OK\r\n\r\n\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "selected proof")
	entry.OccurrenceID = "exact-occurrence"
	for i := range 70 { // Cross the metadata reader's 64-finding boundary.
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("stream-%02d", i), ModuleID: "test", Severity: "high", Evidence: []evidence.Entry{entry}}
		if i%2 == 0 {
			f.HTTPRecordUUIDs = []string{"rec-one", "rec-two"}
		}
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}
	foreign := &database.Finding{ProjectUUID: "foreign", FindingHash: "foreign-stream", ModuleID: "test", Evidence: []evidence.Entry{entry}}
	require.NoError(t, repo.SaveFindingDirect(ctx, foreign))
	var out bytes.Buffer
	n, counts, err := writeDBExportWithCounts(ctx, db, nil, nil, &out)
	require.NoError(t, err)
	require.Equal(t, map[string]int{"records": 73, "http_record": 3, "finding": 70}, counts)
	require.Equal(t, 73, n, "receipt counts emitted envelopes, not the traffic used to discover findings")
	require.Equal(t, map[string]int{"http_record": 3, "finding": 70}, countEnvelopeTypes(t, out.Bytes()))
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	seen := map[int64]bool{}
	for i := range n {
		var env struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		require.NoError(t, dec.Decode(&env))
		if i < 3 {
			require.Equal(t, "http_record", env.Type, "traffic precedes findings")
			var r database.HTTPRecord
			require.NoError(t, json.Unmarshal(env.Data, &r))
			require.Equal(t, database.DefaultProjectUUID, r.ProjectUUID)
			require.Contains(t, string(r.RawResponse), "RAWBODYMARKER")
			continue
		}
		require.Equal(t, "finding", env.Type)
		var f database.Finding
		require.NoError(t, json.Unmarshal(env.Data, &f))
		require.False(t, seen[f.ID])
		seen[f.ID] = true
		require.Equal(t, database.DefaultProjectUUID, f.ProjectUUID)
		require.Len(t, f.Evidence, 1)
		require.Equal(t, entry.OccurrenceID, f.Evidence[0].OccurrenceID)
		require.Equal(t, x.Request, f.Evidence[0].Exchange.Request)
		require.Equal(t, x.Response, f.Evidence[0].Exchange.Response)
	}
	dst := newDBAtPath(t, filepath.Join(t.TempDir(), "roundtrip.sqlite"))
	result, err := dbimport.ImportJSONL(ctx, database.NewRepository(dst), bytes.NewReader(out.Bytes()), database.DefaultProjectUUID, dbimport.Options{})
	require.NoError(t, err)
	require.Equal(t, 3, result.RecordsImported)
	require.Equal(t, 70, result.FindingsSaved)
	var imported bytes.Buffer
	globalTable = "findings"
	n, err = writeDBExportCounted(ctx, dst, nil, nil, &imported)
	require.NoError(t, err)
	require.Equal(t, 70, n)
	require.Contains(t, imported.String(), "exact-occurrence")
	require.NotContains(t, imported.String(), "foreign-stream")
}

func TestDBJSONLProductionPaginationIsPerType(t *testing.T) {
	isolatedDBJSONLFlags(t, "")
	db := newDBAtPath(t, ":memory:")
	ctx := context.Background()
	for i := range 4 {
		seedSelectedEvidenceDBRecord(t, db, fmt.Sprint(i))
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("page-%d", i), ModuleID: "test", Severity: "high"}
		require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, f))
	}
	exportLimit, exportOffset = 2, 1
	var out bytes.Buffer
	n, err := writeDBExportCounted(ctx, db, nil, nil, &out)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, map[string]int{"http_record": 2, "finding": 2}, countEnvelopeTypes(t, out.Bytes()))
	globalTable = "http_records"
	out.Reset()
	n, err = writeDBExportCounted(ctx, db, nil, nil, &out)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, map[string]int{"http_record": 2}, countEnvelopeTypes(t, out.Bytes()))
}

func TestDBJSONLProductionPropagatesWriterAndCancellationErrors(t *testing.T) {
	isolatedDBJSONLFlags(t, "findings")
	db := newDBAtPath(t, ":memory:")
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "writer-error", ModuleID: "test"}
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(context.Background(), f))
	_, err := writeDBExportCounted(context.Background(), db, nil, nil, alwaysFailedDBJSONLWriter{})
	require.ErrorIs(t, err, io.ErrClosedPipe)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	_, err = writeDBExportCounted(ctx, db, nil, nil, &out)
	require.True(t, errors.Is(err, context.Canceled), "got %v", err)
	require.Empty(t, out.Bytes())
}

func TestDBJSONLProductionUUIDBeforePaginationAndSharedFilters(t *testing.T) {
	isolatedDBJSONLFlags(t, "findings")
	db := newDBAtPath(t, ":memory:")
	ctx := context.Background()
	seedSelectedEvidenceDBRecord(t, db, "selected")
	for i := range 70 {
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("uuid-filter-%02d", i), ModuleID: "test", Severity: "high"}
		if i < 4 {
			f.HTTPRecordUUIDs = []string{"rec-selected"}
		}
		require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, f))
	}
	exportRecordUUID, exportOffset, exportLimit = "rec-selected", 1, 2
	var out bytes.Buffer
	n, counts, err := writeDBExportWithCounts(ctx, db, nil, nil, &out)
	require.NoError(t, err)
	require.Equal(t, 2, n, "UUID filtering happens before finding pagination, including across metadata pages")
	require.Equal(t, map[string]int{"records": 2, "http_record": 0, "finding": 2}, counts)
	require.Equal(t, map[string]int{"finding": 2}, countEnvelopeTypes(t, out.Bytes()))
	out.Reset()
	globalTable, exportOffset = "", 1000
	n, counts, err = writeDBExportWithCounts(ctx, db, nil, nil, &out)
	require.NoError(t, err)
	require.Equal(t, map[string]int{"records": 1, "http_record": 1, "finding": 0}, counts)
	require.Equal(t, 1, n, "an exact record UUID is not lost to the traffic pagination offset")
	out.Reset()
	globalTable, exportOffset = "findings", 1
	exportSeverity = "critical"
	n, err = writeDBExportCounted(ctx, db, nil, nil, &out)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Empty(t, out.Bytes())
}

func TestDBJSONLProductionShortWritesFailForEachType(t *testing.T) {
	for _, table := range []string{"http_records", "findings"} {
		t.Run(table, func(t *testing.T) {
			isolatedDBJSONLFlags(t, table)
			db := newDBAtPath(t, ":memory:")
			seedSelectedEvidenceDBRecord(t, db, "short")
			f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "short-finding", ModuleID: "test"}
			require.NoError(t, database.NewRepository(db).SaveFindingDirect(context.Background(), f))
			_, err := writeDBExportCounted(context.Background(), db, nil, nil, shortDBJSONLWriter{})
			require.ErrorIs(t, err, io.ErrShortWrite)
		})
	}
}

type shortDBJSONLWriter struct{}

func (shortDBJSONLWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type alwaysFailedDBJSONLWriter struct{}

func (alwaysFailedDBJSONLWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
