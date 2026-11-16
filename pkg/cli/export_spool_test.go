package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

func resetGeneralExportSpoolFlags(t *testing.T) {
	t.Helper()
	only, exclude := topExportOnly, topExportExclude
	search, severity, limit := topExportSearch, topExportSeverity, topExportLimit
	omit, noDedup, scans := topExportOmitResponse, topExportNoURLDedup, topExportScanUUIDs
	t.Cleanup(func() {
		topExportOnly, topExportExclude = only, exclude
		topExportSearch, topExportSeverity, topExportLimit = search, severity, limit
		topExportOmitResponse, topExportNoURLDedup, topExportScanUUIDs = omit, noDedup, scans
	})
	topExportOnly, topExportExclude, topExportScanUUIDs = nil, nil, nil
	topExportSearch, topExportSeverity, topExportLimit = "", "", 0
	topExportOmitResponse, topExportNoURLDedup = false, false
}

func generalBundleMembers(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	gz, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gz.Close()
	members := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if h.Typeflag != tar.TypeReg {
			continue
		}
		members[h.Name], err = io.ReadAll(tr)
		require.NoError(t, err)
	}
	return members
}

func TestSelectedEvidenceGeneralBundleAndMultiJSONLReuseDiskSnapshot(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	topExportOnly = []string{"http", "findings"}
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seedRecordWithBodies(t, db, "one")
	seedRecordWithBodies(t, db, "two")
	_, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).Set("project_uuid = ?", database.DefaultProjectUUID).Where("uuid IN (?, ?)", "rec-one", "rec-two").Exec(ctx)
	require.NoError(t, err)
	repo := database.NewRepository(db)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 70 { // crosses the bounded metadata page boundary
		x := evidence.NewExchange("http://destination.example:8080", "https://app.test/proof", []byte(fmt.Sprintf("request-%d\x00\xff", i)), []byte(fmt.Sprintf("RAW-SELECTED-MARKER-%d\xff\x00", i)), evidence.ProvenanceCaptured)
		entry := evidence.Select(x, evidence.RoleAttack, true, "proof")
		entry.OccurrenceID = fmt.Sprintf("occurrence-%d", i)
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("general-bundle-%d", i), ModuleID: "test", Severity: "high", EvidenceStatus: "unclassified", FoundAt: at, Evidence: []evidence.Entry{entry, {ExchangeID: "missing", Role: evidence.RoleControl}}}
		if i == 0 {
			f.HTTPRecordUUIDs = []string{"rec-one", "rec-two"}
		}
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}
	foreign := &database.Finding{ProjectUUID: "foreign", FindingHash: "foreign-general-bundle", ModuleID: "test", Severity: "high"}
	require.NoError(t, repo.SaveFindingDirect(ctx, foreign))
	r := &exportRun{db: db, multi: true, projectUUID: database.DefaultProjectUUID}
	t.Cleanup(r.closeSpool)
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "report.jsonl")
	_, err = r.exportJSONL(ctx, jsonl)
	require.NoError(t, err)
	require.NotNil(t, r.spool)
	require.Equal(t, 70, r.counts.byType["finding"])
	require.Equal(t, 2, r.counts.byType["http_record"])
	require.Equal(t, 72, r.counts.total)
	original := mustReadFile(t, jsonl)
	seen := map[int64]bool{}
	dec := json.NewDecoder(bytes.NewReader(original))
	for {
		var env struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		err := dec.Decode(&env)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if env.Type != "finding" {
			continue
		}
		var f database.Finding
		require.NoError(t, json.Unmarshal(env.Data, &f))
		require.False(t, seen[f.ID], "linked records must not duplicate a finding")
		seen[f.ID] = true
		require.Equal(t, database.DefaultProjectUUID, f.ProjectUUID)
		require.Equal(t, "unclassified", f.EvidenceStatus)
		require.Len(t, f.Evidence, 2)
		require.NotNil(t, f.Evidence[0].Exchange)
		require.Contains(t, string(f.Evidence[0].Exchange.Response), "RAW-SELECTED-MARKER-")
		require.Nil(t, f.Evidence[1].Exchange)
	}
	require.Len(t, seen, 70)
	// The bundle must not re-query or collect the corpus for the next format.
	// Freeze the report metadata too; the database is deliberately unavailable.
	r.metaSet = true
	require.NoError(t, db.Close())
	oldRenderer := renderExportBundleHTML
	t.Cleanup(func() { renderExportBundleHTML = oldRenderer })
	renderExportBundleHTML = func(produce output.ReportItemProducer, path string, meta output.HTMLReportMeta) error {
		line := 0
		err := produce(func(item any) error {
			line++
			data, err := json.Marshal(item)
			if err != nil {
				return err
			}
			require.NotContains(t, string(data), "RAW-SELECTED-MARKER")
			require.NotContains(t, string(data), "RAWBODYMARKER")
			require.NotContains(t, string(data), base64.StdEncoding.EncodeToString([]byte("<html>RAWBODYMARKER-one</html>")))
			require.NotContains(t, string(data), base64.StdEncoding.EncodeToString([]byte("<html>RAWBODYMARKER-two</html>")))
			require.NotContains(t, string(data), `"exchange":`)
			var env struct {
				Type string                     `json:"type"`
				Data map[string]json.RawMessage `json:"data"`
			}
			require.NoError(t, json.Unmarshal(data, &env))
			key := "raw_traffic_source"
			if env.Type == "finding" {
				key = "evidence_source"
			}
			var ref bundleDataReference
			require.NoError(t, json.Unmarshal(env.Data[key], &ref))
			require.Equal(t, "export.jsonl", ref.Path)
			require.Equal(t, line, ref.Line)
			return nil
		})
		if err != nil {
			return err
		}
		require.Equal(t, 72, line)
		return oldRenderer(produce, path, meta)
	}
	bundle := filepath.Join(dir, "report.tar.gz")
	_, err = r.exportBundle(ctx, bundle)
	require.NoError(t, err)
	members := generalBundleMembers(t, bundle)
	require.Equal(t, original, members["report/export.jsonl"], "formats share the same disk snapshot, not separate queries")
	require.Contains(t, string(members["report/report.html"]), "evidence_source")
	require.NotContains(t, string(members["report/report.html"]), "RAW-SELECTED-MARKER")
	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(members["report/manifest.json"], &manifest))
	require.Equal(t, 72, manifest.TotalItems)
	require.Equal(t, 70, manifest.ItemCounts["finding"])
	require.Equal(t, database.DefaultProjectUUID, manifest.ProjectUUID)
	spoolDir := r.spool.dir
	r.closeSpool()
	_, err = os.Stat(spoolDir)
	require.True(t, os.IsNotExist(err), "the run must remove its disk spools")
}

func TestSelectedEvidenceGeneralJSONLScopeExcludeAndBundleFilters(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	seedRecordWithBodies(t, db, "one")
	repo := database.NewRepository(db)
	for i, severity := range []string{"high", "high", "low"} {
		x := evidence.NewExchange("http://app.test:80", "http://app.test/needle", []byte("request\xff\x00"), []byte("response\x00\xff"), evidence.ProvenanceCaptured)
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("general-filter-%d", i), ModuleID: "needle-module", Severity: severity, URL: "http://app.test/needle", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "observation")}}
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}
	candidate := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "general-filter-candidate", ModuleID: "needle-module", Severity: "high", URL: "http://app.test/needle", RecordKind: database.RecordKindCandidate}
	require.NoError(t, repo.SaveFindingDirect(ctx, candidate))
	topExportOnly, topExportExclude = []string{"findings"}, []string{"http_record"}
	topExportSearch, topExportSeverity, topExportLimit = "needle", "high", 1
	topExportOmitResponse = true // preserves the existing finding-receipt contract
	r := &exportRun{db: db, multi: true, projectUUID: database.DefaultProjectUUID}
	t.Cleanup(r.closeSpool)
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	_, err := r.exportJSONL(ctx, path)
	require.NoError(t, err)
	require.Equal(t, 1, r.counts.total)
	require.Equal(t, map[string]int{"finding": 1}, r.counts.byType)
	var env struct {
		Type string           `json:"type"`
		Data database.Finding `json:"data"`
	}
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(mustReadFile(t, path)), &env))
	require.Equal(t, "finding", env.Type)
	require.Equal(t, "high", env.Data.Severity)
	require.NotEqual(t, database.RecordKindCandidate, env.Data.RecordKind)
	require.Equal(t, []byte("response\x00\xff"), env.Data.Evidence[0].Exchange.Response)
	bundle := filepath.Join(t.TempDir(), "filtered.tar.gz")
	_, err = r.exportBundle(ctx, bundle)
	require.NoError(t, err)
	members := generalBundleMembers(t, bundle)
	var manifest bundleManifest
	require.NoError(t, json.Unmarshal(members["filtered/manifest.json"], &manifest))
	require.Equal(t, 1, manifest.TotalItems)
	require.Equal(t, "needle", manifest.Filters.Search)
	require.Equal(t, "high", manifest.Filters.Severity)
	require.Equal(t, 1, manifest.Filters.Limit)
	require.True(t, manifest.Filters.OmitResponse)
	require.Equal(t, []string{"findings"}, manifest.Filters.Only)
	// Single-format JSONL must honor topExportScope rather than scanExportScope.
	r.closeSpool()
	r.multi = false
	// --only and --exclude naming the same type is a usage error, so the
	// exclusion is exercised on its own.
	topExportOnly, topExportExclude = nil, []string{"finding"}
	_, err = r.exportJSONL(ctx, path)
	require.NoError(t, err)
	require.Empty(t, mustReadFile(t, path))
	require.Zero(t, r.counts.total)
	require.Nil(t, r.spool, "single JSONL must stream without even a spool")
}

func TestSelectedEvidenceGeneralBundleProjectionStripsDecoratedTrafficAndOAST(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\n\r\nRAWBODYMARKER\x00\xff")
	record := &database.HTTPRecord{UUID: "rec", RawRequest: raw, RawResponse: raw}
	ref := bundleDataReference{Path: "export.jsonl", Line: 3}
	for _, item := range []any{record, database.RecordWithHostFacts{Record: record, Facts: database.HostFacts{A: []string{"192.0.2.1"}}}, &database.OASTInteraction{RawRequest: string(raw), RawResponse: string(raw)}} {
		preview, err := bundleReportProjection(item, ref)
		require.NoError(t, err)
		data, err := json.Marshal(preview)
		require.NoError(t, err)
		require.NotContains(t, string(data), "RAWBODYMARKER")
		require.NotContains(t, string(data), base64.StdEncoding.EncodeToString(raw))
		require.Contains(t, string(data), `"raw_traffic_source":{"path":"export.jsonl","line":3}`)
		if _, ok := item.(database.RecordWithHostFacts); ok {
			require.Contains(t, string(data), "192.0.2.1")
		}
	}
	require.Equal(t, raw, record.RawResponse, "projection must not mutate authoritative rows")
}

func TestSelectedEvidenceGeneralBundleEmptyStillRequiresReportAndCleansOnFailure(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	topExportOnly = []string{"findings"}
	db := newDBAtPath(t, ":memory:")
	ctx := context.Background()
	r := &exportRun{db: db}
	path := filepath.Join(t.TempDir(), "empty.tar.gz")
	_, err := r.exportBundle(ctx, path)
	require.NoError(t, err)
	require.Nil(t, r.spool, "single-format bundle releases its spool")
	members := generalBundleMembers(t, path)
	require.Contains(t, members, "empty/report.html")
	require.Empty(t, members["empty/export.jsonl"])
	previous := mustReadFile(t, path)
	oldRenderer := renderExportBundleHTML
	t.Cleanup(func() { renderExportBundleHTML = oldRenderer })
	renderExportBundleHTML = func(output.ReportItemProducer, string, output.HTMLReportMeta) error {
		return errors.New("render failure")
	}
	_, err = r.exportBundle(ctx, path)
	require.ErrorContains(t, err, "report.html")
	require.Equal(t, previous, mustReadFile(t, path))
	require.Nil(t, r.spool, "render failure cleans the single-format spool")
}
