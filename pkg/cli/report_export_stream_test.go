package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestSelectedEvidenceGeneralDocumentExportsUseDiskSnapshot(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	topExportOnly = []string{"findings"}
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	x := evidence.NewExchange("http://destination.example:8080", "https://display.example/proof", []byte("POST /proof HTTP/1.1\r\nHost: virtual.example\r\nContent-Length: 999\r\n\r\n\x00\xffRECEIPT"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 777\r\n\r\n\xff\x00response"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "proof")
	entry.OccurrenceID = "occurrence"
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "document-receipt-only", ModuleID: "test", ModuleName: "Test", Severity: "high", EvidenceStatus: "unclassified", Evidence: []evidence.Entry{entry, {ExchangeID: "missing", Role: evidence.RoleUnknown}}}
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, f))
	r := &exportRun{db: db, multi: true, projectUUID: f.ProjectUUID, metaSet: true}
	defer r.closeSpool()
	path := filepath.Join(t.TempDir(), "report.sarif")
	_, err := r.exportReport(ctx, "sarif", path)
	require.NoError(t, err)
	require.Equal(t, 1, r.counts.total)
	var log struct {
		Runs []struct {
			Results []struct {
				Properties struct {
					Evidence []evidence.Entry `json:"evidence"`
					Status   string           `json:"evidenceStatus"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &log))
	props := log.Runs[0].Results[0].Properties
	require.Equal(t, "unclassified", props.Status)
	require.Equal(t, entry.Exchange, props.Evidence[0].Exchange)
	require.Equal(t, entry.OccurrenceID, props.Evidence[0].OccurrenceID)
	require.Nil(t, props.Evidence[1].Exchange)
	// Remaining document formats must reuse the snapshot, without querying or
	// collecting the unavailable database's receipt corpus.
	require.NoError(t, db.Close())
	for _, format := range []string{"markdown", "report", "html", "csv", "junit", "github"} {
		path := filepath.Join(t.TempDir(), "report."+format)
		_, err := r.exportReport(ctx, format, path)
		require.NoError(t, err)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotEmpty(t, data)
	}
}

func TestSelectedEvidenceDBRecordExportsStreamFilteredSnapshot(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := range 70 {
		seedRecordWithBodies(t, db, fmt.Sprintf("stream-%02d", i))
	}
	rawRequest := []byte("POST https://absolute.example/proof HTTP/1.1\r\nHost: virtual.example\r\nContent-Length: 9999\r\n\r\n\x00\xffreceipt")
	rawResponse := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n\x00\xffx\r\n0\r\n\r\n")
	_, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).
		Set("project_uuid = ?", database.DefaultProjectUUID).
		Set("raw_request = ?", rawRequest).Set("raw_response = ?", rawResponse).
		Where("uuid LIKE ?", "rec-stream-%").Exec(ctx)
	require.NoError(t, err)
	seedRecordWithBodies(t, db, "foreign")
	filters := database.QueryFilters{ProjectUUID: database.DefaultProjectUUID, Limit: 7, Offset: 3}
	legacy, err := database.NewQueryBuilder(db, filters).Execute(ctx)
	require.NoError(t, err)
	require.Len(t, legacy, 7)
	swapGlobal(t, &exportRecordUUID, "")
	swapGlobal(t, &exportRequestOnly, false)
	for _, format := range []string{"json", "raw", "csv", "markdown", "markdown-table"} {
		t.Run(format, func(t *testing.T) {
			swapGlobal(t, &exportFormat, format)
			var got, want bytes.Buffer
			n, err := streamRecordDBExport(ctx, db, filters, &got)
			require.NoError(t, err)
			require.Equal(t, 7, n)
			switch format {
			case "json":
				err = exportJSON(legacy, &want)
			case "raw":
				err = exportRaw(legacy, &want)
			case "csv":
				err = exportCSV(legacy, &want)
			case "markdown":
				err = exportMarkdown(legacy, &want)
			case "markdown-table":
				err = exportMarkdownTable(legacy, &want)
			}
			require.NoError(t, err)
			if format == "json" {
				var a, b map[string]any
				require.NoError(t, json.Unmarshal(got.Bytes(), &a))
				require.NoError(t, json.Unmarshal(want.Bytes(), &b))
				delete(a, "export_date")
				delete(b, "export_date")
				require.Equal(t, b, a)
				var doc struct {
					Records []*database.HTTPRecord `json:"records"`
				}
				require.NoError(t, json.Unmarshal(got.Bytes(), &doc))
				require.Len(t, doc.Records, 7)
				for _, record := range doc.Records {
					require.Equal(t, rawRequest, record.RawRequest)
					require.Equal(t, rawResponse, record.RawResponse)
				}
			} else {
				require.Equal(t, want.String(), got.String())
				if format == "raw" {
					require.True(t, bytes.Contains(got.Bytes(), rawRequest))
					require.True(t, bytes.Contains(got.Bytes(), rawResponse))
				}
			}
			_, err = streamRecordDBExport(ctx, db, filters, failingReportWriter{})
			require.Error(t, err, "single-record legacy text helpers must not hide writer failures")
		})
	}
}

func TestSelectedEvidenceReportMetadataScopesToProjectAndScan(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	ctx := context.Background()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, id := range []string{"current", "historical"} {
		_, err := db.NewInsert().Model(&database.Scan{UUID: id, ProjectUUID: database.DefaultProjectUUID, Status: "completed", Target: "https://" + id + ".test/", StartedAt: at, FinishedAt: at.Add(time.Second)}).Exec(ctx)
		require.NoError(t, err)
	}
	_, err := db.NewInsert().Model(&database.AgenticScan{UUID: "foreign-agentic", ProjectUUID: "foreign-project", Mode: "query", AgentName: "test", Status: "completed", TargetURL: "https://foreign.test/", DurationMs: 9000}).Exec(ctx)
	require.NoError(t, err)
	target, duration := computeReportMeta(ctx, db, database.DefaultProjectUUID, "current")
	require.Equal(t, "https://current.test/", target)
	require.Equal(t, "1s", duration)
	target, duration = computeReportMeta(ctx, db, database.DefaultProjectUUID, "")
	require.Equal(t, "multiple", target)
	require.Equal(t, "N/A", duration)
	target, duration = computeReportMeta(ctx, db, "missing-project", "")
	require.Empty(t, target)
	require.Empty(t, duration)
}

func TestSelectedEvidenceImportReportUsesCapturedProjectScope(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	t.Setenv("VIGOLIUM_DB_PATH", filepath.Join(t.TempDir(), "must-not-open.sqlite"))
	swapGlobal(t, &globalJSON, true)
	for _, project := range []string{database.DefaultProjectUUID, "foreign-project"} {
		f := &database.Finding{ProjectUUID: project, FindingHash: "import-scope-" + project, ModuleID: "test", Severity: "high", EvidenceStatus: "unclassified", Evidence: []evidence.Entry{{ExchangeID: "missing-" + project, Role: evidence.RoleUnknown}}}
		require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, f))
	}
	path := filepath.Join(t.TempDir(), "import.sarif")
	_, err := emitImportReport(ctx, db, nil, "sarif", path, importReportOpts{projectUUID: database.DefaultProjectUUID})
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	require.Len(t, doc.Runs, 1)
	require.Len(t, doc.Runs[0].Results, 1)
	require.Contains(t, string(data), "missing-"+database.DefaultProjectUUID)
	require.NotContains(t, string(data), "foreign-project")
	_, err = emitImportReport(ctx, db, &database.AgenticScan{ProjectUUID: "foreign-project"}, "sarif", filepath.Join(t.TempDir(), "mismatch.sarif"), importReportOpts{projectUUID: database.DefaultProjectUUID})
	require.ErrorContains(t, err, "another project")
}

type failingReportWriter struct{}

func (failingReportWriter) Write([]byte) (int, error) { return 0, errors.New("report write failed") }
