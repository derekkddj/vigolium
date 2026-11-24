package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// streamRecordDBExport freezes filtered records on disk, closes the query, then
// writes one record at a time. JSON's count precedes its array without requiring
// a raw item collection or a second potentially different database query.
func streamRecordDBExport(ctx context.Context, db *database.DB, filters database.QueryFilters, out io.Writer) (int, error) {
	switch exportFormat {
	case "jsonl", "json", "raw", "csv", "markdown", "markdown-table":
	default:
		return 0, usageErrorf("unsupported export format: %s", exportFormat)
	}
	dir, err := scratch.MkdirTemp("db-export-records-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	file, err := os.OpenFile(filepath.Join(dir, "records.jsonl"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	// --uuid selects exactly one resolved record, irrespective of a traffic
	// page's offset. Finding pagination is independent and keeps its filters.
	if exportRecordUUID != "" {
		filters.Limit, filters.Offset = 0, 0
	}
	qb := database.NewQueryBuilder(db, filters)
	if exportFormat == "csv" || exportFormat == "markdown-table" {
		qb = qb.OmitBodies()
	}
	q := qb.BuildRecordsQuery()
	rows, err := q.Rows(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to query database: %w", err)
	}
	n, err := func() (int, error) {
		defer rows.Close()
		enc := json.NewEncoder(file)
		enc.SetEscapeHTML(false)
		n := 0
		for rows.Next() {
			if err := ctx.Err(); err != nil {
				return n, err
			}
			r := new(database.HTTPRecord)
			if err := db.ScanRow(ctx, rows, r); err != nil {
				return n, err
			}
			if err := enc.Encode(r); err != nil {
				return n, err
			}
			n++
		}
		return n, rows.Err()
	}()
	if err != nil {
		return n, err
	}
	if exportRecordUUID != "" && n == 0 {
		return 0, fmt.Errorf("record UUID %s not found", exportRecordUUID)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return n, err
	}
	// Capture errors from legacy single-record text helpers as well as framing.
	w := &dbExportErrorWriter{Writer: out}
	var csv *output.SafeCSVWriter
	var envelopes *json.Encoder
	switch exportFormat {
	case "jsonl":
		envelopes = json.NewEncoder(w)
		envelopes.SetEscapeHTML(false)
	case "json":
		date, _ := json.Marshal(time.Now().Format(time.RFC3339))
		fmt.Fprintf(w, "{\"export_date\":%s,\"total_records\":%d,\"records\":[", date, n)
	case "csv":
		csv = output.NewSafeCSVWriter(w)
		if err := csv.Write(dbRecordCSVColumns); err != nil {
			return n, err
		}
	case "markdown-table":
		if err := exportMarkdownTable(nil, w); err != nil {
			return n, err
		}
	}
	dec := json.NewDecoder(file)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return n, err
		}
		if exportFormat == "json" {
			if i > 0 {
				io.WriteString(w, ",")
			}
			w.Write(raw)
		} else if exportFormat == "jsonl" {
			if err := envelopes.Encode(exportEnvelope{Type: "http_record", Data: raw}); err != nil {
				return n, err
			}
		} else {
			var r database.HTTPRecord
			if err := json.Unmarshal(raw, &r); err != nil {
				return n, err
			}
			switch exportFormat {
			case "raw":
				err = exportRaw([]*database.HTTPRecord{&r}, w)
			case "markdown":
				if i > 0 {
					io.WriteString(w, "---\n\n")
				}
				renderRecordMarkdown(&r, w, exportRequestOnly, false)
			case "markdown-table":
				err = writeDBMarkdownTableRow(w, &r)
			case "csv":
				err = writeDBRecordCSV(csv, &r)
			}
			if err != nil {
				return n, err
			}
		}
		if w.err != nil {
			return n, w.err
		}
	}
	if exportFormat == "json" {
		io.WriteString(w, "]}\n")
	}
	if csv != nil {
		if err := csv.Flush(); err != nil {
			return n, err
		}
	}
	return n, w.err
}

var dbRecordCSVColumns = []string{"uuid", "hostname", "port", "method", "path", "status_code", "response_time_ms", "content_type", "source", "risk_score", "surface_score", "remarks", "created_at"}

type dbExportErrorWriter struct {
	io.Writer
	err error
}

func (w *dbExportErrorWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.Writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}
