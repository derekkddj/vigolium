package cli

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// dbBundleSpool keeps authoritative JSONL, the manifest-only report view, and
// session paths on disk. No collection owns the export's raw HTTP corpus.
type dbBundleSpool struct {
	dir                                        string
	data, report, sessions                     *os.File
	dataWriter, reportWriter, sessionWriter    *bufio.Writer
	dataEncoder, reportEncoder, sessionEncoder *json.Encoder
	counts                                     map[string]int
	lines                                      int
}

func newDBBundleSpool(counts map[string]int) (*dbBundleSpool, error) {
	dir, err := scratch.MkdirTemp("db-export-bundle-*")
	if err != nil {
		return nil, err
	}
	s := &dbBundleSpool{dir: dir, counts: counts}
	for _, dst := range []struct {
		name    string
		file    **os.File
		writer  **bufio.Writer
		encoder **json.Encoder
	}{
		{"data.jsonl", &s.data, &s.dataWriter, &s.dataEncoder},
		{"report.jsonl", &s.report, &s.reportWriter, &s.reportEncoder},
		{"sessions.jsonl", &s.sessions, &s.sessionWriter, &s.sessionEncoder},
	} {
		f, err := os.OpenFile(filepath.Join(dir, dst.name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			s.close()
			return nil, err
		}
		*dst.file = f
		*dst.writer = bufio.NewWriter(f)
		*dst.encoder = json.NewEncoder(*dst.writer)
		(*dst.encoder).SetEscapeHTML(false)
	}
	return s, nil
}

func (s *dbBundleSpool) close() {
	for _, f := range []*os.File{s.data, s.report, s.sessions} {
		if f != nil {
			_ = f.Close()
		}
	}
	_ = os.RemoveAll(s.dir)
}

type bundleDataReference struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type bundleSessionReference struct {
	Path   string `json:"path"`
	Prefix string `json:"prefix"`
}

func (s *dbBundleSpool) appendEnvelope(kind string, item any) error {
	if err := s.dataEncoder.Encode(exportEnvelope{Type: kind, Data: item}); err != nil {
		return err
	}
	s.lines++
	s.counts[kind]++
	ref := bundleDataReference{Path: "data.jsonl", Line: s.lines}
	preview, err := bundleReportProjection(item, ref)
	if err != nil {
		return err
	}
	switch row := item.(type) {
	case *database.Scan:
		if row.UUID != "" {
			if err := s.sessionEncoder.Encode(bundleSessionReference{filepath.Join(resolveNativeSessionsDir(), row.UUID), "native-sessions"}); err != nil {
				return err
			}
		}
	case *database.AgenticScan:
		path := row.SessionDir
		if path == "" && row.UUID != "" {
			path = filepath.Join(resolveSessionsDir(), row.UUID)
		}
		if path != "" {
			if err := s.sessionEncoder.Encode(bundleSessionReference{path, "sessions"}); err != nil {
				return err
			}
		}
	}
	return s.reportEncoder.Encode(exportEnvelope{Type: kind, Data: preview})
}

func (s *dbBundleSpool) flush() error {
	for _, w := range []*bufio.Writer{s.dataWriter, s.reportWriter, s.sessionWriter} {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// streamDBBundleRows holds one table row at a time; its cursor is closed before
// another table (or any finding receipt hydration) starts.
func streamDBBundleRows[T any](ctx context.Context, db *database.DB, q *bun.SelectQuery, kind string, emit func(string, any) error) error {
	rows, err := q.Rows(ctx)
	if err != nil {
		return fmt.Errorf("query %s: %w", kind, err)
	}
	defer rows.Close()
	for rows.Next() {
		row := new(T)
		if err := db.ScanRow(ctx, rows, row); err != nil {
			return err
		}
		if err := emit(kind, row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// renderDBBundleHTML is indirected for atomic-publication failure regressions.
// Its producer decodes only the raw-free report spool, never data.jsonl.
var renderDBBundleHTML = output.GenerateHTMLReportStreaming

func (s *dbBundleSpool) writeMembers(tw *tar.Writer, meta output.HTMLReportMeta, now time.Time) (int, int, error) {
	if err := s.flush(); err != nil {
		return 0, 0, err
	}
	if err := writeDBBundleFile(tw, "data.jsonl", s.data.Name(), now); err != nil {
		return 0, 0, err
	}
	if s.lines > 0 {
		produce := output.ReportItemProducer(func(emit func(any) error) error {
			if _, err := s.report.Seek(0, io.SeekStart); err != nil {
				return err
			}
			dec := json.NewDecoder(s.report)
			for {
				var item json.RawMessage
				if err := dec.Decode(&item); err != nil {
					if err == io.EOF {
						return nil
					}
					return err
				}
				if err := emit(item); err != nil {
					return err
				}
			}
		})
		htmlPath := filepath.Join(s.dir, "report.html")
		if err := renderDBBundleHTML(produce, htmlPath, meta); err != nil {
			return 0, 0, fmt.Errorf("render report.html for bundle: %w", err)
		}
		if err := writeDBBundleFile(tw, "report.html", htmlPath, now); err != nil {
			return 0, 0, err
		}
	}
	if _, err := s.sessions.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	agent, native := 0, 0
	dec := json.NewDecoder(s.sessions)
	for {
		var ref bundleSessionReference
		if err := dec.Decode(&ref); err != nil {
			if err == io.EOF {
				return agent, native, nil
			}
			return agent, native, err
		}
		archived, err := archiveSessionDir(tw, ref.Path, ref.Prefix)
		if err != nil {
			return agent, native, err
		}
		if archived {
			if ref.Prefix == "sessions" {
				agent++
			} else {
				native++
			}
		}
	}
}

func writeDBBundleFile(tw *tar.Writer, name, path string, now time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: info.Size(), Mode: 0o600, ModTime: now}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}
