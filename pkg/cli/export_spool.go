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

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

// exportSpool is the shared, disk-backed snapshot for a multi-format export.
// Authoritative bodies never accumulate in the run or in the bundle's HTML
// producer: each finding is hydrated, encoded and released before the next one.
type exportSpool struct {
	dir          string
	data, report *os.File
	counts       exportCounts
}

func newExportSpool(produce output.ReportItemProducer) (*exportSpool, error) {
	dir, err := scratch.MkdirTemp("export-spool-*")
	if err != nil {
		return nil, err
	}
	s := &exportSpool{dir: dir, counts: newExportCounts()}
	for _, dst := range []struct {
		name string
		file **os.File
	}{{"export.jsonl", &s.data}, {"report.jsonl", &s.report}} {
		f, err := os.OpenFile(filepath.Join(dir, dst.name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			s.close()
			return nil, err
		}
		*dst.file = f
	}
	dataWriter, reportWriter := bufio.NewWriter(s.data), bufio.NewWriter(s.report)
	dataEncoder, reportEncoder := json.NewEncoder(dataWriter), json.NewEncoder(reportWriter)
	dataEncoder.SetEscapeHTML(false)
	reportEncoder.SetEscapeHTML(false)
	err = produce(func(item any) error {
		env, ok := item.(exportEnvelope)
		if !ok {
			return fmt.Errorf("export producer returned %T, want export envelope", item)
		}
		if err := dataEncoder.Encode(env); err != nil {
			return err
		}
		s.counts.add(env)
		preview, err := bundleReportProjection(env.Data, bundleDataReference{Path: "export.jsonl", Line: s.counts.total})
		if err != nil {
			return err
		}
		return reportEncoder.Encode(exportEnvelope{Type: env.Type, Data: preview})
	})
	if err == nil {
		err = dataWriter.Flush()
	}
	if err == nil {
		err = reportWriter.Flush()
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *exportSpool) close() {
	if s == nil {
		return
	}
	for _, f := range []*os.File{s.data, s.report} {
		if f != nil {
			_ = f.Close()
		}
	}
	_ = os.RemoveAll(s.dir)
}

func (r *exportRun) closeSpool() {
	r.spool.close()
	r.spool = nil
}

func (r *exportRun) loadSpool(ctx context.Context, db *database.DB) (*exportSpool, error) {
	if r.spool != nil {
		return r.spool, nil
	}
	s, err := newExportSpool(func(emit func(any) error) error {
		return streamExportData(ctx, db, topExportQuery(r.projectUUID), emit)
	})
	if err != nil {
		return nil, err
	}
	r.spool = s
	r.counts, r.countsSet = s.counts, true
	return s, nil
}

// producer may be called repeatedly by renderers without reopening the database.
// The report file contains only metadata/manifests and authoritative line refs.
func (s *exportSpool) producer(report bool) output.ReportItemProducer {
	file := s.data
	if report {
		file = s.report
	}
	return jsonFileProducer(file)
}

func jsonFileProducer(file *os.File) output.ReportItemProducer {
	return func(emit func(any) error) error {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		dec := json.NewDecoder(file)
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
	}
}

func (s *exportSpool) copyJSONL(w io.Writer) error {
	if _, err := s.data.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := io.Copy(w, s.data)
	return err
}

// bundleReportProjection never exposes raw messages to an HTML renderer, even
// one that falls back to collecting its producer. Do not embed *HTTPRecord in a
// reference wrapper: its promoted MarshalJSON would silently discard the refs.
func bundleReportProjection(item any, ref bundleDataReference) (any, error) {
	var preview any
	var referenceKey string
	switch row := item.(type) {
	case *database.Finding:
		copy := *row
		copy.Request, copy.Response, copy.AdditionalEvidence = "", "", nil
		copy.Evidence = make([]evidence.Entry, len(row.Evidence))
		for i, entry := range row.Evidence {
			copy.Evidence[i] = entry.Manifest()
		}
		preview, referenceKey = &copy, "evidence_source"
	case *database.HTTPRecord:
		copy := *row
		copy.RawRequest, copy.RawResponse = nil, nil
		preview, referenceKey = &copy, "raw_traffic_source"
	case database.RecordWithHostFacts:
		copy := *row.Record
		copy.RawRequest, copy.RawResponse = nil, nil
		preview, referenceKey = database.RecordWithHostFacts{Record: &copy, Facts: row.Facts}, "raw_traffic_source"
	case *database.OASTPlantingReceipt:
		x, err := row.Exchange()
		if err != nil {
			return nil, err
		}
		x.Request, x.Response = nil, nil
		preview = map[string]any{"project_uuid": row.ProjectUUID, "scan_uuid": row.ScanUUID, "nonce": row.Nonce, "exchange_manifest": x}
		referenceKey = "raw_traffic_source"
	case *database.OASTPayload:
		copy := *row
		copy.Payload = ""
		preview, referenceKey = &copy, "raw_traffic_source"
	case *database.OASTInteraction:
		copy := *row
		copy.RawRequest, copy.RawResponse = "", ""
		preview, referenceKey = &copy, "raw_traffic_source"
	default:
		return item, nil
	}
	data, err := json.Marshal(preview)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	fields[referenceKey], err = json.Marshal(ref)
	if err != nil {
		return nil, err
	}
	if referenceKey == "evidence_source" {
		fields["evidence_preview"], _ = json.Marshal("Manifest only; authoritative selected and legacy bytes are in the referenced finding envelope. No fallback proof is inferred.")
	}
	return fields, nil
}

// The slice-based bundle helpers remain compatibility/test wrappers. Production
// pulls from the disk-backed export snapshot through this renderer instead.
var renderExportBundleHTML = output.GenerateHTMLReportStreaming

func (s *exportSpool) writeBundleMembers(tw *tar.Writer, root string, meta output.HTMLReportMeta, sessionsBase, projectUUID string) ([]string, error) {
	now := time.Now().UTC()
	if err := writeTarDir(tw, root+"/", now); err != nil {
		return nil, err
	}
	if err := writeDBBundleFile(tw, root+"/export.jsonl", s.data.Name(), now); err != nil {
		return nil, err
	}
	htmlPath := filepath.Join(s.dir, "report.html")
	if err := renderExportBundleHTML(s.producer(true), htmlPath, meta); err != nil {
		return nil, fmt.Errorf("render report.html for bundle: %w", err)
	}
	if err := writeDBBundleFile(tw, root+"/report.html", htmlPath, now); err != nil {
		return nil, err
	}
	included, err := writeSessionsToTar(tw, root, sessionsBase, topExportScanUUIDs, now)
	if err != nil {
		return nil, err
	}
	manifest := makeBundleManifest(root, projectUUID, s.counts, included, meta, now)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode manifest: %w", err)
	}
	if err := writeTarBytes(tw, root+"/manifest.json", append(data, '\n'), now); err != nil {
		return nil, err
	}
	return included, nil
}
