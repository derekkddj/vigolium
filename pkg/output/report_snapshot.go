package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/yuin/goldmark"
)

var reportSeverityOrder = []string{"critical", "high", "medium", "low", "info"}

// reportSnapshot owns raw finding envelopes only ON DISK. Its in-memory state
// contains summary counters, TOC identities and tabular metadata, never request /
// response strings or hydrated receipts. The source need only run once; renderers
// hydrate one original envelope at a time, without reconstructing HTTP messages.
type reportSnapshot struct {
	dir    string
	groups map[string]*os.File
	data   ReportData
	views  []FindingView
}

func newReportSnapshot(produce ReportItemProducer, meta HTMLReportMeta) (*reportSnapshot, error) {
	dir, err := scratch.MkdirTemp("report-snapshot-*")
	if err != nil {
		return nil, err
	}
	title := meta.Title
	s := &reportSnapshot{dir: dir, groups: make(map[string]*os.File), data: buildReportData(nil, title, meta)}
	err = produce(func(item any) error {
		raw, err := json.Marshal(item)
		if err != nil {
			return err
		}
		var env struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		switch env.Type {
		case "finding":
			f := parseFinding(env.Data, nil)
			group := reportSeverityGroup(f.Severity)
			file := s.groups[group]
			if file == nil {
				file, err = os.OpenFile(filepath.Join(dir, group+".jsonl"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
				if err != nil {
					return err
				}
				s.groups[group] = file
			}
			// Keep the original fields, including complete base64 receipts, in the
			// spool. No parse/reconciliation or manifest-only substitute is written.
			if _, err := file.Write(append(raw, '\n')); err != nil {
				return err
			}
			s.addTOC(group, ReportFinding{ID: f.ID, Title: f.Title})
			v := decodeFindingView(env.Data)
			v.Evidence = nil // no tabular format serializes receipt messages
			s.views = append(s.views, v)
		case "scan":
			var scan struct {
				Target        string `json:"target"`
				TotalRequests int    `json:"total_requests"`
			}
			_ = json.Unmarshal(env.Data, &scan)
			if scan.Target != "" {
				s.data.Target = scan.Target
			}
			s.data.TotalRequests = scan.TotalRequests
		case "http_record":
			s.data.TotalRequests++
		case "module":
			row := buildReportData([]any{json.RawMessage(raw)}, title, meta)
			s.data.Modules = append(s.data.Modules, row.Modules...)
			s.data.ActiveModules += row.ActiveModules
			s.data.PassiveModules += row.PassiveModules
		}
		return nil
	})
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func reportSeverityGroup(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(severity)
	default:
		return "info"
	}
}

func (s *reportSnapshot) addTOC(group string, f ReportFinding) {
	s.data.TotalFindings++
	switch group {
	case "critical":
		s.data.CriticalCount++
		s.data.CriticalFindings = append(s.data.CriticalFindings, f)
	case "high":
		s.data.HighCount++
		s.data.HighFindings = append(s.data.HighFindings, f)
	case "medium":
		s.data.MediumCount++
		s.data.MediumFindings = append(s.data.MediumFindings, f)
	case "low":
		s.data.LowCount++
		s.data.LowFindings = append(s.data.LowFindings, f)
	default:
		s.data.InfoCount++
		s.data.InfoFindings = append(s.data.InfoFindings, f)
	}
}

func (s *reportSnapshot) count(group string) int {
	switch group {
	case "critical":
		return s.data.CriticalCount
	case "high":
		return s.data.HighCount
	case "medium":
		return s.data.MediumCount
	case "low":
		return s.data.LowCount
	default:
		return s.data.InfoCount
	}
}

func (s *reportSnapshot) findings(group string, emit func(ReportFinding) error) error {
	file := s.groups[group]
	if file == nil {
		return nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	dec, md := json.NewDecoder(file), goldmark.New()
	for {
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := dec.Decode(&env); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read report finding: %w", err)
		}
		if err := emit(parseFinding(env.Data, md)); err != nil {
			return err
		}
	}
}

func (s *reportSnapshot) close() {
	for _, file := range s.groups {
		_ = file.Close()
	}
	_ = os.RemoveAll(s.dir)
}

// sliceReportProducer is only the compatibility adapter for callers that already
// have a small item slice. Production database paths use RenderStream directly.
func sliceReportProducer(items []any) ReportItemProducer {
	return func(emit func(any) error) error {
		for _, item := range items {
			if err := emit(item); err != nil {
				return err
			}
		}
		return nil
	}
}
