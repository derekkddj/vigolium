package output

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// GenerateSARIFReportStreaming preserves the SARIF rules/results contract,
// severity ordering, standard webRequest/webResponse and full selected receipt
// properties. Only one result owns raw evidence at a time; results are spooled
// to disk while the (raw-free) rule table is merged, then copied into the log.
func GenerateSARIFReportStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	s, err := newReportSnapshot(produce, meta)
	if err != nil {
		return err
	}
	defer s.close()
	b := &sarifBuilder{rules: []sarifRule{}, ruleIndex: make(map[string]int), moduleDesc: make(map[string]string)}
	for _, m := range s.data.Modules {
		b.moduleDesc[m.ID] = firstNonEmpty(m.Description, m.ShortDescription)
	}
	results, err := os.OpenFile(filepath.Join(s.dir, "results.jsonl"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer results.Close()
	enc := json.NewEncoder(results)
	enc.SetEscapeHTML(false)
	for _, group := range reportSeverityOrder {
		if err := s.findings(group, func(f ReportFinding) error {
			b.addFinding(&f)
			err := enc.Encode(b.results[0])
			b.results = nil // release complete receipts BEFORE the next finding
			return err
		}); err != nil {
			return err
		}
	}
	// Build only the small log shell with the legacy metadata helper; it has no
	// finding/result data. Marshal its run fields separately from results.
	log := buildSARIFLog(nil, meta)
	run := log.Runs[0]
	run.Tool.Driver.Rules = b.rules
	shell, err := json.Marshal(run)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(shell, &fields); err != nil {
		return err
	}
	delete(fields, "results")
	header, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return writeReportFile(outputPath, func(w io.Writer) error {
		if _, err := io.WriteString(w, `{"$schema":"`+sarifSchemaURI+`","version":"`+sarifVersion+`","runs":[`); err != nil {
			return err
		}
		if _, err := w.Write(header[:len(header)-1]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, `,"results":[`); err != nil {
			return err
		}
		if _, err := results.Seek(0, io.SeekStart); err != nil {
			return err
		}
		dec := json.NewDecoder(results)
		first := true
		for {
			var result json.RawMessage
			if err := dec.Decode(&result); err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			if !first {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			if _, err := w.Write(result); err != nil {
				return err
			}
			first = false
		}
		_, err := io.WriteString(w, "]}]}\n")
		return err
	})
}
