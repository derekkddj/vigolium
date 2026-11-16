package output

import (
	"bufio"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/public"
)

func GenerateMarkdownReportStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	s, err := newReportSnapshot(produce, meta)
	if err != nil {
		return err
	}
	defer s.close()
	return writeReportFile(outputPath, func(w io.Writer) error { return writeSnapshotMarkdown(w, s, meta) })
}

func writeSnapshotMarkdown(w io.Writer, s *reportSnapshot, meta HTMLReportMeta) error {
	bw := bufio.NewWriter(w)
	writeMarkdownHeader(bw, s.data)
	writeMarkdownTOC(bw, s.data)
	writeMarkdownExecutiveSummary(bw, s.data)
	opts := newMarkdownFindingOptions(meta)
	for _, group := range reportSeverityOrder {
		if s.count(group) == 0 {
			continue
		}
		fmt.Fprintf(bw, "## %s Findings\n\n", strings.ToUpper(group[:1])+group[1:])
		if err := s.findings(group, func(f ReportFinding) error { writeMarkdownFinding(bw, f, opts); return nil }); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// GenerateDocumentReportStreaming retains the template's layout, TOC and
// severity ordering, but executes findingBlock for one disk-backed finding at a
// time. The main template receives only TOC identities and summary metadata.
func GenerateDocumentReportStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	if meta.Title == "" {
		meta.Title = defaultReportTitle
	}
	s, err := newReportSnapshot(produce, meta)
	if err != nil {
		return err
	}
	defer s.close()
	return renderDocumentSnapshot(s, outputPath)
}

func renderDocumentSnapshot(s *reportSnapshot, outputPath string) error {
	raw, err := public.StaticFS.ReadFile("static-reports/report-template.html")
	if err != nil {
		return err
	}
	source := string(raw)
	for _, group := range reportSeverityOrder {
		field := strings.ToUpper(group[:1]) + group[1:] + "Findings"
		marker := "{{range ." + field + "}}{{template \"findingBlock\" .}}{{end}}"
		if strings.Count(source, marker) != 1 {
			return fmt.Errorf("document template missing unique streaming marker for %s", field)
		}
		source = strings.Replace(source, marker, "{{streamFindings \""+group+"\"}}", 1)
	}
	var dest io.Writer
	var tmpl *template.Template
	funcs := documentTemplateFuncs()
	funcs["streamFindings"] = func(group string) (string, error) {
		err := s.findings(group, func(f ReportFinding) error { return tmpl.ExecuteTemplate(dest, "findingBlock", f) })
		return "", err
	}
	tmpl, err = template.New("report").Funcs(funcs).Parse(source)
	if err != nil {
		return err
	}
	return writeReportFile(outputPath, func(w io.Writer) error { dest = w; return tmpl.Execute(w, s.data) })
}

func GenerateCSVReportStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	s, err := newReportSnapshot(produce, meta)
	if err != nil {
		return err
	}
	defer s.close()
	return writeReportFile(outputPath, func(w io.Writer) error { return writeFindingsCSV(w, s.views) })
}

func GenerateJUnitReportStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	s, err := newReportSnapshot(produce, meta)
	if err != nil {
		return err
	}
	defer s.close()
	// JUnit groups/sorts scalar finding identities; no request/response corpus
	// or selected receipt buffers are retained by this metadata-only model.
	doc := buildJUnitReport(s.views, meta)
	return writeReportFile(outputPath, func(w io.Writer) error { return writeJUnitXML(w, doc) })
}

func GenerateGitHubAnnotationsStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	s, err := newReportSnapshot(produce, meta)
	if err != nil {
		return err
	}
	defer s.close()
	render := func(w io.Writer) error { return writeGitHubAnnotations(w, s.views) }
	if outputPath == "" {
		bw := bufio.NewWriter(reportStdout)
		if err := render(bw); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	} else if err := writeReportFile(outputPath, render); err != nil {
		return err
	}
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		if err := appendSnapshotGitHubSummary(path, s, meta); err != nil {
			return fmt.Errorf("append GITHUB_STEP_SUMMARY: %w", err)
		}
	}
	return nil
}

func appendSnapshotGitHubSummary(path string, s *reportSnapshot, meta HTMLReportMeta) error {
	// Size-check a disk rendering, not an unbounded Markdown string. Append the
	// full file only when it fits; otherwise use the existing summary contract.
	preview := filepath.Join(s.dir, "summary.md")
	if err := writeReportFile(preview, func(w io.Writer) error { return writeSnapshotMarkdown(w, s, meta) }); err != nil {
		return err
	}
	info, err := os.Stat(preview)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	if info.Size() > githubStepSummaryLimit {
		bw := bufio.NewWriter(out)
		writeMarkdownHeader(bw, s.data)
		writeMarkdownExecutiveSummary(bw, s.data)
		fmt.Fprintf(bw, "_Full report omitted: %d bytes exceeds the job-summary limit; render it with `--format markdown -o <file>`._\n\n", info.Size())
		return bw.Flush()
	}
	in, err := os.Open(preview)
	if err != nil {
		return err
	}
	defer in.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	_, err = io.WriteString(out, "\n")
	return err
}
