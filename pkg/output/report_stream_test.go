package output

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestSelectedEvidenceReportSnapshotRetainsOnlyMetadataInMemory(t *testing.T) {
	calls := 0
	var first *evidence.Exchange
	produce := func(emit func(any) error) error {
		calls++
		for i := range 70 {
			raw := append([]byte("POST https://absolute.example/proof HTTP/1.1\r\nHost: virtual.example\r\nContent-Length: 999999\r\n\r\n\x00\xffRAW-RECEIPT"), bytes.Repeat([]byte("BODY"), 1024)...)
			x := evidence.NewExchange("http://destination.example:8080", "https://display.example/proof", raw, []byte("HTTP/1.1 200 OK\r\nContent-Length: 700\r\n\r\n\xff\x00RESPONSE"), evidence.ProvenanceCaptured)
			if i == 0 {
				first = x
			}
			e := evidence.Select(x, evidence.RoleAttack, true, "proof")
			e.OccurrenceID = fmt.Sprintf("occurrence-%d", i)
			if err := emit(findingEnvelope(map[string]any{"id": i + 1, "module_id": "test", "module_name": "Test", "severity": "high", "request": string(raw), "additional_evidence": []string{"LEGACY-RAW-BODY"}, "evidence_status": "unclassified", "evidence": []evidence.Entry{e, {ExchangeID: "missing", Role: evidence.RoleUnknown}}})); err != nil {
				return err
			}
		}
		return nil
	}
	s, err := newReportSnapshot(produce, HTMLReportMeta{})
	require.NoError(t, err)
	defer s.close()
	require.Equal(t, 1, calls)
	require.Equal(t, 70, s.data.TotalFindings)
	require.Len(t, s.views, 70)
	metadata, err := json.Marshal([]any{s.data, s.views})
	require.NoError(t, err)
	require.NotContains(t, string(metadata), "RAW-RECEIPT")
	require.NotContains(t, string(metadata), "LEGACY-RAW-BODY")
	require.NotContains(t, string(metadata), base64.StdEncoding.EncodeToString(first.Request))
	for _, f := range s.data.HighFindings {
		require.Empty(t, f.Request)
		require.Empty(t, f.Response)
		require.Empty(t, f.Evidence)
		require.Empty(t, f.AdditionalEvidence)
	}
	for range 2 {
		n := 0
		require.NoError(t, s.findings("high", func(f ReportFinding) error {
			n++
			require.Equal(t, "unclassified", f.EvidenceStatus)
			require.Len(t, f.Evidence, 2)
			require.Nil(t, f.Evidence[1].Exchange)
			if n == 1 {
				require.Equal(t, first, f.Evidence[0].Exchange)
			}
			return nil
		}))
		require.Equal(t, 70, n)
	}
	require.Equal(t, 1, calls, "rehydration reads disk, not the original source")
	dir := s.dir
	s.close()
	_, err = os.Stat(dir)
	require.True(t, os.IsNotExist(err))
}

func TestSelectedEvidenceReportStreamingPreservesFormatContracts(t *testing.T) {
	x := evidence.NewExchange("http://destination.example:8080", "https://display.example/proof", []byte("POST /proof HTTP/1.1\r\nHost: virtual.example\r\nContent-Length: 900\r\n\r\n\x00\xffRAW"), []byte("HTTP/1.1 200 OK\r\nContent-Length: 700\r\n\r\n\xff\x00response"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "proof")
	entry.OccurrenceID = "occurrence"
	items := []any{
		map[string]any{"type": "scan", "data": map[string]any{"target": "https://app.test/", "total_requests": 5}},
		findingEnvelope(map[string]any{"id": 1, "severity": "low", "module_id": "same-rule", "module_name": "Test", "finding_hash": "low", "description": "## Low", "request": "GET / HTTP/1.1\r\nHost: app.test\r\n\r\n", "status": "accepted_risk"}),
		findingEnvelope(map[string]any{"id": 2, "severity": "high", "module_id": "same-rule", "module_name": "Test", "module_short": "Display", "finding_hash": "high", "description": "## High", "url": "https://app.test/proof", "request": "POST /proof HTTP/1.1\r\nHost: app.test\r\n\r\nlegacy", "response": "HTTP/1.1 200 OK\r\n\r\nlegacy response", "evidence_status": "unclassified", "evidence": []evidence.Entry{entry, {ExchangeID: "missing", Role: evidence.RoleUnknown}}, "remediation": "Fix this", "cwe_id": "CWE-79"}),
		map[string]any{"type": "module", "data": map[string]any{"id": "same-rule", "name": "Test", "enabled": true, "type": "active", "description": "Rule documentation"}},
	}
	meta := HTMLReportMeta{Title: "Report", Version: "test", GeneratedAt: "2026-01-01T00:00:00Z", ScanTarget: "https://app.test/"}
	for _, name := range []string{"html", "markdown", "report", "sarif", "csv", "junit", "github"} {
		t.Run(name, func(t *testing.T) {
			format, ok := FormatByName(name)
			require.True(t, ok)
			require.NotNil(t, format.RenderStream)
			old, streamed := filepath.Join(t.TempDir(), "old"), filepath.Join(t.TempDir(), "streamed")
			t.Setenv("GITHUB_STEP_SUMMARY", "")
			require.NoError(t, format.Render(items, old, meta))
			require.NoError(t, format.RenderStream(sliceReportProducer(items), streamed, meta))
			a, err := os.ReadFile(old)
			require.NoError(t, err)
			b, err := os.ReadFile(streamed)
			require.NoError(t, err)
			if name == "sarif" {
				var want, got any
				require.NoError(t, json.Unmarshal(a, &want))
				require.NoError(t, json.Unmarshal(b, &got))
				require.Equal(t, want, got)
				var log sarifLog
				require.NoError(t, json.Unmarshal(b, &log))
				require.NotNil(t, log.Runs[0].Results[0].WebRequest)
				require.NotNil(t, log.Runs[0].Results[0].WebResponse)
				receipts, err := json.Marshal(log.Runs[0].Results[0].Properties["evidence"])
				require.NoError(t, err)
				var gotEntries []evidence.Entry
				require.NoError(t, json.Unmarshal(receipts, &gotEntries))
				require.Equal(t, entry, gotEntries[0], "complete receipt fields/bytes must not be repaired or reduced to a manifest")
				require.Nil(t, gotEntries[1].Exchange)
			} else {
				require.Equal(t, string(a), string(b))
			}
		})
	}
	pdf, ok := FormatByName("pdf")
	require.True(t, ok)
	require.NotNil(t, pdf.RenderStream, "PDF must use the same disk-backed document producer")
}

func TestSelectedEvidenceEmptyReportStreamingPreservesDefaults(t *testing.T) {
	meta := HTMLReportMeta{GeneratedAt: "2026-01-01T00:00:00Z"}
	for _, name := range []string{"html", "markdown", "report", "sarif", "csv", "junit", "github"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GITHUB_STEP_SUMMARY", "")
			format, ok := FormatByName(name)
			require.True(t, ok)
			require.NotNil(t, format.RenderStream)
			old, streamed := filepath.Join(t.TempDir(), "old"), filepath.Join(t.TempDir(), "streamed")
			require.NoError(t, format.Render(nil, old, meta))
			require.NoError(t, format.RenderStream(sliceReportProducer(nil), streamed, meta))
			a, err := os.ReadFile(old)
			require.NoError(t, err)
			b, err := os.ReadFile(streamed)
			require.NoError(t, err)
			if name == "sarif" {
				var want, got any
				require.NoError(t, json.Unmarshal(a, &want))
				require.NoError(t, json.Unmarshal(b, &got))
				require.Equal(t, want, got)
			} else {
				require.Equal(t, string(a), string(b))
			}
		})
	}
}

func TestSelectedEvidenceDocumentReportPreservesReceiptJSONAndUnknownHistory(t *testing.T) {
	x := evidence.NewExchange("http://destination.example:8080", "https://display.example/proof", []byte("POST https://absolute.example/ HTTP/1.1\r\nHost: virtual.example\r\nContent-Length: 9999\r\n\r\n\x00\xff"), []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n\x00\xffx\r\n0\r\n\r\n"), evidence.ProvenanceCached)
	// Serialization must preserve even invalid historical declarations, not
	// repair a hash, identity, framing or capture state to manufacture proof.
	x.ContentHash = "stored-invalid-hash"
	later := evidence.Select(x, evidence.RoleObservation, true, "</pre><script>untrusted</script>")
	later.OccurrenceID = "later-occurrence"
	historical := evidence.Entry{ExchangeID: "historic-missing", Role: evidence.RoleUnknown, Primary: true, OccurrenceID: "historic-occurrence"}
	entries := []evidence.Entry{historical, later}
	items := []any{findingEnvelope(map[string]any{"id": 1, "severity": "high", "evidence_status": "unclassified", "evidence": entries, "request": "LEGACY-INLINE-NOT-PROOF", "http_record_uuids": []string{"legacy-reference-not-proof"}})}
	path := filepath.Join(t.TempDir(), "report.html")
	require.NoError(t, GenerateDocumentReportStreaming(sliceReportProducer(items), path, HTMLReportMeta{}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	source := string(data)
	require.Contains(t, source, "Stored Finding Evidence Status: unclassified")
	require.Contains(t, source, "historic-occurrence")
	require.Contains(t, source, "later-occurrence")
	require.Contains(t, source, "Selected bytes unavailable; no fallback substituted.")
	require.Contains(t, source, "cached_observation")
	require.Contains(t, source, "Legacy Request — role unknown (not proof)")
	require.Contains(t, source, "legacy-reference-not-proof")
	require.NotContains(t, source, "<script>untrusted</script>")
	const marker = `<pre class="evidence selected-receipt-json">`
	parts := strings.Split(source, marker)
	require.Len(t, parts, 3)
	for i, part := range parts[1:] {
		encoded, _, found := strings.Cut(part, "</pre>")
		require.True(t, found)
		var got evidence.Entry
		require.NoError(t, json.Unmarshal([]byte(html.UnescapeString(encoded)), &got))
		require.Equal(t, entries[i], got, "document/PDF input must retain every manifest and complete binary receipt")
	}
	require.Contains(t, source, "<details open>", "receipt JSON must not be hidden from Chrome print output")
}

func TestSelectedEvidenceReportStreamingFailurePreservesPreviousFile(t *testing.T) {
	for _, name := range []string{"html", "markdown", "report", "sarif", "csv", "junit", "github"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "previous")
			require.NoError(t, os.WriteFile(path, []byte("previous"), 0o600))
			format, _ := FormatByName(name)
			err := format.RenderStream(func(emit func(any) error) error {
				if err := emit(findingEnvelope(map[string]any{"id": 1, "request": "raw"})); err != nil {
					return err
				}
				return errors.New("source failed")
			}, path, HTMLReportMeta{})
			require.ErrorContains(t, err, "source failed")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, "previous", string(data))
		})
	}
}
