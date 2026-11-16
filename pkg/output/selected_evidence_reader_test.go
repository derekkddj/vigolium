package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestSelectedEvidenceFormatsKeepHistoricalStatusAndLaterOccurrenceSeparate(t *testing.T) {
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	later := evidence.Select(x, evidence.RoleAttack, true, "later selected")
	later.OccurrenceID = "later-occurrence"
	historical := evidence.Entry{ExchangeID: "historic-missing", Role: evidence.RoleUnknown, Primary: true, OccurrenceID: "historic-occurrence"}
	f := ReportFinding{EvidenceStatus: "unclassified", Evidence: []evidence.Entry{historical, later}}
	props := sarifResultProperties(&f)
	if props["evidenceStatus"] != "unclassified" {
		t.Fatal("SARIF reclassified original status")
	}
	data, err := json.Marshal(props["evidence"])
	if err != nil {
		t.Fatal(err)
	}
	var entries []evidence.Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Role != evidence.RoleUnknown || entries[1].OccurrenceID != "later-occurrence" || !bytes.Equal(entries[1].Exchange.Response, x.Response) {
		t.Fatal("SARIF discarded or reclassified per-occurrence evidence")
	}
	var md strings.Builder
	writeMarkdownFindings(&md, "High", []ReportFinding{f}, newMarkdownFindingOptions(HTMLReportMeta{}))
	if !strings.Contains(md.String(), "Stored finding evidence status:** unclassified") || !strings.Contains(md.String(), "historic-occurrence") || !strings.Contains(md.String(), "later-occurrence") || !strings.Contains(md.String(), "role attack") || !strings.Contains(md.String(), "role unknown") {
		t.Fatalf("Markdown hid/reclassified historical or later occurrence: %s", md.String())
	}
}

func TestSelectedEvidenceJSONAndFormatReadersRetainRawContract(t *testing.T) {
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\xff\x00"), []byte("response\xfe\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "selected")
	entry.OccurrenceID = "occurrence"
	ev := &ResultEvent{ModuleID: "test", Evidence: []evidence.Entry{entry}, EvidenceStatus: "selected", Response: "legacy text"}
	w := &StandardWriter{IncludeResponseInOutput: false}
	data, err := w.formatJSON(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got ResultEvent
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Response != "" || got.EvidenceStatus != "selected" || len(got.Evidence) != 1 || !bytes.Equal(got.Evidence[0].Exchange.Response, x.Response) || ev.Response != "legacy text" {
		t.Fatalf("formatJSON dropped selected bytes or mutated caller: %s", data)
	}
	findingData, _ := json.Marshal(map[string]any{"module_id": "test", "evidence_status": "selected", "evidence": []evidence.Entry{entry}})
	for _, entries := range [][]evidence.Entry{decodeFindingView(findingData).Evidence, parseFinding(findingData, nil).Evidence} {
		if len(entries) != 1 || entries[0].Role != evidence.RoleAttack || entries[0].OccurrenceID != "occurrence" || !bytes.Equal(entries[0].Exchange.Request, x.Request) {
			t.Fatal("format reader discarded selected evidence")
		}
	}
	raw, _ := json.Marshal(map[string]any{"type": "finding", "data": json.RawMessage(findingData)})
	budget := int64(1)
	var stats reportTrimStats
	trimmed := trimReportItemJSON(raw, &budget, &stats)
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(trimmed, &env); err != nil {
		t.Fatal(err)
	}
	v := decodeFindingView(env.Data)
	if len(v.Evidence) != 1 || !bytes.Equal(v.Evidence[0].Exchange.Response, x.Response) {
		t.Fatal("HTML preview capping silently truncated authoritative selected bytes")
	}
}
