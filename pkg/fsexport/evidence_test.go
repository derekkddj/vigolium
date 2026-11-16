package fsexport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestSelectedEvidenceSidecarsExactBinaryAndMissingManifest(t *testing.T) {
	dir := t.TempDir()
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff\r\n"), []byte("response\xfe\x00\r\n"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "exact bytes")
	entry.OccurrenceID = "occurrence"
	f := &database.Finding{ProjectUUID: "project-a", EvidenceStatus: "selected", Evidence: []evidence.Entry{entry, {ExchangeID: "missing", Role: evidence.RoleControl, Label: "missing control"}}}
	if err := WriteFindingEvidenceFiles(dir, "0001", f, 0o600); err != nil {
		t.Fatal(err)
	}
	for suffix, want := range map[string][]byte{"request": x.Request, "response": x.Response} {
		path := filepath.Join(dir, "0001.evidence-0001."+suffix+".bin")
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("selected bytes transformed")
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "0001.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Evidence       []evidence.Entry `json:"evidence"`
		EvidenceStatus string           `json:"evidence_status"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.EvidenceStatus != "selected" || len(bundle.Evidence) != 2 || !bytes.Equal(bundle.Evidence[0].Exchange.Response, x.Response) || bundle.Evidence[1].Exchange != nil || bundle.Evidence[1].Role != evidence.RoleControl || bundle.Evidence[0].OccurrenceID != "occurrence" {
		t.Fatalf("lost sidecar manifest: %s", data)
	}
	md := string(RenderFindingMarkdown(f, []LinkedRecord{{Path: "host/first", Request: "FIRST LINK NOT PROOF", ResponseBody: "LINKED RESPONSE"}}, "traffic"))
	if !strings.Contains(md, "role attack, primary true") || !strings.Contains(md, "Selected bytes unavailable") || !strings.Contains(md, "linked context, role unknown (not proof)") {
		t.Fatalf("markdown misclassified receipts: %s", md)
	}
}
