package dbimport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// Receipts are immutable records of what was sent and cannot be masked, so a
// redacting JSONL import keeps a finding's receipt associations as manifests,
// withholds their bytes and skips OAST planting receipts (raw sent requests).
func TestImportJSONLRedactionWithholdsReceipts(t *testing.T) {
	repo := newTestRepo(t)
	ctx := context.Background()
	const secret = "receipt-cookie-secret"
	x := evidence.NewExchange("https://example.com:443", "https://example.com/me",
		[]byte("GET /me HTTP/1.1\r\nHost: example.com\r\nCookie: sid="+secret+"\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nok"), evidence.ProvenanceCaptured)
	finding := database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ModuleID: "idor", ModuleName: "IDOR", Severity: "high",
		FindingHash: "fh-receipt", URL: "https://example.com/me", EvidenceStatus: "selected",
		Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "proof")},
	}
	plant := evidence.NewExchange("https://plant.test:443", "https://plant.test/p",
		[]byte("POST /p HTTP/1.1\r\nHost: plant.test\r\nX-OAST: n1.cb.test\r\nAuthorization: Bearer "+secret+"\r\n\r\n"),
		[]byte("HTTP/1.1 202 Accepted\r\n\r\n"), evidence.ProvenanceCaptured)
	encoded, err := json.Marshal(plant)
	if err != nil {
		t.Fatal(err)
	}
	receipt := database.OASTPlantingReceipt{ProjectUUID: database.DefaultProjectUUID, Nonce: "n1", ScanUUID: "s1", Receipt: string(encoded)}
	stream := jsonlEnvelope(t, "finding", finding) + "\n" + jsonlEnvelope(t, "oast_planting_receipt", receipt) + "\n"

	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream), database.DefaultProjectUUID, Options{RedactCredentials: true})
	if err != nil {
		t.Fatalf("ImportJSONL: %v", err)
	}
	if res.FindingsSaved != 1 || res.OASTPlantingReceiptsImported != 0 {
		t.Fatalf("saved %d findings, %d planting receipts; want 1, 0", res.FindingsSaved, res.OASTPlantingReceiptsImported)
	}
	var corpus []string
	if err := repo.DB().NewRaw("SELECT CAST(COALESCE(raw_request, X'') AS TEXT) FROM evidence_exchanges").Scan(ctx, &corpus); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(corpus, "\n"), secret) {
		t.Fatal("a redacting import stored a receipt carrying a credential")
	}
	var links int
	if err := repo.DB().NewRaw("SELECT COUNT(*) FROM finding_evidence WHERE exchange_id = ?", x.ID).Scan(ctx, &links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Fatalf("receipt association = %d, want 1 kept as a manifest", links)
	}
}
