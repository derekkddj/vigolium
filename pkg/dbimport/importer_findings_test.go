package dbimport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// A checkpoint is reached only when bufio needs more source bytes. This proves
// earlier findings were committed while parsing, not simply after EOF.
type findingImportCheckpoint struct {
	check func()
}

func (r *findingImportCheckpoint) Read([]byte) (int, error) {
	r.check()
	return 0, io.EOF
}

func importReceiptFinding(hash string, x *evidence.Exchange) *database.Finding {
	e := evidence.Select(x, evidence.RoleAttack, true, "binary attack")
	e.OccurrenceID = "occurrence-" + hash
	return &database.Finding{FindingHash: hash, ModuleID: "import-receipts", ModuleName: "Import receipts",
		Severity: "high", URL: x.URL, EvidenceStatus: "selected", Evidence: []evidence.Entry{e}}
}

func storedImportFindings(t *testing.T, repo *database.Repository) int {
	t.Helper()
	var n int
	if err := repo.DB().NewSelect().Model((*database.Finding)(nil)).ColumnExpr("COUNT(*)").Scan(context.Background(), &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestImportJSONLFindingCountBatchesAndForwardReferences(t *testing.T) {
	repo, ctx := newTestRepo(t), context.Background()
	project := database.DefaultProjectUUID
	scan := &database.AgenticScan{UUID: "finding-batch-scan", ProjectUUID: project, FindingCount: 7, SavedCount: 3}
	if err := repo.CreateAgenticScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	x := evidence.NewExchange("https://example.com:443", "https://example.com/a",
		[]byte("POST /a HTTP/1.1\r\n\r\n\x00\xffrequest"), []byte("HTTP/1.1 200 OK\r\n\r\n\xff\x00response"), evidence.ProvenanceSupplied)
	var first, second strings.Builder
	for i := 0; i < 2*findingFlushBatch; i++ {
		f := importReceiptFinding(fmt.Sprintf("batch-%03d", i), x)
		f.HTTPRecordUUIDs = []string{"later-record", "never-imported"}
		if i < findingFlushBatch {
			first.WriteString(jsonlEnvelope(t, "finding", f) + "\n")
		} else {
			second.WriteString(jsonlEnvelope(t, "finding", f) + "\n")
		}
	}
	// A later duplicate appends its new occurrence without increasing new-row
	// counters. Its receipt is independent of the old HTTP record inventory.
	laterX := evidence.NewExchange(x.Service, x.URL, x.Request, []byte("later binary\x00\xfe"), evidence.ProvenanceCaptured)
	duplicate := importReceiptFinding("batch-000", laterX)
	duplicate.Evidence[0].OccurrenceID = "later-occurrence"
	duplicate.HTTPRecordUUIDs = []string{"later-record"}
	last := jsonlEnvelope(t, "finding", duplicate) + "\n" + jsonlRecordLine(t, "later-record")
	stream := io.MultiReader(strings.NewReader(first.String()), &findingImportCheckpoint{check: func() {
		if n := storedImportFindings(t, repo); n != findingFlushBatch {
			t.Fatalf("before second batch: %d findings, want %d", n, findingFlushBatch)
		}
		f, err := repo.GetFindingByHash(ctx, "batch-000", project)
		if err != nil {
			t.Fatal(err)
		}
		var links int
		if err := repo.DB().NewRaw("SELECT COUNT(*) FROM finding_records WHERE finding_id = ?", f.ID).Scan(ctx, &links); err != nil || links != 2 {
			t.Fatalf("forward/ghost references were not retained: links=%d err=%v", links, err)
		}
	}}, strings.NewReader(second.String()), &findingImportCheckpoint{check: func() {
		if n := storedImportFindings(t, repo); n != 2*findingFlushBatch {
			t.Fatalf("before final lines: %d findings, want %d", n, 2*findingFlushBatch)
		}
	}}, strings.NewReader(last))
	res, err := ImportJSONL(ctx, repo, stream, project, Options{AgenticScanUUID: scan.UUID})
	if err != nil {
		t.Fatal(err)
	}
	if res.FindingsTotal != 2*findingFlushBatch+1 || res.FindingsSaved != 2*findingFlushBatch || res.FindingsSkipped != 1 || res.FindingsFailed != 0 || res.RecordsImported != 1 {
		t.Fatalf("multi-batch counters: %+v", res)
	}
	if res.SeverityCounts["high"] != res.FindingsTotal || res.AgenticScan.FindingCount != 7+res.FindingsTotal || res.AgenticScan.SavedCount != 3+res.FindingsSaved {
		t.Fatalf("multi-batch severity/attached counters: %+v", res)
	}
	f, err := repo.GetFindingByHash(ctx, "batch-000", project)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Evidence) != 2 || f.Evidence[1].OccurrenceID != "later-occurrence" {
		t.Fatalf("later occurrence lost: %+v", f.Evidence)
	}
	if err := repo.HydrateFindingRecordRefs(ctx, []*database.Finding{f}); err != nil {
		t.Fatal(err)
	}
	records, err := repo.GetFindingRecordsScoped(ctx, project, f.HTTPRecordUUIDs)
	if err != nil || len(records) != 1 || records[0].UUID != "later-record" || len(f.HTTPRecordUUIDs) != 2 {
		t.Fatalf("forward/ghost refs changed: %+v refs=%v err=%v", records, f.HTTPRecordUUIDs, err)
	}
	for _, want := range []*evidence.Exchange{x, laterX} {
		got, err := repo.GetEvidenceExchange(ctx, want.ID, project)
		if err != nil || !bytes.Equal(got.Request, want.Request) || !bytes.Equal(got.Response, want.Response) || !got.CapturedAt.Equal(want.CapturedAt) {
			t.Fatalf("binary receipt roundtrip for %s: %+v %v", want.ID, got, err)
		}
	}
}

func TestImportJSONLFindingByteBatches(t *testing.T) {
	repo, ctx := newTestRepo(t), context.Background()
	// Six encoded 1 MiB receipts exceed the 8 MiB budget despite being far
	// below the 64-finding count bound. The sixth forces the first five out.
	response := bytes.Repeat([]byte{0xff, 0x00, 0xfe, 'a'}, (1<<20)/4)
	var first, rest strings.Builder
	var receipts []*evidence.Exchange
	for i := 0; i < 12; i++ {
		x := evidence.NewExchange("https://example.com", "https://example.com/large",
			[]byte("request\x00\xff"), response, evidence.ProvenanceCaptured)
		line := jsonlEnvelope(t, "finding", importReceiptFinding(fmt.Sprintf("large-%d", i), x)) + "\n"
		if i < 6 {
			first.WriteString(line)
		} else {
			rest.WriteString(line)
		}
		// Keep only receipt metadata; the test source already holds the bodies.
		x.Request, x.Response = nil, nil
		receipts = append(receipts, x)
	}
	stream := io.MultiReader(strings.NewReader(first.String()), &findingImportCheckpoint{check: func() {
		if n := storedImportFindings(t, repo); n != 5 {
			t.Fatalf("byte budget did not flush before EOF: %d findings, want 5", n)
		}
	}}, strings.NewReader(rest.String()))
	res, err := ImportJSONL(ctx, repo, stream, "", Options{})
	if err != nil || res.FindingsSaved != len(receipts) || res.FindingsFailed != 0 || res.FindingsTotal != len(receipts) {
		t.Fatalf("byte batches: %+v %v", res, err)
	}
	for _, want := range receipts {
		got, err := repo.GetEvidenceExchange(ctx, want.ID, "")
		if err != nil || !bytes.Equal(got.Response, response) || !bytes.Equal(got.Request, []byte("request\x00\xff")) || got.ContentHash != want.ContentHash {
			t.Fatalf("byte-batched receipt %s changed: %v", want.ID, err)
		}
	}
}

func TestImportJSONLFindingBatchTalliesSaveFailures(t *testing.T) {
	repo, ctx := newTestRepo(t), context.Background()
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("request"), []byte("response"), evidence.ProvenanceSupplied)
	var stream strings.Builder
	for i := 0; i < findingFlushBatch; i++ {
		f := importReceiptFinding(fmt.Sprintf("tally-%d", i), x)
		if i == 0 {
			f.Evidence[0].Exchange.Request[0] = 'X' // stale digest: refused, not deduped
		}
		stream.WriteString(jsonlEnvelope(t, "finding", f) + "\n")
	}
	stream.WriteString(jsonlEnvelope(t, "finding", importReceiptFinding("tally-1", x)) + "\n")
	stream.WriteString(jsonlEnvelope(t, "finding", importReceiptFinding("tally-last", x)))
	res, err := ImportJSONL(ctx, repo, strings.NewReader(stream.String()), "", Options{})
	if err != nil || res.FindingsTotal != findingFlushBatch+2 || res.FindingsSaved != findingFlushBatch || res.FindingsSkipped != 1 || res.FindingsFailed != 1 || res.SeverityCounts["high"] != findingFlushBatch+1 {
		t.Fatalf("cross-batch failed/dedup counters: %+v %v", res, err)
	}
	if n := storedImportFindings(t, repo); n != findingFlushBatch {
		t.Fatalf("stored %d findings, want %d", n, findingFlushBatch)
	}
}

func TestImportJSONLSingleOversizeFindingIsNotTruncated(t *testing.T) {
	repo, ctx := newTestRepo(t), context.Background()
	response := bytes.Repeat([]byte{0xff, 0x00}, findingFlushBytes/2)
	x := evidence.NewExchange("https://example.com", "https://example.com/outlier", []byte("request"), response, evidence.ProvenanceCaptured)
	line := jsonlEnvelope(t, "finding", importReceiptFinding("outlier", x)) + "\n"
	stream := io.MultiReader(strings.NewReader(line), &findingImportCheckpoint{check: func() {
		if n := storedImportFindings(t, repo); n != 1 {
			t.Fatalf("outlier must commit alone before EOF: %d findings", n)
		}
	}})
	res, err := ImportJSONL(ctx, repo, stream, "", Options{})
	if err != nil || res.FindingsSaved != 1 {
		t.Fatalf("oversize finding: %+v %v", res, err)
	}
	got, err := repo.GetEvidenceExchange(ctx, x.ID, "")
	if err != nil || !bytes.Equal(got.Response, response) {
		t.Fatalf("outlier receipt truncated: %v", err)
	}
}

func TestImportJSONLFindingBatchesRemainCommittedOnLaterLineError(t *testing.T) {
	repo, ctx := newTestRepo(t), context.Background()
	x := evidence.NewExchange("https://example.com", "https://example.com/a", []byte("request"), []byte("response"), evidence.ProvenanceSupplied)
	var stream strings.Builder
	for i := 0; i < findingFlushBatch; i++ {
		stream.WriteString(jsonlEnvelope(t, "finding", importReceiptFinding(fmt.Sprintf("partial-%d", i), x)) + "\n")
	}
	stream.WriteString(strings.Repeat("x", 8192) + "\n")
	_, err := ImportJSONL(ctx, repo, strings.NewReader(stream.String()), "", Options{MaxLineBytes: 4096})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("(%d findings already committed)", findingFlushBatch)) {
		t.Fatalf("partial import error must describe committed findings: %v", err)
	}
	if n := storedImportFindings(t, repo); n != findingFlushBatch {
		t.Fatalf("earlier batch rolled back: %d findings", n)
	}
}
