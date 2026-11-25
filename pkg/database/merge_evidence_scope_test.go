package database

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/evidence"
)

// seedReceiptSource writes a source with one finding per host, each carrying a
// selected receipt whose request holds a session cookie, and returns its path.
func seedReceiptSource(t *testing.T) string {
	t.Helper()
	src, srcPath := newFileDB(t, "receipts-src.sqlite")
	repo := NewRepository(src)
	ctx := context.Background()
	for _, host := range []string{"app.example.com", "api.other.test"} {
		url := "https://" + host + "/a"
		x := evidence.NewExchange("https://"+host+":443", url,
			[]byte("GET /a HTTP/1.1\r\nHost: "+host+"\r\nCookie: session=secret-"+host+"\r\n\r\n"),
			[]byte("HTTP/1.1 200 OK\r\n\r\nok"), evidence.ProvenanceCaptured)
		f := &Finding{ProjectUUID: DefaultProjectUUID, FindingHash: "fh-" + host, ModuleID: "m", ModuleName: "M",
			Severity: "low", URL: url, Hostname: host, EvidenceStatus: "selected",
			Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "proof")}}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatalf("save %s: %v", host, err)
		}
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	return srcPath
}

func mergedReceiptBytes(t *testing.T, db *DB) (rows int64, corpus string) {
	t.Helper()
	rows = scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges")
	var parts []string
	if err := db.NewRaw("SELECT CAST(COALESCE(raw_request, X'') AS TEXT) FROM evidence_exchanges").Scan(context.Background(), &parts); err != nil {
		t.Fatal(err)
	}
	return rows, strings.Join(parts, "\n")
}

// A host-filtered merge copies only the receipts the kept findings select; raw
// exchanges about excluded hosts never reach the destination.
func TestMergeHostFilterKeepsOnlySelectedHostsReceipts(t *testing.T) {
	srcPath := seedReceiptSource(t)
	dest, _ := newFileDB(t, "dest.sqlite")
	if _, err := MergeSQLiteFileWithOptions(context.Background(), dest, srcPath, MergeOptions{Hosts: []string{"app.example.com"}}); err != nil {
		t.Fatal(err)
	}
	rows, corpus := mergedReceiptBytes(t, dest)
	if rows != 1 || !strings.Contains(corpus, "app.example.com") {
		t.Fatalf("kept host receipts: rows=%d corpus=%q", rows, corpus)
	}
	if strings.Contains(corpus, "api.other.test") {
		t.Fatal("a receipt about an excluded host was merged")
	}
}

// Receipts are immutable records of what was sent, so they cannot be masked.
// A redacting merge withholds their bytes and keeps the association, which
// readers report as an unavailable receipt; no credential is ever copied.
func TestMergeRedactionWithholdsReceiptBytes(t *testing.T) {
	srcPath := seedReceiptSource(t)
	dest, _ := newFileDB(t, "dest.sqlite")
	if _, err := MergeSQLiteFileWithOptions(context.Background(), dest, srcPath, MergeOptions{RedactCredentials: true}); err != nil {
		t.Fatal(err)
	}
	rows, corpus := mergedReceiptBytes(t, dest)
	if rows != 0 || strings.Contains(corpus, "secret-") {
		t.Fatalf("redacting merge copied receipts: rows=%d corpus=%q", rows, corpus)
	}
	if n := scalarInt(t, dest, "SELECT COUNT(*) FROM finding_evidence"); n != 2 {
		t.Fatalf("finding_evidence associations = %d, want 2 kept as manifests", n)
	}
}
