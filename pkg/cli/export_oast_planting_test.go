package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dbimport"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
)

func seedPendingPlanting(t *testing.T, db *database.DB, project, nonce, scan string) *evidence.Exchange {
	t.Helper()
	ctx := context.Background()
	x := evidence.NewExchange("https://target.test:443", "https://target.test/plant", []byte("POST /plant HTTP/1.1\r\nHost: target.test\r\n\r\nentity=http://"+nonce+".cb.test/\x00\xff"), []byte("HTTP/1.1 202 Accepted\r\n\r\nRAW-PLANTING-MARKER\xff\x00"), evidence.ProvenanceCaptured)
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 123456789, time.UTC)
	repo := database.NewRepository(db)
	require.NoError(t, repo.SaveOASTPayloads(ctx, []*database.OASTPayload{{Nonce: nonce, ProjectUUID: project, ScanUUID: scan, Class: "xxe", ModuleID: "xxe", TargetURL: x.URL, Param: "body", Payload: "http://" + nonce + ".cb.test/", RequestHash: "baseline-hash-not-proof", CreatedAt: x.CapturedAt}}))
	data, err := json.Marshal(x)
	require.NoError(t, err)
	require.NoError(t, repo.SaveOASTPlantingReceipt(ctx, &database.OASTPlantingReceipt{ProjectUUID: project, Nonce: nonce, ScanUUID: scan, Receipt: string(data)}))
	return x
}

func TestExportPendingOASTActualTableRoundTripAndLateCallback(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	topExportOnly = []string{"oast"}
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx := context.Background()
	const nonce = "abcdefghijklmnopqrst"
	x := seedPendingPlanting(t, db, "project-a", nonce, "scan-a")
	seedPendingPlanting(t, db, "project-a", "uvwxyzabcdefghijklmn", "scan-b")
	seedPendingPlanting(t, db, "project-b", "nopqrstuvwxyzabcdefg", "scan-a")
	spool, err := newExportSpool(func(emit func(any) error) error {
		return streamExportData(ctx, db, exportQuery{scope: topExportScope(), projectUUID: "project-a", scanUUID: "scan-a"}, emit)
	})
	require.NoError(t, err)
	defer spool.close()
	require.Equal(t, 1, spool.counts.byType["oast_payload"])
	require.Equal(t, 1, spool.counts.byType["oast_planting_receipt"])
	require.Equal(t, 2, spool.counts.total, "no crawl traffic/findings are required")
	var data bytes.Buffer
	require.NoError(t, spool.copyJSONL(&data))
	require.NotContains(t, data.String(), "project-b")
	require.NotContains(t, data.String(), "scan-b")
	report, err := os.ReadFile(spool.report.Name())
	require.NoError(t, err)
	require.NotContains(t, string(report), base64.StdEncoding.EncodeToString(x.Request))
	require.NotContains(t, string(report), base64.StdEncoding.EncodeToString(x.Response))
	require.NotContains(t, string(report), `"receipt":`)
	require.Contains(t, string(report), `"exchange_manifest":`)
	require.Contains(t, string(report), `"raw_traffic_source":`)

	dest := newDBAtPath(t, ":memory:")
	repo := database.NewRepository(dest)
	res, err := dbimport.ImportJSONL(ctx, repo, bytes.NewReader(data.Bytes()), "project-a", dbimport.Options{})
	require.NoError(t, err)
	require.Equal(t, 1, res.OASTPlantingReceiptsImported)
	in := server.Interaction{UniqueID: nonce, Protocol: "http", RawRequest: "GET / HTTP/1.1\r\nHost: " + nonce + ".cb.test\r\n\r\n", RawResponse: "HTTP/1.1 204 No Content\r\n\r\n", Timestamp: x.CapturedAt.Add(time.Second)}
	callback := []oast.Callback{{Interaction: in, Where: []string{nonce + ".cb.test"}}}
	foreign, err := oast.Ingest(ctx, repo, "project-b", callback)
	require.NoError(t, err)
	require.Empty(t, foreign.Findings)
	late, err := oast.Ingest(ctx, repo, "project-a", callback)
	require.NoError(t, err)
	require.Len(t, late.Findings, 1)
	finding, err := repo.GetFindingByHash(ctx, late.Findings[0].FindingHash, "project-a")
	require.NoError(t, err)
	require.NoError(t, repo.HydrateFindingEvidenceForExport(ctx, finding))
	var proof *evidence.Exchange
	for _, entry := range finding.Evidence {
		if entry.Primary {
			require.Equal(t, evidence.RoleAttack, entry.Role)
			proof = entry.Exchange
		}
	}
	require.NotNil(t, proof)
	require.Equal(t, x.ID, proof.ID)
	require.Equal(t, x.Request, proof.Request)
	require.Equal(t, x.Response, proof.Response)
	require.True(t, x.CapturedAt.Equal(proof.CapturedAt))
	require.Equal(t, "scan-a", finding.ScanUUID)
}

func TestPendingOASTImportReceiptsAndChangeDetection(t *testing.T) {
	res := &dbimport.Result{OASTPayloadsImported: 1, OASTPlantingReceiptsImported: 2}
	require.True(t, importChanged(res))
	data := importResultJSON("pending.jsonl", res)
	require.Equal(t, 1, data["oast_payloads_imported"])
	require.Equal(t, 2, data["oast_planting_receipts_imported"])
	res = &dbimport.Result{MergeStats: &database.MergeStats{OASTPlantingReceiptsMerged: 3}}
	require.True(t, importChanged(res))
	data = importResultJSON("pending.db", res)
	require.Equal(t, 3, data["oast_planting_receipts_merged"])
}

func TestDBBundlePendingOASTUsesRawFreeReportSpool(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	x := seedPendingPlanting(t, db, "project-a", "abcdefghijklmnopqrst", "scan-a")
	original := renderDBBundleHTML
	t.Cleanup(func() { renderDBBundleHTML = original })
	renderDBBundleHTML = func(produce output.ReportItemProducer, path string, _ output.HTMLReportMeta) error {
		if err := produce(func(item any) error {
			data, err := json.Marshal(item)
			if err != nil {
				return err
			}
			require.NotContains(t, string(data), base64.StdEncoding.EncodeToString(x.Response))
			require.NotContains(t, string(data), `"receipt":`)
			return nil
		}); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("raw-free report"), 0o600)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	stats, err := writeDBBundleMembers(context.Background(), db, "project-a", tw)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.Equal(t, 1, stats.counts["oast_payload"])
	require.Equal(t, 1, stats.counts["oast_planting_receipt"])
	members := map[string][]byte{}
	tr := tar.NewReader(&archive)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		members[h.Name], err = io.ReadAll(tr)
		require.NoError(t, err)
	}
	require.Contains(t, string(members["data.jsonl"]), base64.StdEncoding.EncodeToString(x.Response))
	dest := newDBAtPath(t, ":memory:")
	res, err := dbimport.ImportJSONL(context.Background(), database.NewRepository(dest), bytes.NewReader(members["data.jsonl"]), "project-a", dbimport.Options{})
	require.NoError(t, err)
	require.Equal(t, 1, res.OASTPlantingReceiptsImported)
}
