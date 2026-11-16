package dbimport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func importPlantingFixture(t *testing.T) (*database.OASTPayload, *database.OASTPlantingReceipt) {
	t.Helper()
	const nonce = "abcdefghijklmnopqrst"
	x := evidence.NewExchange("https://target.test:443", "https://target.test/plant", []byte("GET /?url=http://"+nonce+".cb.test HTTP/1.1\r\n\r\n\xff\x00"), []byte("HTTP/1.1 202 Accepted\r\n\r\n\x00\xff"), evidence.ProvenanceCaptured)
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 987654321, time.UTC)
	data, err := json.Marshal(x)
	require.NoError(t, err)
	p := &database.OASTPayload{Nonce: nonce, ProjectUUID: "project-a", ScanUUID: "scan-a", Class: "xxe", ModuleID: "xxe", TargetURL: x.URL, Param: "url", Payload: "http://" + nonce + ".cb.test", RequestHash: "baseline-only", CreatedAt: x.CapturedAt}
	return p, &database.OASTPlantingReceipt{ProjectUUID: p.ProjectUUID, Nonce: nonce, ScanUUID: p.ScanUUID, Receipt: string(data)}
}

func TestImportOASTPlantingMetadataOnlyBinaryRoundTrip(t *testing.T) {
	for _, order := range []string{"context-first", "receipt-first", "receipt-only"} {
		t.Run(order, func(t *testing.T) {
			repo, ctx := newTestRepo(t), context.Background()
			p, row := importPlantingFixture(t)
			contextLine, receiptLine := jsonlEnvelope(t, "oast_payload", p), jsonlEnvelope(t, "oast_planting_receipt", row)
			lines := contextLine + "\n" + receiptLine
			if order == "receipt-first" {
				lines = receiptLine + "\n" + contextLine
			}
			if order == "receipt-only" {
				lines = receiptLine
			}
			for range 2 {
				res, err := ImportJSONL(ctx, repo, strings.NewReader(lines), p.ProjectUUID, Options{})
				require.NoError(t, err)
				require.Equal(t, 1, res.OASTPlantingReceiptsImported)
				require.Zero(t, res.RecordsImported)
				require.Zero(t, res.FindingsTotal)
			}
			got, err := repo.GetOASTPlantingReceipt(ctx, row.ProjectUUID, row.Nonce, row.ScanUUID)
			require.NoError(t, err)
			x, err := got.Exchange()
			require.NoError(t, err)
			want, err := row.Exchange()
			require.NoError(t, err)
			require.Equal(t, want.Request, x.Request)
			require.Equal(t, want.Response, x.Response)
			require.True(t, want.CapturedAt.Equal(x.CapturedAt))
			require.Equal(t, "scan-a", got.ScanUUID)
			if order != "receipt-only" {
				rows, err := repo.GetOASTPayloadsByNonce(ctx, "project-a", []string{p.Nonce})
				require.NoError(t, err)
				require.Equal(t, p.Payload, rows[p.Nonce].Payload)
				require.Equal(t, p.RequestHash, rows[p.Nonce].RequestHash)
			}
		})
	}
}

func TestImportOASTPlantingRefusesRehomeAndConflicts(t *testing.T) {
	for _, kind := range []string{"oast_payload", "oast_planting_receipt"} {
		t.Run(kind, func(t *testing.T) {
			repo, ctx := newTestRepo(t), context.Background()
			p, row := importPlantingFixture(t)
			var data any = p
			if kind == "oast_planting_receipt" {
				data = row
			}
			line := jsonlEnvelope(t, kind, data)
			_, err := ImportJSONL(ctx, repo, strings.NewReader(line), "project-b", Options{})
			require.ErrorContains(t, err, "cannot be rehomed")
			_, err = ImportJSONL(ctx, repo, strings.NewReader(line), "project-b", Options{PreserveProjectUUID: true})
			require.NoError(t, err)
			p.ScanUUID, row.ScanUUID = "foreign-scan", "foreign-scan"
			line = jsonlEnvelope(t, kind, data)
			_, err = ImportJSONL(ctx, repo, strings.NewReader(line), "project-a", Options{})
			require.ErrorIs(t, err, database.ErrOASTPlantingReceiptConflict)
			if kind == "oast_planting_receipt" {
				var got database.OASTPlantingReceipt
				require.NoError(t, repo.DB().NewSelect().Model(&got).Where("nonce = ?", row.Nonce).Scan(ctx))
				require.Equal(t, "scan-a", got.ScanUUID)
			}
		})
	}
}

func TestImportOASTPlantingRejectsChangedReceiptIdentityBytesAndTime(t *testing.T) {
	for _, mutation := range []string{"identity", "bytes", "time", "cached", "missing-request"} {
		t.Run(mutation, func(t *testing.T) {
			repo, ctx := newTestRepo(t), context.Background()
			_, row := importPlantingFixture(t)
			original := row.Receipt
			_, err := ImportJSONL(ctx, repo, strings.NewReader(jsonlEnvelope(t, "oast_planting_receipt", row)), row.ProjectUUID, Options{})
			require.NoError(t, err)
			x, err := row.Exchange()
			require.NoError(t, err)
			switch mutation {
			case "identity":
				x.ID = "other-execution"
			case "bytes":
				x.Response = append(x.Response, 'x')
			case "time":
				x.CapturedAt = x.CapturedAt.Add(time.Nanosecond)
			case "cached":
				x.Provenance = evidence.ProvenanceCached
			case "missing-request":
				x.Request = nil
				x.RequestState = evidence.StateMissing
			}
			x.ContentHash = x.Hash()
			data, err := json.Marshal(x)
			require.NoError(t, err)
			row.Receipt = string(data)
			_, err = ImportJSONL(ctx, repo, strings.NewReader(jsonlEnvelope(t, "oast_planting_receipt", row)), row.ProjectUUID, Options{})
			require.Error(t, err)
			got, err := repo.GetOASTPlantingReceipt(ctx, row.ProjectUUID, row.Nonce, row.ScanUUID)
			require.NoError(t, err)
			require.JSONEq(t, original, got.Receipt)
		})
	}
}

func TestImportOASTPlantingDeclaredSlotValidationInEitherOrder(t *testing.T) {
	for _, surface := range []string{"query", "form", "header"} {
		for _, wrong := range []bool{false, true} {
			for _, receiptFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/wrong=%v/receiptFirst=%v", surface, wrong, receiptFirst), func(t *testing.T) {
					repo, ctx := newTestRepo(t), context.Background()
					p, row := importPlantingFixture(t)
					field := p.Param
					if surface == "header" {
						p.Param, p.InjectionType = "X-OAST", "explicit header injection"
						field = p.Param
					}
					if wrong {
						field = "other"
					}
					x, err := row.Exchange()
					require.NoError(t, err)
					switch surface {
					case "query":
						x.Request = []byte("GET /?" + field + "=" + url.QueryEscape(p.Payload) + " HTTP/1.1\r\nHost: target.test\r\n\r\n")
					case "form":
						body := field + "=" + url.QueryEscape(p.Payload)
						x.Request = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
					case "header":
						x.Request = []byte("GET / HTTP/1.1\r\nHost: target.test\r\n" + field + ": " + p.Payload + "\r\n\r\n")
					}
					x.ContentHash = x.Hash()
					data, err := json.Marshal(x)
					require.NoError(t, err)
					row.Receipt = string(data)
					first, second := jsonlEnvelope(t, "oast_payload", p), jsonlEnvelope(t, "oast_planting_receipt", row)
					if receiptFirst {
						first, second = second, first
					}
					_, err = ImportJSONL(ctx, repo, strings.NewReader(first), row.ProjectUUID, Options{})
					require.NoError(t, err)
					_, err = ImportJSONL(ctx, repo, strings.NewReader(second), row.ProjectUUID, Options{})
					if wrong {
						require.ErrorIs(t, err, database.ErrOASTPlantingReceiptConflict)
						return
					}
					require.NoError(t, err)
					got, err := repo.GetOASTPlantingReceipt(ctx, row.ProjectUUID, row.Nonce, row.ScanUUID)
					require.NoError(t, err)
					proof, err := got.Exchange()
					require.NoError(t, err)
					require.Equal(t, x.Request, proof.Request)
					require.Equal(t, x.Response, proof.Response)
					require.True(t, x.CapturedAt.Equal(proof.CapturedAt))
				})
			}
		}
	}
}

func TestImportOASTPlantingCannotAdoptForeignNonceContext(t *testing.T) {
	for _, receiptFirst := range []bool{true, false} {
		repo, ctx := newTestRepo(t), context.Background()
		p, row := importPlantingFixture(t)
		p.ProjectUUID = "foreign"
		first, second := jsonlEnvelope(t, "oast_payload", p), jsonlEnvelope(t, "oast_planting_receipt", row)
		if receiptFirst {
			first, second = second, first
		}
		_, err := ImportJSONL(ctx, repo, strings.NewReader(first), "scratch", Options{PreserveProjectUUID: true})
		require.NoError(t, err)
		_, err = ImportJSONL(ctx, repo, strings.NewReader(second), "scratch", Options{PreserveProjectUUID: true})
		require.ErrorIs(t, err, database.ErrOASTPlantingReceiptConflict)
	}
}
