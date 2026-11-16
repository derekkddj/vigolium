package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestGenericEvidenceStorageAccessDenied(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://example.com:443", "https://example.com/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	f := receiptFinding("generic-denial", DefaultProjectUUID, evidence.Select(x, evidence.RoleAttack, true, "proof"))
	require.NoError(t, repo.SaveFindingDirect(ctx, f))

	for _, table := range []string{"evidence_exchanges", "finding_evidence"} {
		t.Run(table, func(t *testing.T) {
			// Metadata discovery is allowed, but no generic record operation is.
			require.NoError(t, ValidateTableName(ctx, db, table))
			columns, err := ListColumns(ctx, db, table)
			require.NoError(t, err)
			require.NotEmpty(t, columns)
			_, _, _, err = QueryGenericTable(ctx, db, table, 100, 0)
			require.ErrorIs(t, err, ErrGenericTableAccessDenied)
			_, _, _, err = QueryGenericTableFiltered(ctx, db, table, GenericQueryOptions{Columns: []string{"id"}})
			require.ErrorIs(t, err, ErrGenericTableAccessDenied)
			_, err = GetGenericRecord(ctx, db, table, "1")
			require.ErrorIs(t, err, ErrGenericTableAccessDenied)
			require.ErrorIs(t, InsertGenericRecord(ctx, db, table, map[string]interface{}{"raw_request": "changed"}), ErrGenericTableAccessDenied)
			require.ErrorIs(t, UpdateGenericRecord(ctx, db, table, "1", map[string]interface{}{"label": "changed"}), ErrGenericTableAccessDenied)
			require.ErrorIs(t, DeleteGenericRecord(ctx, db, table, "1"), ErrGenericTableAccessDenied)
		})
	}
	got, err := repo.GetEvidenceExchange(ctx, x.ID, DefaultProjectUUID)
	require.NoError(t, err)
	require.Equal(t, x.Request, got.Request)
	require.Equal(t, x.Response, got.Response)
	require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence WHERE finding_id = ?", f.ID))
}

func TestGenericHTTPRecordMutationProtectsCapturedExchange(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	id := insertRecordP(t, repo, DefaultProjectUUID, "GET", "generic.test", "/original", 200)
	before, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	columns, err := ListColumns(ctx, db, "http_records")
	require.NoError(t, err)
	for _, column := range columns {
		if column.Name == "uuid" || isGenericRecordMetadataColumn(column.Name) {
			continue
		}
		t.Run(column.Name, func(t *testing.T) {
			// A forbidden field rejects the entire update, including safe fields.
			err := UpdateGenericRecord(ctx, db, "http_records", id, map[string]interface{}{column.Name: "changed", "risk_score": 99})
			require.ErrorIs(t, err, ErrImmutableRecordExchange)
		})
	}
	after, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.ErrorIs(t, InsertGenericRecord(ctx, db, "http_records", map[string]interface{}{"uuid": "unsupported", "raw_request": "supplied"}), ErrGenericInsertUnsupported)
	require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM http_records"))

	require.NoError(t, UpdateGenericRecord(ctx, db, "http_records", id, map[string]interface{}{
		"risk_score": 12, "surface_score": 34, "parent_uuid": "parent", "root_uuid": "root",
		"target": "https://generic.test/input", "chain_truncated": true, "remarks": `["reviewed"]`,
	}))
	after, err = repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, 12, after.RiskScore)
	require.Equal(t, 34, after.SurfaceScore)
	require.Equal(t, "parent", after.ParentUUID)
	require.Equal(t, "root", after.RootUUID)
	require.Equal(t, []string{"reviewed"}, after.Remarks)
	require.Equal(t, before.RawRequest, after.RawRequest)
	require.Equal(t, before.RawResponse, after.RawResponse)
	require.Equal(t, before.URL, after.URL)
	require.Equal(t, before.RequestHash, after.RequestHash)
	require.Equal(t, before.ResponseHash, after.ResponseHash)
}

func TestGenericFindingDeletionDropsAssociationsRetainsRaw(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://example.com:443", "https://example.com/proof", []byte("request"), []byte("response"), evidence.ProvenanceCaptured)
	f := receiptFinding("generic-delete", DefaultProjectUUID, evidence.Select(x, evidence.RoleAttack, true, "proof"))
	require.NoError(t, repo.SaveFindingDirect(ctx, f))
	require.NoError(t, DeleteGenericRecord(ctx, db, "findings", fmt.Sprint(f.ID)))
	for _, table := range findingChildTables {
		require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE finding_id = ?", f.ID), table)
	}
	got, err := repo.GetEvidenceExchange(ctx, x.ID, DefaultProjectUUID)
	require.NoError(t, err)
	require.Equal(t, x.Response, got.Response)
}
