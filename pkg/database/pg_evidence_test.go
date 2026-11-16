package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestPg_EvidenceBinaryImmutableAndProjectScoped(t *testing.T) {
	db := openPGTestDB(t) // dedicated disposable database; never an application store
	repo, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://destination.test:8443", "https://attribution.test/probe",
		[]byte("POST /probe HTTP/1.1\r\nHost: virtual.test\r\nContent-Length: 99\r\n\r\n\x00\xff"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n\x00\xff"), evidence.ProvenanceCaptured)
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 123456789, time.UTC)
	primary := evidence.Select(x, evidence.RoleAttack, true, "actual execution")
	primary.OccurrenceID = "occurrence-a"
	f := receiptFinding("pg-binary", "project-a", primary)
	require.NoError(t, repo.SaveFindingDirect(ctx, f))
	got, err := repo.GetEvidenceExchange(ctx, x.ID, "project-a")
	require.NoError(t, err)
	require.Equal(t, x.Request, got.Request)
	require.Equal(t, x.Response, got.Response)
	require.True(t, x.CapturedAt.Equal(got.CapturedAt), "receipt timestamps retain nanoseconds independently of PostgreSQL timestamp precision")
	require.Equal(t, x.Service, got.Service)
	var requestType, responseType string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT pg_typeof(raw_request)::text, pg_typeof(raw_response)::text FROM evidence_exchanges WHERE id = ? AND project_uuid = ?", x.ID, "project-a").Scan(&requestType, &responseType))
	require.Equal(t, "bytea", requestType)
	require.Equal(t, "bytea", responseType)
	_, err = repo.GetEvidenceExchange(ctx, x.ID, "project-b")
	require.ErrorIs(t, err, sql.ErrNoRows)
	manifest, err := repo.GetFindingByID(ctx, f.ID)
	require.NoError(t, err)
	require.Len(t, manifest.Evidence, 1)
	require.Nil(t, manifest.Evidence[0].Exchange, "detail reads must not hydrate a raw corpus")

	for _, change := range []func(*evidence.Exchange){
		func(other *evidence.Exchange) { other.Response = []byte("changed") },
		func(other *evidence.Exchange) { other.CapturedAt = other.CapturedAt.Add(time.Nanosecond) },
	} {
		other := x.Clone()
		change(other)
		other.ContentHash = other.Hash()
		require.Error(t, repo.SaveFindingDirect(ctx, receiptFinding("pg-conflict", "project-a", evidence.Select(other, evidence.RoleAttack, true, "conflict"))))
	}
	require.NoError(t, repo.HydrateFindingEvidenceForExport(ctx, manifest))
	require.Equal(t, x.Request, manifest.Evidence[0].Exchange.Request)
	require.Equal(t, x.Response, manifest.Evidence[0].Exchange.Response)
}
