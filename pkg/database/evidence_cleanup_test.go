package database

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestDeleteOrphansPreservesReceiptOnlyAndUnavailableEvidence(t *testing.T) {
	for _, project := range []string{"", "project-a"} {
		t.Run("scope="+project, func(t *testing.T) {
			db := newTestDB(t)
			repo, ctx := NewRepository(db), context.Background()
			x := evidence.NewExchange("https://example.com:443", "https://example.com/proof", []byte("request"), []byte("response"), evidence.ProvenanceCaptured)
			selected := receiptFinding("receipt-only", "project-a", evidence.Select(x, evidence.RoleAttack, true, "proof"))
			unavailable := receiptFinding("unavailable", "project-a", evidence.Entry{ExchangeID: "unavailable-receipt", Role: evidence.RoleAttack, Primary: true})
			orphan := receiptFinding("orphan", "project-a")
			foreignOrphan := receiptFinding("foreign-orphan", "project-b")
			for _, f := range []*Finding{selected, unavailable, orphan, foreignOrphan} {
				require.NoError(t, repo.SaveFindingDirect(ctx, f))
			}
			clean := NewDeleteBuilder(db, QueryFilters{ProjectUUID: project})
			want := int64(1)
			if project == "" {
				want = 2
			}
			n, err := clean.DeleteOrphans(ctx, true)
			require.NoError(t, err)
			require.Equal(t, want, n)
			require.Equal(t, int64(4), scalarInt(t, db, "SELECT COUNT(*) FROM findings"))
			n, err = clean.DeleteOrphans(ctx, false)
			require.NoError(t, err)
			require.Equal(t, want, n)
			for _, f := range []*Finding{selected, unavailable} {
				got, err := repo.GetFindingByID(ctx, f.ID)
				require.NoError(t, err)
				require.Len(t, got.Evidence, 1)
			}
			if project != "" {
				_, err := repo.GetFindingByID(ctx, foreignOrphan.ID)
				require.NoError(t, err)
			}
			for _, table := range findingChildTables {
				require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM "+table+" WHERE finding_id = ?", orphan.ID), table)
			}
		})
	}
}

func TestRecordCleanupPreservesSelectedReceiptFinding(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	id := insertRecordP(t, repo, DefaultProjectUUID, "GET", "cleanup.test", "/baseline", 200)
	x := evidence.NewExchange("https://cleanup.test:443", "https://cleanup.test/proof", []byte("request"), []byte("response"), evidence.ProvenanceCaptured)
	f := receiptFinding("selected-and-legacy", DefaultProjectUUID, evidence.Select(x, evidence.RoleAttack, true, "proof"))
	f.HTTPRecordUUIDs = []string{id}
	require.NoError(t, repo.SaveFindingDirect(ctx, f))
	n, err := NewDeleteBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID}).DeleteRecords(ctx, false)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
	got, err := repo.GetFindingByID(ctx, f.ID)
	require.NoError(t, err)
	require.Len(t, got.Evidence, 1)
}

func TestEvidenceCleanupScopedTablesAndRawRetention(t *testing.T) {
	for _, table := range []string{"findings", "finding_evidence", "evidence_exchanges"} {
		t.Run(table, func(t *testing.T) {
			db := newTestDB(t)
			repo, ctx := NewRepository(db), context.Background()
			x := evidence.NewExchange("https://cleanup.test:443", "https://cleanup.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
			a := receiptFinding("cleanup-a", "project-a", evidence.Select(x, evidence.RoleAttack, true, "proof"))
			b := receiptFinding("cleanup-b", "project-b", evidence.Select(x, evidence.RoleControl, true, "foreign"))
			for _, f := range []*Finding{a, b} {
				require.NoError(t, repo.SaveFindingDirect(ctx, f))
			}
			clean := NewDeleteBuilder(db, QueryFilters{ProjectUUID: "project-a"})
			n, err := clean.DeleteTable(ctx, table, true)
			require.NoError(t, err)
			require.Equal(t, int64(1), n)
			require.Equal(t, int64(2), scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges"))
			n, err = clean.DeleteTable(ctx, table, false)
			require.NoError(t, err)
			require.Equal(t, int64(1), n)
			foreign, err := repo.GetFindingByID(ctx, b.ID)
			require.NoError(t, err)
			require.Len(t, foreign.Evidence, 1)
			foreignRaw, err := repo.GetEvidenceExchange(ctx, x.ID, "project-b")
			require.NoError(t, err)
			require.Equal(t, x.Response, foreignRaw.Response)
			if table == "evidence_exchanges" {
				_, err := repo.GetEvidenceExchange(ctx, x.ID, "project-a")
				require.ErrorIs(t, err, sql.ErrNoRows)
				kept, err := repo.GetFindingByID(ctx, a.ID)
				require.NoError(t, err)
				require.Len(t, kept.Evidence, 1)
				n, err := clean.DeleteOrphans(ctx, true)
				require.NoError(t, err)
				require.Zero(t, n, "unavailable raw must not make selected finding orphaned")
			} else {
				_, err := repo.GetEvidenceExchange(ctx, x.ID, "project-a")
				require.NoError(t, err, "association/finding cleanup must retain raw")
				require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM finding_evidence WHERE finding_id = ?", a.ID))
				if table == "findings" {
					for _, child := range findingChildTables {
						require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM "+child+" WHERE finding_id = ?", a.ID), child)
					}
				}
				n, err := clean.DeleteTable(ctx, "evidence_exchanges", false)
				require.NoError(t, err)
				require.Equal(t, int64(1), n)
			}
		})
	}
}

func TestEvidenceFullCleanupCountsRawAndPreservesOtherProject(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	x := evidence.NewExchange("https://cleanup.test:443", "https://cleanup.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	var foreignFindingID int64
	for _, project := range []string{"project-a", "project-b"} {
		f := receiptFinding("full-cleanup", project, evidence.Select(x, evidence.RoleAttack, true, project))
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
		if project == "project-b" {
			foreignFindingID = f.ID
		}
		recordID := insertRecordP(t, repo, project, "GET", "cleanup.test", "/"+project, 200)
		artifact := &AnalysisArtifact{ProjectUUID: project, HTTPRecordUUID: recordID, Kind: "derived", SHA256: "hash", ByteLength: 3, Content: []byte("raw")}
		_, err := db.NewInsert().Model(artifact).Exec(ctx)
		require.NoError(t, err)
	}
	order := AllTablesDeleteOrder()
	require.Contains(t, order, "finding_evidence")
	require.Contains(t, order, "evidence_exchanges")
	scoped := NewDeleteBuilder(db, QueryFilters{ProjectUUID: "project-a"})
	counts, err := scoped.DeleteAllTables(ctx, true)
	require.NoError(t, err)
	for _, table := range []string{"finding_evidence", "evidence_exchanges", "findings", "http_records", "analysis_artifacts"} {
		require.Equal(t, int64(1), counts[table], table)
		require.Equal(t, int64(2), scalarInt(t, db, "SELECT COUNT(*) FROM "+table), table)
	}
	deleted, err := scoped.DeleteAllTables(ctx, false)
	require.NoError(t, err)
	require.Equal(t, counts, deleted)
	for _, table := range []string{"finding_evidence", "evidence_exchanges", "findings", "http_records", "analysis_artifacts"} {
		require.Equal(t, int64(1), scalarInt(t, db, "SELECT COUNT(*) FROM "+table), table)
	}
	foreignManifest, err := repo.GetFindingByID(ctx, foreignFindingID)
	require.NoError(t, err)
	require.Equal(t, "project-b", foreignManifest.ProjectUUID)
	require.Len(t, foreignManifest.Evidence, 1)
	require.Equal(t, "project-b", foreignManifest.Evidence[0].Label)
	foreign, err := repo.GetEvidenceExchange(ctx, x.ID, "project-b")
	require.NoError(t, err)
	require.Equal(t, x.Request, foreign.Request)
	require.Equal(t, x.Response, foreign.Response)

	all := NewDeleteBuilder(db, QueryFilters{})
	counts, err = all.DeleteAllTables(ctx, true)
	require.NoError(t, err)
	require.Equal(t, int64(1), counts["evidence_exchanges"])
	require.Equal(t, int64(1), counts["finding_evidence"])
	deleted, err = all.DeleteAllTables(ctx, false)
	require.NoError(t, err)
	require.Equal(t, counts, deleted)
	for _, table := range order {
		require.Zero(t, scalarInt(t, db, "SELECT COUNT(*) FROM "+table), table)
	}
}
