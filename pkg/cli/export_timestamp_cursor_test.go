package cli

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

// CURRENT_TIMESTAMP and Bun's UTC timestamps can encode the same instant with
// different text keys. Export cursors must retain the query's exact ordering and
// finish without repeating a row, including with one connection and hydration.
func TestExportTimestampCursorsKeepStoredSQLiteKeys(t *testing.T) {
	resetGeneralExportSpoolFlags(t)
	topExportNoURLDedup = true
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	keys := []string{
		"2026-01-01 00:00:00",
		"2026-01-01 00:00:00", // same stored timestamp, different identity
		"2026-01-01 00:00:00.000000+00:00",
		"2026-01-01 00:00:00.123456789+00:00",
		"2025-12-31 23:59:59",
	}
	repo := database.NewRepository(db)
	for i, key := range keys {
		suffix := fmt.Sprintf("cursor-%d", i)
		seedSelectedEvidenceDBRecord(t, db, suffix)
		_, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).
			Set("created_at = ?", key).Where("uuid = ?", "rec-"+suffix).Exec(ctx)
		require.NoError(t, err)
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: suffix, ModuleID: "test", Severity: "high", HTTPRecordUUIDs: []string{"rec-" + suffix}}
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
		_, err = db.NewUpdate().Model((*database.Finding)(nil)).
			Set("found_at = ?", key).Where("id = ?", f.ID).Exec(ctx)
		require.NoError(t, err)
	}
	filters := database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}
	wantRecords, err := database.NewQueryBuilder(db, filters).Execute(ctx)
	require.NoError(t, err)
	wantUUIDs := make([]string, 0, len(wantRecords))
	for _, record := range wantRecords {
		wantUUIDs = append(wantUUIDs, record.UUID)
	}
	require.Len(t, wantUUIDs, len(keys))
	for _, omit := range []bool{false, true} {
		t.Run(fmt.Sprintf("http-omit-%t", omit), func(t *testing.T) {
			var got []string
			err := streamHTTPRecords(ctx, db, exportQuery{omitResponse: omit, projectUUID: database.DefaultProjectUUID}, func(kind string, item any) error {
				require.Equal(t, "http_record", kind)
				var record *database.HTTPRecord
				switch row := item.(type) {
				case *database.HTTPRecord:
					record = row
				case database.RecordWithHostFacts:
					record = row.Record
				default:
					return fmt.Errorf("unexpected HTTP export type %T", item)
				}
				got = append(got, record.UUID)
				if len(got) > len(keys) {
					return fmt.Errorf("HTTP cursor repeated a row: %v", got)
				}
				if omit {
					require.Empty(t, record.RawRequest)
					require.Empty(t, record.RawResponse)
				} else {
					require.NotEmpty(t, record.RawRequest)
					require.NotEmpty(t, record.RawResponse)
				}
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, wantUUIDs, got)
		})
	}
	for _, asc := range []bool{false, true} {
		t.Run(fmt.Sprintf("finding-asc-%t", asc), func(t *testing.T) {
			order := "DESC"
			if asc {
				order = "ASC"
			}
			q := db.NewSelect().Model((*database.Finding)(nil)).
				Where("project_uuid = ?", database.DefaultProjectUUID).
				OrderExpr("found_at " + order + ", id " + order)
			var want []*database.Finding
			require.NoError(t, q.Clone().Scan(ctx, &want))
			wantIDs := make([]int64, 0, len(want))
			for _, f := range want {
				wantIDs = append(wantIDs, f.ID)
			}
			var got []int64
			err := iterateEvidenceFindings(ctx, db, q, asc, 0, func(f *database.Finding) error {
				got = append(got, f.ID)
				if len(got) > len(keys) {
					return fmt.Errorf("finding cursor repeated a row: %v", got)
				}
				require.Len(t, f.HTTPRecordUUIDs, 1, "hydration runs only after the cursor closes")
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, wantIDs, got)
		})
	}
}
