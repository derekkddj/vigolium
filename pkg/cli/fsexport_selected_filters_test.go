package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestFindingSelectedEvidenceFSSharedScanDateOffsetAndReferenceUnion(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	seedRecordWithBodies(t, db, "one")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	for i, tc := range []struct {
		project, scan string
		at            time.Time
		array         bool
	}{
		{database.DefaultProjectUUID, "wrong-scan", start, true},
		{database.DefaultProjectUUID, "wanted-scan", start.Add(time.Hour), true},
		{database.DefaultProjectUUID, "wanted-scan", start.Add(2 * time.Hour), false},
		{database.DefaultProjectUUID, "wanted-scan", end.Add(time.Hour), true},
		{"foreign", "wanted-scan", start.Add(3 * time.Hour), true},
	} {
		f := &database.Finding{ProjectUUID: tc.project, FindingHash: fmt.Sprintf("filter-%d", i), ModuleID: fmt.Sprintf("module-%d", i), RecordKind: database.RecordKindFinding, ScanUUID: tc.scan, FoundAt: tc.at, CreatedAt: tc.at, Severity: "high", Hostname: "one.example", URL: "http://one.example/one"}
		if tc.array {
			f.HTTPRecordUUIDs = []string{"rec-one"}
		}
		_, err := db.NewInsert().Model(f).Exec(ctx)
		require.NoError(t, err)
		if !tc.array {
			_, err := db.ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)", f.ID, "rec-one")
			require.NoError(t, err)
		}
	}
	filters := database.QueryFilters{ProjectUUID: database.DefaultProjectUUID, ScanUUID: "wanted-scan", DateFrom: &start, DateTo: &end, RecordUUIDs: []string{"rec-one"}, SortBy: "found_at", SortAsc: true, Offset: 1, Limit: 1}
	var got []*database.Finding
	require.NoError(t, iterateFilteredEvidenceFindings(ctx, db, filters, func(f *database.Finding) error { got = append(got, f); return nil }))
	require.Len(t, got, 1)
	require.Equal(t, "module-2", got[0].ModuleID)
	require.Equal(t, []string{"rec-one"}, got[0].HTTPRecordUUIDs, "junction-only refs must be exposed too")
	base := filepath.Join(t.TempDir(), "filtered")
	stats, err := writeFSExport(ctx, db, filters, base, fsExportOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, stats.Findings)
	var index []map[string]any
	readJSON(t, filepath.Join(base+"-findings", "index.json"), &index)
	require.Len(t, index, 1)
	require.Equal(t, "module-2", index[0]["module"])
	filters.Offset, filters.Limit = 0, 0
	got = nil
	require.NoError(t, iterateFilteredEvidenceFindings(ctx, db, filters, func(f *database.Finding) error { got = append(got, f); return nil }))
	require.Len(t, got, 2, "array-only and junction-only representations both match before pagination")
}

func TestFindingSelectedEvidenceFSCrossProjectLegacyRefDoesNotHydrateForeignTraffic(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	ctx := context.Background()
	seedRecordWithBodies(t, db, "foreign")
	_, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).Set("project_uuid = ?", "foreign-project").Where("uuid = ?", "rec-foreign").Exec(ctx)
	require.NoError(t, err)
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "foreign-soft-ref", ModuleID: "test", Hostname: "own.example", HTTPRecordUUIDs: []string{"rec-foreign"}}
	_, err = db.NewInsert().Model(f).Exec(ctx) // legacy stores may retain foreign soft identities
	require.NoError(t, err)
	base := filepath.Join(t.TempDir(), "export")
	_, err = writeFSExport(ctx, db, database.QueryFilters{}, base, fsExportOptions{})
	require.NoError(t, err)
	var index []map[string]any
	readJSON(t, filepath.Join(base+"-findings", "index.json"), &index)
	require.Len(t, index, 1)
	traffic, _ := index[0]["traffic"].([]any)
	require.Empty(t, traffic, "all-project export must not attach another project's bytes to this finding")
}

func TestFindingSelectedEvidenceFilteredIteratorPaginatesMetadataWithoutRepeatingOffset(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	ctx := context.Background()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 70 {
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("page-%d", i), ModuleID: "test", FoundAt: at, CreatedAt: at}
		_, err := db.NewInsert().Model(f).Exec(ctx)
		require.NoError(t, err)
	}
	seen := map[int64]bool{}
	filters := database.QueryFilters{ProjectUUID: database.DefaultProjectUUID, SortBy: "found_at", SortAsc: true, Offset: 2}
	require.NoError(t, iterateFilteredEvidenceFindings(ctx, db, filters, func(f *database.Finding) error {
		require.False(t, seen[f.ID])
		seen[f.ID] = true
		return nil
	}))
	require.Len(t, seen, 68)
	q := db.NewSelect().Model((*database.Finding)(nil)).OrderExpr("found_at ASC, id ASC").Offset(2)
	seen = map[int64]bool{}
	require.NoError(t, iterateEvidenceFindings(ctx, db, q, true, 0, func(f *database.Finding) error {
		require.False(t, seen[f.ID])
		seen[f.ID] = true
		return nil
	}))
	require.Len(t, seen, 68, "initial offset must not be reapplied on every keyset page")
}
