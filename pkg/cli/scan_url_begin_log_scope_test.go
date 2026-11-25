package cli

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestDirectScanBeginLogScopeRefusesUnvalidatedRows(t *testing.T) {
	oldSilent := globalSilent
	globalSilent = true
	t.Cleanup(func() { globalSilent = oldSilent })
	for _, tc := range []struct {
		name          string
		project       string
		seedForeign   bool
		sharedCreated bool
		failInsert    bool
	}{
		{name: "foreign-creation-collision", project: "project-b", seedForeign: true},
		{name: "foreign-already-shared-row", project: "project-b", seedForeign: true, sharedCreated: true},
		{name: "empty-project-means-default-not-stored-project", seedForeign: true},
		{name: "missing-already-shared-row", project: "project-a", sharedCreated: true},
		{name: "insert-failure", project: "project-a", failInsert: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := newDBAtPath(t, filepath.Join(t.TempDir(), "scope.sqlite"))
			repo := database.NewRepository(db)
			if tc.seedForeign {
				if err := repo.CreateScan(ctx, &database.Scan{
					UUID: "pinned-scan", ProjectUUID: "project-a", Name: "original",
					Status: "pending", Target: "https://original.invalid", AgenticScanUUID: "original-parent",
				}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.failInsert {
				if _, err := db.ExecContext(ctx, `CREATE TRIGGER deny_scan_insert BEFORE INSERT ON scans BEGIN SELECT RAISE(FAIL, 'injected create failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			var before []*database.Scan
			if err := db.NewSelect().Model(&before).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			session := &directScanSession{
				name: database.ScanNameScanURL, pinned: "pinned-scan",
				targets: []string{"https://replacement.invalid"}, sharedCreated: tc.sharedCreated,
			}
			// A failed first input must not mark a pinned row initialized and
			// let a later input bypass the scope check.
			for range 2 {
				if err := session.begin(ctx, repo, tc.project, "pinned-scan", "https://replacement.invalid", "GET", 1, 1); err == nil {
					t.Fatal("unvalidated row initialization must fail closed")
				}
			}
			if session.sharedCreated != tc.sharedCreated || len(session.heartbeats) != 0 {
				t.Fatalf("failed guard initialized session: shared=%v heartbeats=%d", session.sharedCreated, len(session.heartbeats))
			}
			// Query raw logs: ListScanLogs would hide the very malformed rows
			// this regression must prove were never written.
			if n, err := db.NewSelect().Model((*database.ScanLog)(nil)).Count(ctx); err != nil || n != 0 {
				t.Fatalf("failed begin wrote logs: count=%d err=%v", n, err)
			}
			var after []*database.Scan
			if err := db.NewSelect().Model(&after).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("failed begin changed/fabricated scan rows: before=%+v after=%+v", before, after)
			}
		})
	}
}
