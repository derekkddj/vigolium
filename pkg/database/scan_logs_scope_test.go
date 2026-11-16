package database

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestListScanLogsStoredProjectScopeAndPagination(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScan(ctx, &Scan{UUID: "scan-a", ProjectUUID: "project-a", Name: "scan", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScan(ctx, &Scan{UUID: "scan-b", ProjectUUID: "project-b", Name: "scan", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0).UTC()
	// Deliberately insert out of timestamp order, with interleaved legacy
	// foreign/default-project logs and a tie between two valid log timestamps.
	entries := []*ScanLog{
		{ProjectUUID: "project-a", ScanUUID: "scan-a", Level: "warn", Phase: "scan", Message: "second", CreatedAt: at.Add(time.Second)},
		{ProjectUUID: "project-b", ScanUUID: "scan-a", Level: "warn", Phase: "scan", Message: "foreign", CreatedAt: at},
		{ProjectUUID: "project-a", ScanUUID: "scan-a", Level: "info", Phase: "discovery", Message: "first", CreatedAt: at},
		{ProjectUUID: "project-a", ScanUUID: "scan-a", Level: "warn", Phase: "scan", Message: "third", CreatedAt: at.Add(time.Second)},
		{ProjectUUID: "", ScanUUID: "scan-a", Level: "warn", Phase: "scan", Message: "legacy-default", CreatedAt: at.Add(2 * time.Second)},
		{ProjectUUID: "project-a", ScanUUID: "scan-a", Level: "warn", Phase: "scan", Message: "fourth", CreatedAt: at.Add(3 * time.Second)},
		{ProjectUUID: "project-b", ScanUUID: "scan-b", Level: "warn", Phase: "scan", Message: "other-scan", CreatedAt: at},
	}
	if err := repo.CreateScanLogBatch(ctx, entries); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, level, phase string
		limit, offset      int
		total              int64
		messages           []string
	}{
		{name: "all", limit: 20, total: 4, messages: []string{"first", "second", "third", "fourth"}},
		{name: "first-page", limit: 2, total: 4, messages: []string{"first", "second"}},
		{name: "second-page", limit: 2, offset: 2, total: 4, messages: []string{"third", "fourth"}},
		{name: "last-page", limit: 2, offset: 3, total: 4, messages: []string{"fourth"}},
		{name: "past-end", limit: 2, offset: 8, total: 4},
		{name: "level", level: "info", limit: 10, total: 1, messages: []string{"first"}},
		{name: "phase", phase: "scan", limit: 10, total: 3, messages: []string{"second", "third", "fourth"}},
		{name: "filtered-page", level: "warn", phase: "scan", limit: 1, offset: 1, total: 3, messages: []string{"third"}},
		{name: "filtered-past-end", level: "warn", phase: "scan", limit: 1, offset: 9, total: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs, total, err := repo.ListScanLogs(ctx, "scan-a", tc.level, tc.phase, tc.limit, tc.offset)
			if err != nil {
				t.Fatal(err)
			}
			var messages []string
			for _, log := range logs {
				if log.ProjectUUID != "project-a" || log.ScanUUID != "scan-a" {
					t.Fatalf("mis-scoped log exposed: %+v", log)
				}
				messages = append(messages, log.Message)
			}
			if total != tc.total || !reflect.DeepEqual(messages, tc.messages) {
				t.Fatalf("total/messages=%d/%v want=%d/%v", total, messages, tc.total, tc.messages)
			}
		})
	}
	// Reading must exclude bad legacy rows, not rewrite/delete their evidence.
	if n, err := repo.DB().NewSelect().Model((*ScanLog)(nil)).Count(ctx); err != nil || n != int64(len(entries)) {
		t.Fatalf("listing changed stored logs: count=%d err=%v", n, err)
	}
}

func TestListScanLogsMissingParentAndDefaultProject(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScanLog(ctx, &ScanLog{ProjectUUID: "project-a", ScanUUID: "missing-scan", Level: "info", Message: "orphan"}); err != nil {
		t.Fatal(err)
	}
	logs, total, err := repo.ListScanLogs(ctx, "missing-scan", "", "", 10, 0)
	if err != nil || len(logs) != 0 || total != 0 {
		t.Fatalf("orphan log exposed: logs=%+v total=%d err=%v", logs, total, err)
	}
	if n, err := repo.DB().NewSelect().Model((*Scan)(nil)).Count(ctx); err != nil || n != 0 {
		t.Fatalf("listing fabricated a parent: count=%d err=%v", n, err)
	}
	if err := repo.CreateScan(ctx, &Scan{UUID: "default-scan", Name: "scan", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateScanLogBatch(ctx, []*ScanLog{
		{ScanUUID: "default-scan", Level: "info", Message: "matching-default"},
		{ProjectUUID: "project-b", ScanUUID: "default-scan", Level: "info", Message: "foreign"},
	}); err != nil {
		t.Fatal(err)
	}
	logs, total, err = repo.ListScanLogs(ctx, "default-scan", "", "", 10, 0)
	if err != nil || total != 1 || len(logs) != 1 || logs[0].ProjectUUID != DefaultProjectUUID || logs[0].Message != "matching-default" {
		t.Fatalf("default-project logs=%+v total=%d err=%v", logs, total, err)
	}
}
