package database

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func serverReceiveTestTime() time.Time {
	return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
}

func insertServerReceiveTestScan(t *testing.T, repo *Repository, scan *Scan) *Scan {
	t.Helper()
	if scan.StartedAt.IsZero() {
		scan.StartedAt = serverReceiveTestTime()
	}
	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = serverReceiveTestTime()
	}
	scan.UpdatedAt = scan.CreatedAt
	if err := repo.CreateScan(context.Background(), scan); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetScanByUUID(context.Background(), scan.UUID)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func insertServerReceiveTestRecord(t *testing.T, repo *Repository, project, id string, at time.Time, bunTimestamp bool) {
	t.Helper()
	generatedID := insertRecordP(t, repo, project, "GET", "receive.invalid", "/"+id, 200)
	var timestamp any = dbCursorTimeValue(repo.DB().Driver(), at)
	if bunTimestamp {
		timestamp = at
	}
	if _, err := repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).
		Set("uuid = ?", id).Set("created_at = ?", timestamp).
		Where("uuid = ?", generatedID).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func assertServerReceiveTestCursor(t *testing.T, repo *Repository, scan *Scan, project string, at time.Time, id string) {
	t.Helper()
	stored, err := repo.GetScanByUUID(context.Background(), scan.UUID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []*Scan{scan, stored} {
		if row.ProjectUUID != defaultProjectUUID(project) || !row.StartCursorAt.Equal(at) || row.StartCursorUUID != id || !row.CursorAt.Equal(at) || row.CursorUUID != id {
			t.Fatalf("scan %s cursor: project=%q start=(%v,%q) current=(%v,%q), want project=%q cursor=(%v,%q)",
				row.UUID, row.ProjectUUID, row.StartCursorAt, row.StartCursorUUID, row.CursorAt, row.CursorUUID, defaultProjectUUID(project), at, id)
		}
	}
}

func TestCreateServerReceiveScanResumesLegacyReceipts(t *testing.T) {
	for _, status := range []string{"failed", "cancelled", "canceled", "running", "completed", "paused"} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			repo := NewRepository(newTestDB(t))
			const project = "receive-project"
			at := serverReceiveTestTime()
			before := insertServerReceiveTestScan(t, repo, &Scan{
				UUID: "scan-11111111-1111-4111-8111-111111111111", ProjectUUID: project, Status: status,
				ScanSource: "scan-on-receive", ScanMode: "incremental", Modules: "passive-headers,passive-cookies",
				CursorAt: at, CursorUUID: "record-444", ProcessedCount: 444, ErrorMessage: "service stopped",
			})
			// Supplied cursors are not authoritative; the persisted selection is.
			scan := &Scan{
				UUID: "new-receipt", ProjectUUID: project, Status: "running",
				ScanSource: "scan-on-receive", ScanMode: "incremental", Modules: "",
				StartCursorAt: at.Add(time.Hour), StartCursorUUID: "stale-start",
				CursorAt: at.Add(time.Hour), CursorUUID: "stale-current",
			}
			if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
				t.Fatal(err)
			}
			assertServerReceiveTestCursor(t, repo, scan, project, at, "record-444")
			stored, err := repo.GetScanByUUID(ctx, before.UUID)
			if err != nil || !reflect.DeepEqual(before, stored) {
				t.Fatalf("historical receipt changed: stored=%+v err=%v", stored, err)
			}
			current, err := repo.GetScanByUUID(ctx, scan.UUID)
			if err != nil || current.Modules != "" || current.ProcessedCount != 0 || current.Status != "running" {
				t.Fatalf("new receipt inherited non-cursor fields: stored=%+v err=%v", current, err)
			}
		})
	}
}

func TestCreateServerReceiveScanChoosesGreatestCursor(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "receive-project"
	at := serverReceiveTestTime()
	for _, scan := range []*Scan{
		{UUID: "latest-completion", CursorAt: at, CursorUUID: "zzzz", Status: "completed", FinishedAt: at.Add(3 * time.Hour)},
		{UUID: "latest-created", CursorAt: at.Add(-time.Hour), CursorUUID: "zzzz", Status: "running", CreatedAt: at.Add(4 * time.Hour)},
		{UUID: "same-time-low-uuid", CursorAt: at.Add(time.Minute), CursorUUID: "record-a", Status: "completed", Modules: "other-modules"},
		{UUID: "highest-cursor", CursorAt: at.Add(time.Minute), CursorUUID: "record-z", Status: "failed"},
	} {
		scan.ProjectUUID, scan.ScanSource, scan.ScanMode = project, "scan-on-receive", "incremental"
		insertServerReceiveTestScan(t, repo, scan)
	}
	// AdvanceScanCursor stores SQLite timestamps without Bun's UTC suffix.
	// The equal-time lower UUID still has its Bun suffix and must not win.
	if err := repo.AdvanceScanCursor(ctx, "highest-cursor", at.Add(time.Minute), "record-z"); err != nil {
		t.Fatal(err)
	}
	scan := &Scan{UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	assertServerReceiveTestCursor(t, repo, scan, project, at.Add(time.Minute), "record-z")
}

func TestCreateServerReceiveScanPreservesCursorPrecision(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "receive-project"
	at := serverReceiveTestTime()
	for _, entry := range []struct {
		id string
		at time.Time
	}{
		{"record-z", at.Add(123455 * time.Microsecond)},
		{"record-a", at.Add(123456 * time.Microsecond)},
	} {
		insertServerReceiveTestScan(t, repo, &Scan{
			UUID: entry.id, ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental",
			CursorAt: entry.at, CursorUUID: entry.id,
		})
	}
	scan := &Scan{UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	assertServerReceiveTestCursor(t, repo, scan, project, at.Add(123456*time.Microsecond), "record-a")
}

func TestCreateServerReceiveScanIgnoresIncompleteAndZeroCursors(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "receive-project"
	at := serverReceiveTestTime()
	insertServerReceiveTestScan(t, repo, &Scan{
		UUID: "valid-receipt", ProjectUUID: project, Status: "failed", ScanSource: "scan-on-receive", ScanMode: "incremental",
		CursorAt: at, CursorUUID: "record-valid",
	})
	for _, scan := range []*Scan{
		{UUID: "pending-zero", Status: "running"},
		{UUID: "timestamp-only", CursorAt: at.Add(time.Hour), Status: "completed"},
		{UUID: "uuid-only", CursorUUID: "record-incomplete", Status: "failed"},
		{UUID: "explicit-zero-time", CursorUUID: "record-zero-time", Status: "cancelled"},
	} {
		scan.ProjectUUID, scan.ScanSource, scan.ScanMode = project, "scan-on-receive", "incremental"
		scan.CreatedAt, scan.FinishedAt = at.Add(2*time.Hour), at.Add(3*time.Hour)
		insertServerReceiveTestScan(t, repo, scan)
	}
	// Also exercise a persisted non-NULL Go zero time, not just nullzero fields.
	if _, err := repo.DB().NewUpdate().Model((*Scan)(nil)).Set("cursor_at = ?", time.Time{}).
		Where("uuid = ?", "explicit-zero-time").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	insertServerReceiveTestRecord(t, repo, project, "high-water-must-not-win", at.Add(4*time.Hour), false)
	scan := &Scan{UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	assertServerReceiveTestCursor(t, repo, scan, project, at, "record-valid")
}

func TestCreateServerReceiveScanProjectIsolationAndFallback(t *testing.T) {
	for _, project := range []string{"receive-project", ""} {
		for _, hasReceipt := range []bool{false, true} {
			name := defaultProjectUUID(project) + "/high-water"
			if hasReceipt {
				name = defaultProjectUUID(project) + "/resume"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				repo := NewRepository(newTestDB(t))
				ownedProject := defaultProjectUUID(project)
				at := serverReceiveTestTime()
				insertServerReceiveTestScan(t, repo, &Scan{
					UUID: "foreign-receipt", ProjectUUID: "foreign-project", ScanSource: "scan-on-receive", ScanMode: "incremental",
					CursorAt: at.Add(24 * time.Hour), CursorUUID: "foreign-cursor", Status: "completed",
				})
				insertServerReceiveTestRecord(t, repo, "foreign-project", "foreign-record", at.Add(48*time.Hour), false)
				// Native and non-incremental cursors cannot seed receive startup.
				for i, entry := range []struct{ source, mode string }{
					{"cli", "incremental"}, {"api", "incremental"}, {"", "incremental"}, {"scan-on-receive", "full"},
				} {
					insertServerReceiveTestScan(t, repo, &Scan{
						UUID: "excluded-scan-" + string(rune('a'+i)), ProjectUUID: ownedProject, Status: "completed",
						ScanSource: entry.source, ScanMode: entry.mode, CursorAt: at.Add(12 * time.Hour), CursorUUID: "excluded-cursor",
					})
				}
				insertServerReceiveTestRecord(t, repo, ownedProject, "record-old", at.Add(-time.Hour), false)
				insertServerReceiveTestRecord(t, repo, ownedProject, "record-a", at.Add(time.Hour), true)
				insertServerReceiveTestRecord(t, repo, ownedProject, "record-z", at.Add(time.Hour), false)
				wantAt, wantUUID := at.Add(time.Hour), "record-z"
				if hasReceipt {
					insertServerReceiveTestScan(t, repo, &Scan{
						UUID: "owned-receipt", ProjectUUID: ownedProject, Status: "failed", ScanSource: "scan-on-receive", ScanMode: "incremental",
						CursorAt: at, CursorUUID: "owned-cursor",
					})
					wantAt, wantUUID = at, "owned-cursor"
				}
				var recordsBefore []HTTPRecord
				if err := repo.DB().NewSelect().Model(&recordsBefore).Order("uuid ASC").Scan(ctx); err != nil {
					t.Fatal(err)
				}
				scan := &Scan{UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
				if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
					t.Fatal(err)
				}
				assertServerReceiveTestCursor(t, repo, scan, project, wantAt, wantUUID)
				var recordsAfter []HTTPRecord
				if err := repo.DB().NewSelect().Model(&recordsAfter).Order("uuid ASC").Scan(ctx); err != nil || !reflect.DeepEqual(recordsBefore, recordsAfter) {
					t.Fatalf("startup modified historical traffic: err=%v", err)
				}
			})
		}
	}
}

func TestCreateServerReceiveScanEmptyProjectStartsAtZero(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "empty-receive-project"
	at := serverReceiveTestTime()
	insertServerReceiveTestRecord(t, repo, DefaultProjectUUID, "foreign-record", at, false)
	insertServerReceiveTestScan(t, repo, &Scan{
		UUID: "zero-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental",
	})
	scan := &Scan{
		UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental",
		StartCursorAt: at, StartCursorUUID: "discard-me", CursorAt: at, CursorUUID: "discard-me",
	}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	assertServerReceiveTestCursor(t, repo, scan, project, time.Time{}, "")
}

func TestCreateServerReceiveScanKeepsNewBacklogBeyondCursor(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "receive-project"
	at := serverReceiveTestTime()
	insertServerReceiveTestRecord(t, repo, project, "record-m", at, false)
	insertServerReceiveTestScan(t, repo, &Scan{
		UUID: "previous-receipt", ProjectUUID: project, Status: "failed", Modules: "legacy-passive",
		ScanSource: "scan-on-receive", ScanMode: "incremental", CursorAt: at, CursorUUID: "record-m",
	})
	// These arrived after the old service cursor, but before restart. Neither
	// the later high-water mark nor the same-timestamp UUID tie may skip them.
	insertServerReceiveTestRecord(t, repo, project, "record-z", at, false)
	insertServerReceiveTestRecord(t, repo, project, "record-later", at.Add(time.Second), false)
	scan := &Scan{UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	assertServerReceiveTestCursor(t, repo, scan, project, at, "record-m")
	assertCursorTestReaders(t, repo, scan, "record-z", "record-later")
}

func TestCreateServerReceiveScanRejectsInvalidSourceOrMode(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	// A nil receiver proves validation happens before touching any database.
	var noDB *Repository
	if err := noDB.CreateServerReceiveScan(ctx, nil); err == nil {
		t.Fatal("nil scan accepted")
	}
	for _, entry := range []struct{ source, mode string }{
		{"", "incremental"}, {"cli", "incremental"}, {"api", "incremental"},
		{"scan-on-receive", ""}, {"scan-on-receive", "full"},
	} {
		scan := &Scan{UUID: "invalid-scan", ScanSource: entry.source, ScanMode: entry.mode, CursorUUID: "unchanged"}
		before := *scan
		if err := noDB.CreateServerReceiveScan(ctx, scan); err == nil {
			t.Fatalf("invalid source/mode accepted without DB: %+v", entry)
		}
		if err := repo.CreateServerReceiveScan(ctx, scan); err == nil {
			t.Fatalf("invalid source/mode accepted: %+v", entry)
		}
		if !reflect.DeepEqual(before, *scan) {
			t.Fatalf("validation mutated caller scan: %+v", scan)
		}
	}
	if n, err := repo.DB().NewSelect().Model((*Scan)(nil)).Count(ctx); err != nil || n != 0 {
		t.Fatalf("invalid request inserted a receipt: count=%d err=%v", n, err)
	}
}

func TestCreateServerReceiveScanReportsQueryAndInsertErrors(t *testing.T) {
	for _, failure := range []string{"receipt-query", "high-water-query", "insert"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			repo := NewRepository(newTestDB(t))
			const project = "receive-project"
			var statement, wantError string
			switch failure {
			case "receipt-query":
				statement = "ALTER TABLE scans RENAME COLUMN cursor_at TO unavailable_cursor_at"
				wantError = "load server receive receipt cursor"
			case "high-water-query":
				statement = "ALTER TABLE http_records RENAME TO unavailable_http_records"
				wantError = "load server receive traffic high-water mark"
			case "insert":
				insertServerReceiveTestRecord(t, repo, project, "record-existing", serverReceiveTestTime(), false)
				statement = "CREATE TRIGGER reject_receive_insert BEFORE INSERT ON scans BEGIN SELECT RAISE(ABORT, 'receipt insert rejected'); END"
				wantError = "failed to insert server receive scan"
			}
			if _, err := repo.DB().ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
			scan := &Scan{UUID: "new-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental", CursorUUID: "unchanged"}
			before := *scan
			if err := repo.CreateServerReceiveScan(ctx, scan); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("failure not reported honestly: err=%v, want %q", err, wantError)
			}
			if !reflect.DeepEqual(before, *scan) {
				t.Fatalf("failed transaction mutated caller scan: %+v", scan)
			}
			if n, err := repo.DB().NewSelect().TableExpr("scans").Count(ctx); err != nil || n != 0 {
				t.Fatalf("failed transaction inserted receipt: count=%d err=%v", n, err)
			}
		})
	}
}
