package database

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func setCursorTestTimestamp(t *testing.T, repo *Repository, id, timestamp string) {
	t.Helper()
	if _, err := repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).
		Set("created_at = ?", timestamp).Where("uuid = ?", id).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Compare the actual feed (including its Count snapshot) and both counter
// paths against the same persisted project cursor.
func assertCursorTestReaders(t *testing.T, repo *Repository, scan *Scan, ids ...string) {
	t.Helper()
	ctx := context.Background()
	stored, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil {
		t.Fatal(err)
	}
	hosts := []HostTarget{{Hostname: "receive.invalid"}}
	count, err := repo.CountRecordsAfterCursor(ctx, stored.ProjectUUID, stored.CursorAt, stored.CursorUUID, hosts...)
	if err != nil || count != int64(len(ids)) {
		t.Fatalf("project counter=%d err=%v, want %d", count, err, len(ids))
	}
	count, err = repo.CountRecordsAfterCursorBySource(ctx, stored.ProjectUUID, stored.CursorAt, stored.CursorUUID, []string{"test"}, hosts)
	if err != nil || count != int64(len(ids)) {
		t.Fatalf("source counter=%d err=%v, want %d", count, err, len(ids))
	}
	feed := NewDBInputSource(repo.DB(), repo, scan.UUID, time.Second).
		WithHostScopes(hosts).WithIncludeSources([]string{"test"})
	batch, err := feed.fetchNextBatch(ctx)
	if len(ids) == 0 {
		if !errors.Is(err, sql.ErrNoRows) || len(batch) != 0 {
			t.Fatalf("actual feed replayed history: batch=%+v err=%v", batch, err)
		}
	} else if err != nil || len(batch) != len(ids) {
		t.Fatalf("actual feed=%+v err=%v, want %v", batch, err, ids)
	}
	for i, id := range ids {
		if batch[i].UUID != id {
			t.Fatalf("feed row %d=%q, want %q", i, batch[i].UUID, id)
		}
	}
	if feed.Count() != int64(len(ids)) {
		t.Fatalf("actual feed count=%d, want %d", feed.Count(), len(ids))
	}
	if _, err := feed.fetchNextBatch(ctx); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second batch replayed rows: err=%v", err)
	}
}

func TestServerReceiveCursorFeedDoesNotReplayHighWater(t *testing.T) {
	for _, precision := range []struct {
		name string
		ns   int
	}{
		{"whole-second", 0},
		{"fractional-microseconds", 123456000},
		{"fractional-nanoseconds", 123456789},
	} {
		t.Run(precision.name, func(t *testing.T) {
			ctx := context.Background()
			repo := NewRepository(newTestDB(t))
			const project = "receive-project"
			at := serverReceiveTestTime().Add(time.Duration(precision.ns))
			insertServerReceiveTestRecord(t, repo, project, "record-a", at, false)
			insertServerReceiveTestRecord(t, repo, project, "record-b", at, false)
			insertServerReceiveTestRecord(t, repo, project, "record-z", at, false)
			// These encode the same instant as record-z, but have a UTC suffix
			// and (for whole seconds/microseconds) insignificant fractional zeros.
			setCursorTestTimestamp(t, repo, "record-a", at.Format("2006-01-02 15:04:05.999999999")+"+00:00")
			setCursorTestTimestamp(t, repo, "record-b", at.Format("2006-01-02 15:04:05.000000000")+"+00:00")
			insertServerReceiveTestRecord(t, repo, project, "record-older", at.Add(-time.Nanosecond), false)
			insertServerReceiveTestRecord(t, repo, "foreign-project", "foreign-future", at.Add(time.Hour), false)
			scan := &Scan{UUID: "initial-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
			if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
				t.Fatal(err)
			}
			assertServerReceiveTestCursor(t, repo, scan, project, at, "record-z")
			assertCursorTestReaders(t, repo, scan)

			// Exercise the actual ongoing feed, not a handcrafted SQL predicate.
			feed := NewDBInputSource(repo.DB(), repo, scan.UUID, time.Second).WithPageSize(1)
			if batch, err := feed.fetchNextBatch(ctx); !errors.Is(err, sql.ErrNoRows) || len(batch) != 0 {
				t.Fatalf("initial high-water replay: batch=%+v err=%v", batch, err)
			}
			// A higher UUID at the same instant is eligible. A one-nanosecond
			// later record must follow it even if its UUID sorts earlier.
			insertServerReceiveTestRecord(t, repo, project, "record-zz", at, false)
			setCursorTestTimestamp(t, repo, "record-zz", at.Format("2006-01-02 15:04:05.000000000")+"+00:00")
			later := at.Add(time.Nanosecond)
			insertServerReceiveTestRecord(t, repo, project, "record-next", later, false)
			assertCursorTestReaders(t, repo, scan, "record-zz", "record-next")

			for i, expected := range []struct {
				id string
				at time.Time
			}{{"record-zz", at}, {"record-next", later}} {
				record, seq, err := feed.nextBufferedRecord(ctx)
				if err != nil || record.UUID != expected.id || !record.CreatedAt.Equal(expected.at) {
					t.Fatalf("actual one-row page=%+v err=%v, want (%v,%q)", record, err, expected.at, expected.id)
				}
				// Use the real WorkItem completion/ack path to persist the cursor.
				item, err := feed.workItemFromRecord(record, seq)
				if err != nil {
					t.Fatal(err)
				}
				item.Complete()
				stored, err := repo.GetScanByUUID(ctx, scan.UUID)
				if err != nil || !stored.CursorAt.Equal(expected.at) || stored.CursorUUID != expected.id || stored.ProcessedCount != int64(i+1) {
					t.Fatalf("ack regressed/lost cursor precision: stored=%+v err=%v", stored, err)
				}
				if !stored.StartCursorAt.Equal(at) || stored.StartCursorUUID != "record-z" {
					t.Fatalf("advance modified starting cursor: %+v", stored)
				}
				if i == 0 {
					assertCursorTestReaders(t, repo, scan, "record-next")
				} else {
					assertCursorTestReaders(t, repo, scan)
				}
			}
			if batch, err := feed.fetchNextBatch(ctx); !errors.Is(err, sql.ErrNoRows) || len(batch) != 0 {
				t.Fatalf("ongoing feed replayed completed traffic: batch=%+v err=%v", batch, err)
			}
			restart := &Scan{UUID: "restart-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
			if err := repo.CreateServerReceiveScan(ctx, restart); err != nil {
				t.Fatal(err)
			}
			assertServerReceiveTestCursor(t, repo, restart, project, later, "record-next")
			assertCursorTestReaders(t, repo, restart)
		})
	}
}

func TestRiskPrioritizedDBInputSourceMixedCursorKeys(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "risk-cursor-project"
	at := serverReceiveTestTime().Add(123456789 * time.Nanosecond)
	insertServerReceiveTestRecord(t, repo, project, "record-a", at, false)
	insertServerReceiveTestRecord(t, repo, project, "record-m", at, false)
	setCursorTestTimestamp(t, repo, "record-a", at.Format("2006-01-02 15:04:05.000000000")+"+00:00")
	scan := &Scan{UUID: "risk-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	initial := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scan.UUID)
	if item, err := initial.Next(ctx); !errors.Is(err, io.EOF) || item != nil || initial.Count() != 0 {
		t.Fatalf("risk snapshot replayed history: item=%+v err=%v count=%d", item, err, initial.Count())
	}
	insertServerReceiveTestRecord(t, repo, project, "record-z", at, false)
	setCursorTestTimestamp(t, repo, "record-z", at.Format("2006-01-02 15:04:05.000000000")+"+00:00")
	later := at.Add(time.Nanosecond)
	insertServerReceiveTestRecord(t, repo, project, "record-next", later, false)
	insertServerReceiveTestRecord(t, repo, "foreign-project", "foreign-risk", later.Add(time.Hour), false)
	if err := repo.UpdateRiskScores(ctx, map[string]int{"record-next": 10, "foreign-risk": 100}); err != nil {
		t.Fatal(err)
	}
	assertCursorTestReaders(t, repo, scan, "record-z", "record-next")
	risk := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scan.UUID)
	for _, id := range []string{"record-next", "record-z"} {
		item, err := risk.Next(ctx)
		if err != nil || item.RecordUUID != id {
			t.Fatalf("risk feed item=%+v err=%v, want %s", item, err, id)
		}
		item.Complete()
	}
	if item, err := risk.Next(ctx); !errors.Is(err, io.EOF) || item != nil || risk.Count() != 2 {
		t.Fatalf("risk snapshot did not drain: item=%+v err=%v count=%d", item, err, risk.Count())
	}
	stored, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil || !stored.CursorAt.Equal(later) || stored.CursorUUID != "record-next" || stored.ProcessedCount != 2 {
		t.Fatalf("risk snapshot regressed durable cursor: stored=%+v err=%v", stored, err)
	}
	assertCursorTestReaders(t, repo, scan)
}

func TestParamMiningCandidatesMixedCursorKeys(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	const project = "mining-cursor-project"
	at := serverReceiveTestTime().Add(123456789 * time.Nanosecond)
	insertServerReceiveTestRecord(t, repo, project, "record-a", at, false)
	insertServerReceiveTestRecord(t, repo, project, "record-m", at, false)
	setCursorTestTimestamp(t, repo, "record-a", at.Format("2006-01-02 15:04:05.000000000")+"+00:00")
	scan := &Scan{UUID: "mining-receipt", ProjectUUID: project, ScanSource: "scan-on-receive", ScanMode: "incremental"}
	if err := repo.CreateServerReceiveScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if rows, err := repo.ParamMiningCandidates(ctx, scan.UUID, nil, 128); err != nil || len(rows) != 0 {
		t.Fatalf("param mining replayed history: rows=%+v err=%v", rows, err)
	}
	insertServerReceiveTestRecord(t, repo, project, "record-z", at, false)
	setCursorTestTimestamp(t, repo, "record-z", at.Format("2006-01-02 15:04:05.000000000")+"+00:00")
	later := at.Add(time.Nanosecond)
	insertServerReceiveTestRecord(t, repo, project, "record-next", later, false)
	insertServerReceiveTestRecord(t, repo, "foreign-project", "foreign-mining", later.Add(time.Hour), false)
	rows, err := repo.ParamMiningCandidates(ctx, scan.UUID, nil, 128)
	if err != nil || len(rows) != 2 || rows[0].UUID != "record-z" || rows[1].UUID != "record-next" {
		t.Fatalf("param mining skipped/reordered/leaked candidates: rows=%+v err=%v", rows, err)
	}
	if err := repo.AdvanceScanCursorBy(ctx, scan.UUID, later, "record-next", 2); err != nil {
		t.Fatal(err)
	}
	if rows, err := repo.ParamMiningCandidates(ctx, scan.UUID, nil, 128); err != nil || len(rows) != 0 {
		t.Fatalf("param mining replayed advanced cursor: rows=%+v err=%v", rows, err)
	}
}

func TestDBCursorTimeContract(t *testing.T) {
	at := serverReceiveTestTime().Add(123456789 * time.Nanosecond)
	if got := dbCursorTimeValue(driverSQLite, at); got != "2026-10-01 12:00:00.123456789" {
		t.Fatalf("SQLite bound lost precision: %v", got)
	}
	if got := dbCursorTimeValue(driverSQLite, serverReceiveTestTime()); got != "2026-10-01 12:00:00" {
		t.Fatalf("whole-second bound has an incompatible suffix: %v", got)
	}
	local := at.In(time.FixedZone("UTC+7", 7*60*60))
	if got := dbCursorTimeValue(driverSQLite, local); got != dbCursorTimeValue(driverSQLite, at) {
		t.Fatalf("SQLite bound not UTC normalized: %v", got)
	}
	if got, ok := dbCursorTimeValue(driverPostgres, local).(time.Time); !ok || !got.Equal(at) || got.Location() != time.UTC {
		t.Fatalf("PostgreSQL bound is not a native UTC time: %v", got)
	}
	for _, column := range []string{"created_at", "sc.cursor_at"} {
		if got := dbCursorTimeExpr(driverPostgres, column); got != column {
			t.Fatalf("PostgreSQL timestamp unnecessarily transformed: %s", got)
		}
		if got := dbCursorTimeExpr(driverSQLite, column); !strings.Contains(got, "replace("+column+", '+00:00', '')") || strings.Contains(got, "julianday") {
			t.Fatalf("SQLite key expression is lossy or inconsistent: %s", got)
		}
	}
}
