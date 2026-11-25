package database

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScanLoggerProjectScope(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	project, scan := uuid.NewString(), uuid.NewString()
	l := NewScanLogger(repo, scan, project)
	l.Info("scan", "started")
	l.Trace("scan", "trace")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	var rows []*ScanLog
	if err := repo.DB().NewSelect().Model(&rows).Where("scan_uuid = ?", scan).Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
	for _, row := range rows {
		if row.ProjectUUID != project {
			t.Fatalf("leaked project scope: %q", row.ProjectUUID)
		}
	}
	if o := l.Outcome(); o.WrittenEntries != 2 || o.BufferedEntries != 0 || !o.Closed || !o.Joined {
		t.Fatalf("outcome=%+v", o)
	}
}

func TestScanLoggerBoundedAdmissionAndFailureAccounting(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	l := NewScanLogger(repo, uuid.NewString(), uuid.NewString())
	failure := errors.New("injected insert failure")
	l.writeBatch = func(context.Context, []*ScanLog) error { return failure }
	l.writeOne = func(context.Context, *ScanLog) error { return failure }
	for range scanLogMaxEntries + 7 {
		l.Trace("scan", "small")
	}
	l.Trace("scan", strings.Repeat("x", scanLogMaxEntry))
	o := l.Outcome()
	if o.BufferedEntries != scanLogMaxEntries || o.BufferedBytes > scanLogMaxBytes || o.DroppedEntries != 8 {
		t.Fatalf("admission outcome=%+v", o)
	}
	if err := l.Flush(); !errors.Is(err, failure) {
		t.Fatalf("flush=%v", err)
	}
	l.Info("scan", "immediate failure")
	if err := l.Close(); !errors.Is(err, failure) || !errors.Is(err, ErrScanLogLoss) {
		t.Fatalf("close=%v", err)
	}
	o = l.Outcome()
	if o.FailedEntries != scanLogMaxEntries+1 || o.FailedBytes == 0 || o.DroppedBytes == 0 || o.BufferedEntries != 0 || o.WrittenEntries != 0 {
		t.Fatalf("failure outcome=%+v", o)
	}
	l.StartBatcher() // cannot restart a closed logger
	l.Trace("scan", "late")
	if l.Outcome().DroppedEntries != 9 {
		t.Fatal("post-close loss unaccounted")
	}
	if !errors.Is(l.Err(), failure) {
		t.Fatal("failure became inaccessible")
	}
}

func TestScanLoggerByteAdmission(t *testing.T) {
	l := NewScanLogger(NewRepository(newTestDB(t)), "scan", "project")
	for range 100 {
		l.Trace("scan", strings.Repeat("x", 60000))
	}
	o := l.Outcome()
	if o.BufferedBytes > scanLogMaxBytes || o.BufferedEntries >= 100 || o.DroppedEntries == 0 {
		t.Fatalf("byte cap not enforced: %+v", o)
	}
	_ = l.Close()
}

func TestScanLoggerConcurrentFlushCloseJoins(t *testing.T) {
	l := NewScanLogger(NewRepository(newTestDB(t)), uuid.NewString(), uuid.NewString())
	l.flushInterval = time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	l.writeBatch = func(ctx context.Context, _ []*ScanLog) error {
		once.Do(func() { close(entered) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	l.Trace("scan", "buffered")
	l.StartBatcher()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("batcher did not start")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); l.StartBatcher(); _ = l.Flush() }()
	}
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close did not join active batch: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked")
	}
	wg.Wait()
	select {
	case <-l.batchDone:
	default:
		t.Fatal("batch worker not joined")
	}
	if o := l.Outcome(); o.WrittenEntries != 1 || o.FailedEntries != 0 || o.BufferedEntries != 0 {
		t.Fatalf("outcome=%+v", o)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestScanLoggerCloseJoinsImmediateWrites(t *testing.T) {
	l := NewScanLogger(NewRepository(newTestDB(t)), "scan", "project")
	entered, release := make(chan struct{}), make(chan struct{})
	l.writeOne = func(ctx context.Context, _ *ScanLog) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	logged := make(chan struct{})
	go func() { l.Info("scan", "immediate"); close(logged) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("immediate write not joined: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-logged
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join")
	}
	if o := l.Outcome(); o.WrittenEntries != 1 || o.InFlightEntries != 0 || !o.Joined {
		t.Fatalf("outcome=%+v", o)
	}
}

func TestScanLoggerShutdownDeadlineIsObservable(t *testing.T) {
	l := NewScanLogger(NewRepository(newTestDB(t)), "scan", "project")
	entered, release := make(chan struct{}), make(chan struct{})
	l.writeBatch = func(ctx context.Context, _ []*ScanLog) error {
		close(entered)
		select {
		case <-release:
			return errors.New("injected failure")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	l.Trace("scan", "buffered")
	flushed := make(chan error, 1)
	go func() { flushed <- l.Flush() }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline=%v", err)
	}
	if !errors.Is(l.Err(), context.DeadlineExceeded) {
		t.Fatal("deadline not accessible")
	}
	if o := l.Outcome(); !o.Closed || o.Joined || o.InFlightEntries != 1 || o.InFlightBytes == 0 {
		t.Fatalf("deadline hid the unjoined write: %+v", o)
	}
	close(release)
	<-flushed
	if err := l.Close(); !errors.Is(err, ErrScanLogLoss) {
		t.Fatalf("loss missing: %v", err)
	}
	if o := l.Outcome(); o.FailedEntries != 1 || o.BufferedEntries != 0 {
		t.Fatalf("outcome=%+v", o)
	}
}
