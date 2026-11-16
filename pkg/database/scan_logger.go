package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	scanLogMaxEntries = 2048
	scanLogMaxBytes   = 2 << 20
	scanLogMaxEntry   = 64 << 10
	scanLogWriteLimit = 5 * time.Second
	scanLogCloseLimit = 10 * time.Second
)

var ErrScanLogLoss = errors.New("scan log entries lost")

// ScanLoggerOutcome is a bounded accounting snapshot. Failed entries could not
// be encoded or confirmed persisted; dropped entries failed size/cap/closed
// admission. Neither is silently retried: ambiguous inserts can duplicate logs.
type ScanLoggerOutcome struct {
	WrittenEntries  uint64
	FailedEntries   uint64
	FailedBytes     uint64
	DroppedEntries  uint64
	DroppedBytes    uint64
	BufferedEntries int
	BufferedBytes   int
	InFlightEntries int
	InFlightBytes   int
	Closed          bool // admission is closed
	Joined          bool // shutdown worker and all admitted writes completed
}

// ScanLogger bounds trace buffering and DB calls. Close joins the batcher and
// admitted synchronous writes before the final flush. A nil repo is a no-op.
type ScanLogger struct {
	repo        *Repository
	scanUUID    string
	projectUUID string

	mu            sync.Mutex
	buf           []*ScanLog
	bufBytes      int
	flushInterval time.Duration
	stopCh        chan struct{}
	batchDone     chan struct{}
	closeDone     chan struct{}
	started       bool
	closed        bool
	outcome       ScanLoggerOutcome
	err           error // first persistence/shutdown error, bounded memory
	lossWarned    bool
	writes        sync.WaitGroup
	// Serializes detached batches so concurrent Flush/Close cannot reorder or
	// leave an unjoined batch. Acquisition itself respects the caller's deadline.
	flushGate  chan struct{}
	writeBatch func(context.Context, []*ScanLog) error
	writeOne   func(context.Context, *ScanLog) error
}

// NewScanLogger requires the scan's explicit project scope. Empty means the
// repository's default project, matching scan creation; callers with an existing
// row must pass that row's ProjectUUID, not the process's current project.
func NewScanLogger(repo *Repository, scanUUID, projectUUID string) *ScanLogger {
	l := &ScanLogger{
		repo: repo, scanUUID: scanUUID, projectUUID: defaultProjectUUID(projectUUID),
		flushInterval: 2 * time.Second, stopCh: make(chan struct{}),
		batchDone: make(chan struct{}), closeDone: make(chan struct{}),
		flushGate: make(chan struct{}, 1),
	}
	if repo != nil {
		l.writeBatch = repo.CreateScanLogBatch
		l.writeOne = repo.CreateScanLog
	}
	return l
}

func (l *ScanLogger) enabled() bool { return l != nil && l.repo != nil && l.scanUUID != "" }

// StartBatcher is idempotent and cannot restart a closed logger.
func (l *ScanLogger) StartBatcher() {
	if !l.enabled() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started || l.closed {
		return
	}
	l.started = true
	go l.batchLoop()
}

func (l *ScanLogger) batchLoop() {
	defer close(l.batchDone)
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), scanLogWriteLimit)
			_ = l.flushOpen(ctx, false)
			cancel()
		case <-l.stopCh:
			return
		}
	}
}

// Flush returns persistence failures instead of silently discarding the batch.
// Outcome accounts for every removed entry, including ambiguous failed inserts.
func (l *ScanLogger) Flush() error {
	ctx, cancel := context.WithTimeout(context.Background(), scanLogWriteLimit)
	defer cancel()
	return l.FlushContext(ctx)
}

func (l *ScanLogger) FlushContext(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, scanLogWriteLimit)
	defer cancel()
	return l.flushOpen(ctx, true)
}

func (l *ScanLogger) flushOpen(ctx context.Context, joinClosed bool) error {
	if !l.enabled() {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		// Shutdown owns the final flush. A public Flush joins it; a tick
		// selected just before Close must not wait on the worker joining it.
		done := l.closeDone
		l.mu.Unlock()
		if !joinClosed {
			return nil
		}
		select {
		case <-done:
			return l.Err()
		case <-ctx.Done():
			l.recordFailure(ctx.Err(), 0, 0)
			return ctx.Err()
		}
	}
	// Admission under mu avoids WaitGroup.Add racing Close's Wait.
	l.writes.Add(1)
	l.mu.Unlock()
	defer l.writes.Done()
	return l.flush(ctx)
}

func (l *ScanLogger) flush(ctx context.Context) error {
	select {
	case l.flushGate <- struct{}{}:
		defer func() { <-l.flushGate }()
	case <-ctx.Done():
		l.recordFailure(ctx.Err(), 0, 0)
		return ctx.Err()
	}
	l.mu.Lock()
	entries, bytes := l.buf, l.bufBytes
	l.buf, l.bufBytes = nil, 0
	l.outcome.InFlightEntries += len(entries)
	l.outcome.InFlightBytes += bytes
	l.mu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	err := l.writeBatch(ctx, entries)
	l.completeWrite(err, len(entries), bytes)
	return err
}

// Close is a bounded, joined shutdown. Concurrent calls wait for the same
// shutdown and receive the same persisted error/loss outcome.
func (l *ScanLogger) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), scanLogCloseLimit)
	defer cancel()
	return l.CloseContext(ctx)
}

func (l *ScanLogger) CloseContext(ctx context.Context) error {
	if !l.enabled() {
		return nil
	}
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.stopCh)
		if !l.started {
			close(l.batchDone)
		}
		go l.shutdown()
	}
	done := l.closeDone
	l.mu.Unlock()
	select {
	case <-done:
		return l.Err()
	case <-ctx.Done():
		l.recordFailure(ctx.Err(), 0, 0)
		return ctx.Err()
	}
}

func (l *ScanLogger) shutdown() {
	defer func() {
		l.mu.Lock()
		l.outcome.Joined = true
		l.mu.Unlock()
		close(l.closeDone)
	}()
	// All admitted writes have bounded contexts. No new Add is possible once
	// closed is set, and the periodic batcher is included in writes.
	<-l.batchDone
	l.writes.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), scanLogWriteLimit)
	defer cancel()
	_ = l.flush(ctx)
}

func (l *ScanLogger) Err() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.outcome.DroppedEntries > 0 || l.outcome.FailedEntries > 0 {
		return errors.Join(l.err, ErrScanLogLoss)
	}
	return l.err
}

func (l *ScanLogger) Outcome() ScanLoggerOutcome {
	if l == nil {
		return ScanLoggerOutcome{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.outcome
	o.BufferedEntries, o.BufferedBytes, o.Closed = len(l.buf), l.bufBytes, l.closed
	return o
}

func (l *ScanLogger) completeWrite(err error, count, bytes int) {
	l.mu.Lock()
	l.outcome.InFlightEntries -= count
	l.outcome.InFlightBytes -= bytes
	first := err != nil && l.err == nil
	if err != nil {
		if first {
			l.err = err
		}
		l.outcome.FailedEntries += uint64(count)
		l.outcome.FailedBytes += uint64(bytes)
	} else {
		l.outcome.WrittenEntries += uint64(count)
	}
	l.mu.Unlock()
	if first {
		zap.L().Warn("Scan log persistence/shutdown failed", zap.String("scan_uuid", l.scanUUID), zap.Int("entries", count), zap.Error(err))
	}
}

func (l *ScanLogger) recordFailure(err error, count, bytes int) {
	l.mu.Lock()
	first := l.err == nil
	if first {
		l.err = err
	}
	l.outcome.FailedEntries += uint64(count)
	l.outcome.FailedBytes += uint64(bytes)
	l.mu.Unlock()
	if first {
		zap.L().Warn("Scan log persistence/shutdown failed", zap.String("scan_uuid", l.scanUUID), zap.Int("entries", count), zap.Error(err))
	}
}

// dropLocked accounts for admission loss; external warning writes happen after
// releasing mu so a blocked warning sink cannot prevent shutdown admission.
func (l *ScanLogger) dropLocked(bytes int) bool {
	l.outcome.DroppedEntries++
	l.outcome.DroppedBytes += uint64(bytes)
	first := !l.lossWarned
	l.lossWarned = true
	return first
}

func (l *ScanLogger) warnAdmission() {
	zap.L().Warn("Scan log admission rejected; see logger outcome for lost counts", zap.String("scan_uuid", l.scanUUID))
}

func (l *ScanLogger) Info(phase, message string)  { l.log("info", phase, message, nil) }
func (l *ScanLogger) Warn(phase, message string)  { l.log("warn", phase, message, nil) }
func (l *ScanLogger) Error(phase, message string) { l.log("error", phase, message, nil) }

func (l *ScanLogger) entry(level, phase, message string) *ScanLog {
	return &ScanLog{ProjectUUID: l.projectUUID, ScanUUID: l.scanUUID, Level: level, Phase: phase, Message: message, CreatedAt: time.Now()}
}

// entryBytes includes fixed allocation overhead, not just message bytes.
func entryBytes(entry *ScanLog) int {
	return 256 + len(entry.ProjectUUID) + len(entry.ScanUUID) + len(entry.Level) + len(entry.Phase) + len(entry.Message) + len(entry.Metadata)
}

func (l *ScanLogger) Trace(phase, message string) {
	if !l.enabled() {
		return
	}
	entry := l.entry("trace", phase, message)
	bytes := entryBytes(entry)
	l.mu.Lock()
	if l.closed || bytes > scanLogMaxEntry || len(l.buf) >= scanLogMaxEntries || l.bufBytes+bytes > scanLogMaxBytes {
		warn := l.dropLocked(bytes)
		l.mu.Unlock()
		if warn {
			l.warnAdmission()
		}
		return
	}
	l.buf = append(l.buf, entry)
	l.bufBytes += bytes
	l.mu.Unlock()
}

func (l *ScanLogger) InfoWithMeta(phase, message string, meta map[string]interface{}) {
	l.log("info", phase, message, meta)
}

func (l *ScanLogger) log(level, phase, message string, meta map[string]interface{}) {
	if !l.enabled() {
		return
	}
	entry := l.entry(level, phase, message)
	if meta != nil {
		b, err := json.Marshal(meta)
		if err != nil {
			l.recordFailure(fmt.Errorf("encode scan log metadata: %w", err), 1, entryBytes(entry))
			return
		}
		entry.Metadata = string(b)
	}
	bytes := entryBytes(entry)
	l.mu.Lock()
	if l.closed || bytes > scanLogMaxEntry {
		warn := l.dropLocked(bytes)
		l.mu.Unlock()
		if warn {
			l.warnAdmission()
		}
		return
	}
	l.writes.Add(1)
	l.outcome.InFlightEntries++
	l.outcome.InFlightBytes += bytes
	l.mu.Unlock()
	defer l.writes.Done()
	ctx, cancel := context.WithTimeout(context.Background(), scanLogWriteLimit)
	defer cancel()
	l.completeWrite(l.writeOne(ctx, entry), 1, bytes)
}
