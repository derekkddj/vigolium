package database

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// FindingWriterConfig configures the batching behavior of FindingWriter.
type FindingWriterConfig struct {
	// BufferSize is the channel capacity. When full, Save persists inline rather
	// than waiting for count-buffer room; byte admission can still wait. Default: 1024.
	BufferSize int

	// MaxPendingBytes bounds estimated retained snapshot bytes across the queue,
	// current flush and all concurrent inline writes. Save waits cancellably for
	// this budget BEFORE cloning evidence, even when the count buffer is full.
	// An individual finding larger than the budget returns an admission error.
	// Non-positive values use the default: 64 MiB.
	MaxPendingBytes int64

	// BatchSize is the maximum number of findings coalesced into one transaction.
	// Default: 64.
	BatchSize int

	// FlushInterval is the maximum time a finding waits in the buffer before
	// being flushed, even if the batch isn't full. Default: 50ms.
	FlushInterval time.Duration

	// FlushTimeout bounds the shutdown drain so a wedged database can't block
	// Close() forever. Steady-state flushes are bounded by OperationTimeout
	// instead, and remain immune to scan cancellation. Default: 2m.
	FlushTimeout time.Duration

	// OperationTimeout bounds ONE steady-state flush. Steady flushes deliberately
	// do not inherit the scan's context — cancelling a scan mid-transaction would
	// abort findings already pulled off the channel — but "not cancellable" was
	// implemented as context.Background(), i.e. no bound at all: a wedged database
	// parked the writer goroutine for the rest of the process. This is the bound,
	// set far above SQLite's 60s busy_timeout so a merely busy database still
	// succeeds. Default: 2m.
	OperationTimeout time.Duration

	// saveBatch replaces the repository batch save. Unexported, so only this
	// package's tests can set it — and it lives on the config rather than on the
	// writer because NewFindingWriter starts the flush goroutine, which reads the
	// seam: assigning it afterwards would be a data race on every flush.
	saveBatch func(context.Context, []FindingWrite) []FindingSaveResult
}

func (c *FindingWriterConfig) withDefaults() FindingWriterConfig {
	out := *c
	if out.BufferSize <= 0 {
		out.BufferSize = 1024
	}
	if out.MaxPendingBytes <= 0 {
		out.MaxPendingBytes = 64 << 20
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 64
	}
	if out.FlushInterval <= 0 {
		out.FlushInterval = 50 * time.Millisecond
	}
	if out.FlushTimeout <= 0 {
		out.FlushTimeout = 2 * time.Minute
	}
	if out.OperationTimeout <= 0 {
		out.OperationTimeout = 2 * time.Minute
	}
	return out
}

// findingWrite is a single queued finding.
type findingWrite struct {
	event        *output.ResultEvent
	recordUUIDs  []string
	scanUUID     string
	projectUUID  string
	pendingBytes int64 // byte lease transfers with the snapshot until persistence finishes
}

// FindingWriterMetrics exposes counters for monitoring.
//
// Written and Errors are exact per finding, not per batch: a flush asks for the
// per-finding outcomes and counts each one. They used to be charged by batch size
// on any batch error, so one unconvertible finding reported the whole batch as
// dropped and Written+Errors could exceed Enqueued.
type FindingWriterMetrics struct {
	Enqueued         int64 // findings handed to the background writer
	Written          int64 // findings the background writer persisted (or deduped onto an existing row)
	Inline           int64 // accepted synchronous persistence attempts (buffer full / shutting down)
	InlineFailed     int64 // inline saves that returned an error
	Errors           int64 // findings that individually failed to persist in a flush
	AdmissionFailed  int64 // rejected before acceptance (invalid, oversize, cancellation or shutdown while waiting)
	PendingBytes     int64 // estimated retained bytes leased by queued, flushing and inline findings
	PeakPendingBytes int64 // maximum PendingBytes observed; never exceeds MaxPendingBytes
}

// FindingWriter decouples finding persistence from scan workers. SaveFinding is
// a multi-statement, dedup-aware operation; calling it synchronously on every
// worker blocks the worker on a database round-trip. FindingWriter funnels
// findings through a single background goroutine that coalesces them into batch
// transactions (one fsync for many findings) via Repository.SaveFindingsBatch.
//
// Findings are low-volume relative to HTTP records, so a single writer goroutine
// keeps up while also eliminating write contention between concurrent finding
// transactions. This mirrors RecordWriter's lifecycle (buffered channel,
// background flush, bounded shutdown drain) but is fire-and-forget: the result
// UUID is never needed by the caller, so an enqueued Save does not wait for its
// persistence. Byte admission and the inline fallback can still block Save.
type FindingWriter struct {
	repo *Repository
	cfg  FindingWriterConfig
	ch   chan findingWrite

	// mu guards the closed flag against concurrent channel sends so Close can
	// guarantee no send is in flight when it stops accepting new findings.
	mu     sync.RWMutex
	closed bool

	// Byte admission has its own short-held lock. A waiter must NEVER hold mu:
	// Shutdown needs mu to stop channel sends before waking the drain. Closing
	// bytesChanged broadcasts a release without parking a releasing goroutine.
	bytesMu          sync.Mutex
	bytesChanged     chan struct{}
	pendingBytes     int64
	peakPendingBytes int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// shutdown carries the single absolute deadline the whole shutdown shares —
	// the drain's flushes and the wait for the goroutine to exit — and the
	// once-only outcome. See shutdownBudget.
	shutdown shutdownBudget

	// saveBatch is the persistence seam. Defaults to the repository's aligned
	// batch save; replaced in tests to drive the failure and stall paths.
	saveBatch func(context.Context, []FindingWrite) []FindingSaveResult

	// onInserted, when set, is called for every finding persisted as a NEW
	// row (not a dedup-append), so notifications fire only for new findings.
	// Called from the writer goroutine (or the inline saver).
	onInserted atomic.Pointer[func(*output.ResultEvent)]

	enqueued        atomic.Int64
	written         atomic.Int64
	inline          atomic.Int64
	inlineWritten   atomic.Int64 // completed inline saves; in-flight attempts remain Unknown
	inlineFailed    atomic.Int64
	errors          atomic.Int64
	admissionFailed atomic.Int64
}

// NewFindingWriter creates and starts a FindingWriter. Call Close() to flush
// remaining findings and stop the background goroutine.
func NewFindingWriter(repo *Repository, cfg FindingWriterConfig) *FindingWriter {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())

	w := &FindingWriter{
		repo:         repo,
		cfg:          cfg,
		ch:           make(chan findingWrite, cfg.BufferSize),
		ctx:          ctx,
		cancel:       cancel,
		bytesChanged: make(chan struct{}),
	}
	if w.saveBatch = cfg.saveBatch; w.saveBatch == nil {
		w.saveBatch = func(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
			return repo.SaveFindingsBatchResults(ctx, writes)
		}
	}

	w.wg.Add(1)
	go w.flushLoop()

	return w
}

// Save enqueues a finding for batched persistence. Byte admission may wait until
// ctx is cancelled or retained snapshots are released. Once admitted, a full
// count buffer (or closed writer) still persists inline; an enqueued finding is
// still fire-and-forget. A rejected admission is NOT accepted or persisted and
// returns an error to the caller. Safe for concurrent callers; the producer must
// not mutate the input until Save returns (as with the snapshot contract).
func (w *FindingWriter) Save(ctx context.Context, event *output.ResultEvent, recordUUIDs []string, scanUUID, projectUUID string) error {
	if event == nil {
		w.admissionFailed.Add(1)
		return fmt.Errorf("invalid ResultEvent")
	}
	if err := ctx.Err(); err != nil {
		w.admissionFailed.Add(1)
		return err
	}
	pendingBytes := estimateFindingBytes(event, recordUUIDs, scanUUID, projectUUID)
	if err := w.acquireBytes(ctx, pendingBytes); err != nil {
		w.admissionFailed.Add(1)
		return err
	}

	// Reserve BEFORE any owned allocation, especially evidence.CloneEntries.
	// The caller keeps the lease for cloning and inline persistence; only a
	// successful channel send transfers it to the background writer.
	transferred := false
	var fw findingWrite
	defer func() {
		if !transferred {
			fw = findingWrite{}
			event = nil
			recordUUIDs = nil
			w.releaseBytes(pendingBytes)
		}
	}()
	event = snapshotFindingEvent(event)
	recordUUIDs = cloneFindingUUIDs(recordUUIDs)
	scanUUID = strings.Clone(scanUUID)
	projectUUID = strings.Clone(projectUUID)
	fw = findingWrite{event: event, recordUUIDs: recordUUIDs, scanUUID: scanUUID, projectUUID: projectUUID, pendingBytes: pendingBytes}

	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		return w.saveInline(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
	// The non-blocking send happens under RLock so Close (which takes the write
	// lock before cancelling) can never race a send against the drain shutdown.
	select {
	case w.ch <- fw:
		transferred = true
		fw = findingWrite{}
		event = nil
		recordUUIDs = nil
		w.enqueued.Add(1)
		w.mu.RUnlock()
		return nil
	default:
		w.mu.RUnlock()
		return w.saveInline(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
}

func cloneFindingUUIDs(uuids []string) []string {
	if uuids == nil {
		return nil
	}
	owned := make([]string, len(uuids))
	for i, uuid := range uuids {
		owned[i] = strings.Clone(uuid)
	}
	return owned
}

// snapshotFindingEvent preserves the producer ownership contract. Metadata is
// deliberately not marshalled/unmarshalled: typed values keep their identity and
// the same shallow-copy contract as before byte admission was added.
func snapshotFindingEvent(event *output.ResultEvent) *output.ResultEvent {
	snapshot := *event
	// These strings participate in finding identity/attribution or persist as the
	// module/record identity. Own their bytes before the event can outlive Save.
	snapshot.ModuleID = strings.Clone(event.ModuleID)
	snapshot.Info.Name = strings.Clone(event.Info.Name)
	snapshot.Info.Description = strings.Clone(event.Info.Description)
	snapshot.Matched = strings.Clone(event.Matched)
	snapshot.DedupKey = strings.Clone(event.DedupKey)
	snapshot.OriginRecordUUID = strings.Clone(event.OriginRecordUUID)
	snapshot.RecordKind = output.RecordKind(strings.Clone(string(event.RecordKind)))
	snapshot.EvidenceGrade = output.EvidenceGrade(strings.Clone(string(event.EvidenceGrade)))
	snapshot.Info.Tags = append([]string(nil), event.Info.Tags...)
	snapshot.ExtractedResults = append([]string(nil), event.ExtractedResults...)
	snapshot.AdditionalEvidence = append([]string(nil), event.AdditionalEvidence...)
	snapshot.Evidence = evidence.CloneEntries(event.Evidence)
	for i := range snapshot.Evidence {
		entry := &snapshot.Evidence[i]
		entry.ExchangeID = strings.Clone(entry.ExchangeID)
		entry.OccurrenceID = strings.Clone(entry.OccurrenceID)
		entry.ScanUUID = strings.Clone(entry.ScanUUID)
		if entry.Exchange != nil {
			entry.Exchange.ID = strings.Clone(entry.Exchange.ID)
			entry.Exchange.ContentHash = strings.Clone(entry.Exchange.ContentHash)
			// Service and URL are inputs to Exchange.Hash. Own them with the
			// captured hash so queued validation sees the same receipt identity;
			// CloneEntries already owns the potentially large request/response bytes.
			entry.Exchange.Service = strings.Clone(entry.Exchange.Service)
			entry.Exchange.URL = strings.Clone(entry.Exchange.URL)
		}
	}
	if event.Metadata != nil {
		snapshot.Metadata = make(map[string]interface{}, len(event.Metadata))
		for key, value := range event.Metadata {
			if values, ok := value.([]string); ok {
				value = append([]string(nil), values...)
			}
			if values, ok := value.([]interface{}); ok {
				value = append([]interface{}(nil), values...)
			}
			snapshot.Metadata[key] = value
		}
	}
	return &snapshot
}

// acquireBytes does not hold the channel lifecycle lock while waiting. Shutdown
// interrupts a blocked admission explicitly, without pretending it was accepted.
// Saves starting after Close can still acquire available bytes and persist inline,
// but cannot bypass the budget if an earlier write remains wedged.
func (w *FindingWriter) acquireBytes(ctx context.Context, size int64) error {
	if size == maxFindingBytes {
		return fmt.Errorf("finding byte admission: retained size saturated; finding cannot fit MaxPendingBytes %d", w.cfg.MaxPendingBytes)
	}
	if size > w.cfg.MaxPendingBytes {
		return fmt.Errorf("finding byte admission: estimated %d bytes exceeds MaxPendingBytes %d", size, w.cfg.MaxPendingBytes)
	}
	waited := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if waited && w.ctx.Err() != nil {
			return fmt.Errorf("finding byte admission: writer shut down while waiting for retained bytes")
		}
		w.bytesMu.Lock()
		if err := ctx.Err(); err != nil {
			w.bytesMu.Unlock()
			return err
		}
		if size <= w.cfg.MaxPendingBytes-w.pendingBytes {
			w.pendingBytes += size
			if w.pendingBytes > w.peakPendingBytes {
				w.peakPendingBytes = w.pendingBytes
			}
			w.bytesMu.Unlock()
			return nil
		}
		changed := w.bytesChanged
		w.bytesMu.Unlock()
		waited = true
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.ctx.Done():
			return fmt.Errorf("finding byte admission: writer shut down while waiting for retained bytes")
		case <-changed:
		}
	}
}

func (w *FindingWriter) releaseBytes(size int64) {
	if size == 0 {
		return
	}
	w.bytesMu.Lock()
	w.pendingBytes -= size
	close(w.bytesChanged)
	w.bytesChanged = make(chan struct{})
	w.bytesMu.Unlock()
}

const maxFindingBytes int64 = 1<<63 - 1

// estimateFindingBytes measures the graph retained by a snapshot without JSON
// serialization (which would itself allocate another full copy of the evidence).
// Count immutable strings too: although not cloned, the writer pins their data.
// Reflection keeps typed metadata intact and covers future ResultEvent fields.
// Shared values are deliberately counted more than once; slices use capacity,
// plus padding for clone allocation rounding, and maps have a per-entry floor.
// This is a conservative admission estimate, not an allocator/RSS measurement:
// it cannot discover a substring's larger backing allocation or external state.
func estimateFindingBytes(event *output.ResultEvent, recordUUIDs []string, scanUUID, projectUUID string) int64 {
	size := findingRetainedBytes(reflect.ValueOf(event), 0)
	size = addFindingBytes(size, findingRetainedBytes(reflect.ValueOf(recordUUIDs), 0))
	size = addFindingBytes(size, int64(len(scanUUID)))
	size = addFindingBytes(size, int64(len(projectUUID)))
	// Queue slot, lease, batch and temporary FindingWrite headers, including
	// allocation padding. Even an otherwise empty finding has a real byte cost.
	return addFindingBytes(size, 512)
}

func addFindingBytes(a, b int64) int64 {
	if a >= maxFindingBytes-b {
		return maxFindingBytes
	}
	return a + b
}

func multiplyFindingBytes(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > maxFindingBytes/b {
		return maxFindingBytes
	}
	return a * b
}

func findingRetainedBytes(value reflect.Value, depth int) int64 {
	if !value.IsValid() {
		return 0
	}
	// Cyclic or excessively deep metadata cannot be safely sized with bounded
	// work. Saturation makes it an explicit oversize admission error, not a hang.
	if depth >= 32 {
		return maxFindingBytes
	}
	size := addFindingBytes(int64(value.Type().Size()), 32)
	if value.Type() == reflect.TypeOf(time.Time{}) {
		// Do not walk time.Location's private cache/recursive timezone graph.
		return addFindingBytes(size, 256)
	}
	switch value.Kind() {
	case reflect.String:
		return addFindingBytes(size, int64(value.Len()))
	case reflect.Interface, reflect.Pointer:
		if !value.IsNil() {
			size = addFindingBytes(size, findingRetainedBytes(value.Elem(), depth+1))
		}
	case reflect.Slice, reflect.Array:
		capacity := value.Len()
		if value.Kind() == reflect.Slice {
			capacity = value.Cap()
		}
		elementSize := int64(value.Type().Elem().Size())
		if elementSize == 0 {
			elementSize = 16
		}
		// Twice capacity covers allocation size-class rounding of owned clones.
		size = addFindingBytes(size, multiplyFindingBytes(int64(capacity), multiplyFindingBytes(elementSize, 2)))
		kind := value.Type().Elem().Kind()
		if kind != reflect.String && kind != reflect.Interface && kind != reflect.Pointer && kind != reflect.Slice && kind != reflect.Array && kind != reflect.Map && kind != reflect.Struct {
			return size
		}
		for i := 0; i < value.Len() && size < maxFindingBytes; i++ {
			size = addFindingBytes(size, findingRetainedBytes(value.Index(i), depth+1))
		}
	case reflect.Map:
		// A one-byte key/value still needs bucket/control/header storage. This
		// floor prevents many tiny metadata entries from evading backpressure.
		size = addFindingBytes(size, 128)
		size = addFindingBytes(size, multiplyFindingBytes(int64(value.Len()), 128))
		entries := value.MapRange()
		for size < maxFindingBytes && entries.Next() {
			size = addFindingBytes(size, findingRetainedBytes(entries.Key(), depth+1))
			size = addFindingBytes(size, findingRetainedBytes(entries.Value(), depth+1))
		}
	case reflect.Struct:
		for i := 0; i < value.NumField() && size < maxFindingBytes; i++ {
			size = addFindingBytes(size, findingRetainedBytes(value.Field(i), depth+1))
		}
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		if !value.IsNil() {
			// Opaque objects can pin arbitrary data and cannot be inspected without
			// changing producer state. JSON persistence cannot encode them either.
			return maxFindingBytes
		}
	}
	return size
}

// saveInline persists a finding synchronously and counts the attempt. The failure
// count matters because Save's error goes to a caller that usually only logs it,
// so an inline save that failed was invisible in the shutdown accounting even
// though the finding is just as lost as one dropped by a flush.
func (w *FindingWriter) saveInline(ctx context.Context, event *output.ResultEvent, recordUUIDs []string, scanUUID, projectUUID string) error {
	w.inline.Add(1)
	var (
		inserted bool
		err      error
	)
	if w.cfg.saveBatch != nil {
		// The configured test seam also controls inline writes. Production keeps
		// the existing single-finding repository path and its callbacks.
		writes := []FindingWrite{{Event: event, HTTPRecordUUIDs: recordUUIDs, ScanUUID: scanUUID, ProjectUUID: projectUUID}}
		defer clear(writes)
		results := w.saveBatch(ctx, writes)
		if len(results) == 0 {
			err = fmt.Errorf("finding inline save returned no outcome")
		} else {
			err = results[0].Err
			inserted = results[0].Inserted
		}
	} else {
		inserted, err = w.repo.SaveFindingInserted(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
	if err != nil {
		w.inlineFailed.Add(1)
		return err
	}
	w.inlineWritten.Add(1)
	if inserted {
		w.notifyInserted(event)
	}
	return nil
}

// SetOnInserted installs the new-finding callback (nil clears it). Safe to
// call while the writer runs.
func (w *FindingWriter) SetOnInserted(fn func(*output.ResultEvent)) {
	if w == nil {
		return
	}
	if fn == nil {
		w.onInserted.Store(nil)
		return
	}
	w.onInserted.Store(&fn)
}

func (w *FindingWriter) notifyInserted(event *output.ResultEvent) {
	if fn := w.onInserted.Load(); fn != nil && event != nil {
		(*fn)(event)
	}
}

// Metrics returns a snapshot of the writer's counters.
func (w *FindingWriter) Metrics() FindingWriterMetrics {
	w.bytesMu.Lock()
	pending, peak := w.pendingBytes, w.peakPendingBytes
	w.bytesMu.Unlock()
	return FindingWriterMetrics{
		Enqueued:         w.enqueued.Load(),
		Written:          w.written.Load(),
		Inline:           w.inline.Load(),
		InlineFailed:     w.inlineFailed.Load(),
		Errors:           w.errors.Load(),
		AdmissionFailed:  w.admissionFailed.Load(),
		PendingBytes:     pending,
		PeakPendingBytes: peak,
	}
}

// Close stops accepting new findings, flushes the buffer, and returns. After
// Close, admitted Saves persist synchronously (without bypassing the byte budget).
// Prefer Shutdown when the caller can report what happened; Close is the
// fire-and-forget form kept for existing call sites.
func (w *FindingWriter) Close() { _ = w.Shutdown() }

// Shutdown stops accepting new queued findings, drains the buffer, and reports
// accepted writes and pre-acceptance rejections observed before the snapshot.
// Saves after the once-only snapshot do not change the returned outcome.
//
// One absolute deadline (now+FlushTimeout) governs the whole shutdown and is
// published before the drain is woken, so the drain's flushes and the wait for the
// goroutine to exit share a single budget instead of each starting its own.
//
// Idempotent: the outcome is computed once and every later or concurrent caller
// gets that same value, so two phases closing the same writer cannot report the
// same findings twice.
// A nil writer is a no-op reporting a zero (clean) outcome — see
// RecordWriter.Shutdown for why that lives here rather than at every call site.
func (w *FindingWriter) Shutdown() PersistenceOutcome {
	if w == nil {
		return PersistenceOutcome{Writer: PersistenceWriterFindings}
	}
	w.shutdown.once.Do(func() {
		// Published BEFORE cancel: the drain branch reads it the moment it wakes.
		deadline := w.shutdown.publish(w.cfg.FlushTimeout)

		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()
		// No send can be in flight now (Save holds RLock during its send, and we
		// hold the write lock above until all such sends complete), and no new send
		// will start because Save sees closed==true. Safe to wake the drain.
		w.cancel()

		timedOut := !waitBounded(&w.wg, time.Until(deadline))

		enqueued := w.enqueued.Load()
		written := w.written.Load()
		errCount := w.errors.Load()
		inlineWritten := w.inlineWritten.Load()
		inlineFailed := w.inlineFailed.Load()
		// Read attempts AFTER completions so even concurrent inline saves cannot
		// make known outcomes exceed Accepted. In-flight attempts are Unknown,
		// not optimistically counted as committed just because Save started.
		inline := w.inline.Load()

		w.shutdown.outcome = PersistenceOutcome{
			Writer:    PersistenceWriterFindings,
			Accepted:  enqueued + inline,
			Committed: written + inlineWritten,
			Failed:    errCount + inlineFailed,
			Rejected:  w.admissionFailed.Load(),
			// Queued, mid-flush and in-flight inline writes may yet land; calling
			// them lost would be as wrong as calling them stored. Rejected writes
			// never entered Accepted and must not inflate Failed or Unknown.
			Unknown:  nonNegative(enqueued - written - errCount + inline - inlineWritten - inlineFailed),
			TimedOut: timedOut,
		}

		// Surface fire-and-forget persistence failures at shutdown. Save returns nil
		// as soon as a finding is enqueued, so a later batch failure is otherwise
		// invisible — the scan would complete reporting success while silently having
		// dropped findings. This warning lands in the scan's captured stderr/log.
		if o := w.shutdown.outcome; !o.Clean() {
			zap.L().Warn("FindingWriter: some findings may not have been persisted",
				zap.Int64("failed", o.Failed),
				zap.Int64("rejected", o.Rejected),
				zap.Int64("unknown", o.Unknown),
				zap.Int64("committed", o.Committed),
				zap.Int64("accepted", o.Accepted),
				zap.Bool("timed_out", o.TimedOut))
		}
	})
	return w.shutdown.outcome
}

// flushLoop drains the channel and coalesces findings into batch transactions.
//
// Steady-state flushes never inherit the scan's context — cancelling a scan
// mid-transaction would abort findings already pulled off the channel — but they
// are bounded by OperationTimeout, so a wedged database fails the batch instead of
// parking this goroutine for the rest of the process. The shutdown drain runs on
// the single absolute deadline Shutdown published.
func (w *FindingWriter) flushLoop() {
	defer w.wg.Done()

	batch := make([]findingWrite, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case fw := <-w.ch:
			batch = append(batch, fw)
			fw = findingWrite{}
			if len(batch) >= w.cfg.BatchSize {
				w.flushBounded(batch)
				batch = resetFindingBatch(batch)
				ticker.Reset(w.cfg.FlushInterval)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.flushBounded(batch)
				batch = resetFindingBatch(batch)
			}

		case <-w.ctx.Done():
			drainCtx, cancel := context.WithDeadline(context.Background(), w.shutdown.drainDeadline(w.cfg.FlushTimeout))
			defer cancel()
			for {
				select {
				case fw := <-w.ch:
					batch = append(batch, fw)
					fw = findingWrite{}
					if len(batch) >= w.cfg.BatchSize {
						w.flush(drainCtx, batch)
						batch = resetFindingBatch(batch)
					}
				default:
					if len(batch) > 0 {
						w.flush(drainCtx, batch)
					}
					return
				}
			}
		}
	}
}

// flushBounded runs one steady-state flush under OperationTimeout, detached from
// any caller's context.
func (w *FindingWriter) flushBounded(batch []findingWrite) {
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.OperationTimeout)
	defer cancel()
	w.flush(ctx, batch)
}

// resetFindingBatch empties a flushed batch for reuse, clearing the entries
// first. This mirrors resetBatch in record_writer.go, for the same reason: a
// plain batch[:0] leaves the backing array's pointers live, so after a flush the
// loop still pins up to BatchSize findings — each one a *output.ResultEvent
// holding the full request, response and additional evidence that produced it.
// Findings are low-volume, so the writer is idle most of the time, and that is
// exactly when the stale retention lasts longest.
func resetFindingBatch(batch []findingWrite) []findingWrite {
	clear(batch)
	return batch[:0]
}

// flush persists a batch of findings in a single transaction and counts the
// per-finding outcomes exactly.
//
// The batch save already retries each finding individually when the transaction
// fails, so most "failed" batches persisted nearly all of their findings. Charging
// the whole batch to errors on any error therefore reported findings as dropped
// that are sitting in the database, and inflated the shutdown warning by up to
// BatchSize per incident.
func (w *FindingWriter) flush(ctx context.Context, batch []findingWrite) {
	writes := make([]FindingWrite, len(batch))
	// Both backing arrays must stop retaining snapshots BEFORE waking byte
	// waiters. This runs on normal success, aligned per-item failure and panic;
	// panic propagation and persistence outcome handling otherwise stay unchanged.
	defer func() {
		clear(writes)
		var released int64
		for i := range batch {
			released += batch[i].pendingBytes
			batch[i] = findingWrite{}
		}
		w.releaseBytes(released)
	}()
	for i, b := range batch {
		writes[i] = FindingWrite{
			Event:           b.event,
			HTTPRecordUUIDs: b.recordUUIDs,
			ScanUUID:        b.scanUUID,
			ProjectUUID:     b.projectUUID,
		}
	}

	results := w.saveBatch(ctx, writes)

	var ok, failed int64
	var firstErr error
	for i := range writes {
		// A result slice shorter than the input would silently drop findings from
		// the accounting, so anything unaccounted for counts as failed.
		if i >= len(results) || results[i].Err != nil {
			failed++
			if firstErr == nil && i < len(results) {
				firstErr = results[i].Err
			}
			continue
		}
		ok++
		if results[i].Inserted {
			w.notifyInserted(writes[i].Event)
		}
	}

	w.written.Add(ok)
	w.errors.Add(failed)
	if failed > 0 {
		zap.L().Warn("FindingWriter: some findings in a batch failed to persist",
			zap.Int("batch_size", len(batch)),
			zap.Int64("failed", failed),
			zap.Int64("persisted", ok),
			zap.Error(firstErr))
	}
}
