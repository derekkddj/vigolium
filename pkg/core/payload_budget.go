package core

import (
	"fmt"
	"strings"
	"sync"
)

// DefaultPayloadBudgetBytes is a finite admission default, not an RSS limit.
const DefaultPayloadBudgetBytes int64 = 1 << 30

var processPayloadBudget = NewPayloadBudget(DefaultPayloadBudgetBytes)

// ProcessPayloadBudget returns the process-wide default. Executors with no
// explicit budget must share this pointer, including successive rounds. Do not
// replace or reset it at run exit: abandoned actual calls still own their leases.
func ProcessPayloadBudget() *PayloadBudget { return processPayloadBudget }

// PayloadBudget accounts for retained HTTP payload reservations. It neither
// waits nor owns cancellation, ACKs, queues, or goroutines. A lease remains
// charged until its owner explicitly releases it, even after Execute returns.
//
// The zero value uses the finite default. A PayloadBudget must not be copied.
// Share a pointer across all executors belonging to the same memory domain.
type PayloadBudget struct {
	mu      sync.Mutex
	limit   int64
	used    int64
	peak    int64
	changed chan struct{}
}

// PayloadBudgetStats is one consistent, lock-protected accounting snapshot.
// PeakBytes is a lifetime high-water mark; it is not reset between executions.
type PayloadBudgetStats struct {
	UsedBytes  int64
	PeakBytes  int64
	LimitBytes int64
}

// NewPayloadBudget constructs an independent budget. Non-positive limits use
// the finite 1 GiB default; they never disable admission. To use the process
// default rather than an independent budget, call ProcessPayloadBudget.
func NewPayloadBudget(limit int64) *PayloadBudget {
	if limit <= 0 {
		limit = DefaultPayloadBudgetBytes
	}
	return &PayloadBudget{limit: limit, changed: make(chan struct{})}
}

// initLocked supports the zero value. The caller must hold b.mu.
func (b *PayloadBudget) initLocked() {
	if b.limit <= 0 {
		b.limit = DefaultPayloadBudgetBytes
	}
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
}

func (b *PayloadBudget) Stats() PayloadBudgetStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initLocked()
	return PayloadBudgetStats{UsedBytes: b.used, PeakBytes: b.peak, LimitBytes: b.limit}
}

// TryAcquire returns exactly one of:
//   - a lease, with nil changed and nil error;
//   - a capacity-change channel, with nil lease and nil error;
//   - a permanent MemoryAdmissionError, with nil lease and nil changed.
//
// A negative request or a request exceeding the total limit is permanent. Zero
// is allowed; callers account for tiny objects in their payload estimator.
// Temporary pressure does not allocate an error or a waiter goroutine.
//
// The capacity check and subscription happen under the SAME lock as Release.
// A positive release closes the subscribed channel and publishes a fresh one
// under that lock, so a release between this return and select cannot be lost.
// Channels broadcast an opportunity to retry, not a grant or a fairness promise.
// Callers select on changed, cancellation, feedback, and their own stop signal.
func (b *PayloadBudget) TryAcquire(requiredBytes int64) (*PayloadLease, <-chan struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.initLocked()
	if requiredBytes < 0 || requiredBytes > b.limit {
		return nil, nil, NewMemoryAdmissionError("payload", requiredBytes, b.limit, "")
	}
	// Subtraction is safe under 0 <= used <= limit; adding an untrusted
	// requiredBytes before checking would permit int64 overflow.
	if requiredBytes > b.limit-b.used {
		return nil, b.changed, nil
	}
	b.used += requiredBytes
	if b.used > b.peak {
		b.peak = b.used
	}
	return &PayloadLease{budget: b, bytes: requiredBytes}, nil, nil
}

// PayloadLease is a single reservation. Transfer its pointer between queues,
// dispatcher, tracker, and real-call ownership; do not copy the value or acquire
// the same item's bytes again. A watchdog timeout must not release this lease.
type PayloadLease struct {
	budget *PayloadBudget
	bytes  int64
	once   sync.Once
}

// Release is nil-safe and idempotent, including concurrent and late releases.
// No time, context, executor lifecycle, or finalizer releases a lease implicitly.
func (l *PayloadLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.budget == nil || l.bytes == 0 {
			return
		}
		b := l.budget
		b.mu.Lock()
		defer b.mu.Unlock()
		b.used -= l.bytes
		close(b.changed)
		b.changed = make(chan struct{})
	})
}

const (
	memoryAdmissionStageBytes      = 64
	memoryAdmissionRecordUUIDBytes = 128
)

// MemoryAdmissionError describes an impossible or refused payload admission.
// Queueing, cancellation, partial execution, and no-ACK policy belong to callers.
// Use NewMemoryAdmissionError rather than retaining arbitrary input in a literal.
type MemoryAdmissionError struct {
	Stage         string
	RequiredBytes int64
	LimitBytes    int64
	RecordUUID    string
}

// NewMemoryAdmissionError owns bounded diagnostic strings. Copying even a short
// substring is intentional: it must not pin a large source string's allocation.
func NewMemoryAdmissionError(stage string, requiredBytes, limitBytes int64, recordUUID string) *MemoryAdmissionError {
	return &MemoryAdmissionError{
		Stage:         boundedAdmissionLabel(stage, memoryAdmissionStageBytes),
		RequiredBytes: requiredBytes,
		LimitBytes:    limitBytes,
		RecordUUID:    boundedAdmissionLabel(recordUUID, memoryAdmissionRecordUUIDBytes),
	}
}

func (e *MemoryAdmissionError) Error() string {
	stage := boundedAdmissionLabel(e.Stage, memoryAdmissionStageBytes)
	record := boundedAdmissionLabel(e.RecordUUID, memoryAdmissionRecordUUIDBytes)
	if e.RequiredBytes < 0 {
		return fmt.Sprintf("memory admission at %q for record %q: invalid negative payload size %d bytes (limit %d bytes)", stage, record, e.RequiredBytes, e.LimitBytes)
	}
	return fmt.Sprintf("memory admission at %q for record %q: requires %d payload bytes, limit %d bytes", stage, record, e.RequiredBytes, e.LimitBytes)
}

func boundedAdmissionLabel(value string, limit int) string {
	if len(value) > limit {
		return value[:limit-3] + "..."
	}
	return strings.Clone(value)
}
