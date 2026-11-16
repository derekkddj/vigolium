package database

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

// Done is first consulted when admission actually needs to wait. This lets tests
// observe a blocked Save deterministically, without sleeping or a writer hook.
type findingMemoryWaitContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *findingMemoryWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func findingMemoryAwait(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("finding writer memory test stalled")
	}
}

func findingMemoryAwaitError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("Save did not return")
		return nil
	}
}

type findingMemoryTypedMetadata struct {
	Index int
	Text  string
}

func findingMemoryEvent(index, payloadBytes int) *output.ResultEvent {
	id := fmt.Sprintf("%04d", index)
	return &output.ResultEvent{
		ModuleID: id,
		Info: output.Info{
			Tags:      []string{"original-tag"},
			Reference: []string{"original-reference"},
		},
		Request:            strings.Repeat("q", 8192),
		Response:           strings.Repeat(id, 16384),
		AdditionalEvidence: []string{strings.Repeat("a", 8192)},
		ExtractedResults:   []string{strings.Repeat("x", 4096)},
		Metadata: map[string]interface{}{
			"strings": []string{"original-metadata"},
			"values":  []interface{}{"original-value"},
			"typed":   findingMemoryTypedMetadata{Index: index, Text: "typed-value"},
		},
		Evidence: []evidence.Entry{{
			Label: "original-label",
			Exchange: &evidence.Exchange{
				ID:       id,
				Request:  []byte("original-request"),
				Response: []byte(strings.Repeat(id, payloadBytes/len(id))),
			},
		}},
	}
}

func findingMemoryMutateProducer(event *output.ResultEvent, records []string) {
	event.Info.Tags[0] = "changed"
	event.Request = "changed"
	event.Response = "changed"
	event.AdditionalEvidence[0] = "changed"
	event.ExtractedResults[0] = "changed"
	event.Metadata["strings"].([]string)[0] = "changed"
	event.Metadata["values"].([]interface{})[0] = "changed"
	event.Metadata["typed"] = "changed"
	event.Evidence[0].Label = "changed"
	event.Evidence[0].Exchange.Request[0] = 'X'
	event.Evidence[0].Exchange.Response[0] = 'X'
	records[0] = "changed"
}

func findingMemorySnapshotError(write FindingWrite) error {
	event := write.Event
	if event == nil {
		return errors.New("nil finding snapshot")
	}
	if event.Info.Tags[0] != "original-tag" || event.Info.Reference[0] != "original-reference" ||
		event.Request != strings.Repeat("q", 8192) || event.Response != strings.Repeat(event.ModuleID, 16384) ||
		event.AdditionalEvidence[0] != strings.Repeat("a", 8192) || event.ExtractedResults[0] != strings.Repeat("x", 4096) ||
		event.Metadata["strings"].([]string)[0] != "original-metadata" || event.Metadata["values"].([]interface{})[0] != "original-value" ||
		event.Evidence[0].Label != "original-label" || string(event.Evidence[0].Exchange.Request) != "original-request" ||
		event.Evidence[0].Exchange.Response[0] != event.ModuleID[0] || write.HTTPRecordUUIDs[0] != "record-"+event.ModuleID ||
		write.ScanUUID != "scan" || write.ProjectUUID != "project" {
		return fmt.Errorf("producer mutation reached finding %s", event.ModuleID)
	}
	if typed, ok := event.Metadata["typed"].(findingMemoryTypedMetadata); !ok || typed.Text != "typed-value" {
		return fmt.Errorf("typed metadata changed in finding %s", event.ModuleID)
	}
	return nil
}

func TestFindingWriterMemory_QueuedFlushAndConcurrentInlineBound(t *testing.T) {
	const count = 40
	events := make([]*output.ResultEvent, count)
	records := make([][]string, count)
	for i := range events {
		events[i] = findingMemoryEvent(i, 256<<10)
		records[i] = []string{"record-" + events[i].ModuleID}
	}
	weight := estimateFindingBytes(events[0], records[0], "scan", "project")
	for i := range events {
		if got := estimateFindingBytes(events[i], records[i], "scan", "project"); got != weight {
			t.Fatalf("fixture %d weight = %d, want %d", i, got, weight)
		}
	}

	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	entered := make(chan string, count)
	var seenMu sync.Mutex
	seen := make(map[string]int)
	w := NewFindingWriter(nil, FindingWriterConfig{
		BufferSize:      1,
		BatchSize:       1,
		FlushInterval:   time.Hour,
		MaxPendingBytes: 4 * weight,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			entered <- writes[0].Event.ModuleID
			<-release
			results := make([]FindingSaveResult, len(writes))
			for i, write := range writes {
				results[i].Err = findingMemorySnapshotError(write)
				seenMu.Lock()
				seen[write.Event.ModuleID]++
				seenMu.Unlock()
			}
			return results
		},
	})
	t.Cleanup(func() { unblock(); w.Close() })

	if err := w.Save(context.Background(), events[0], records[0], "scan", "project"); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-entered:
		if id != "0000" {
			t.Fatalf("first flush = %s", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("seed never entered the blocked flush")
	}
	findingMemoryMutateProducer(events[0], records[0])
	if err := w.Save(context.Background(), events[1], records[1], "scan", "project"); err != nil {
		t.Fatal(err)
	}
	findingMemoryMutateProducer(events[1], records[1])

	returned := make(chan error, count)
	for i := 2; i < 4; i++ {
		go func(i int) {
			err := w.Save(context.Background(), events[i], records[i], "scan", "project")
			findingMemoryMutateProducer(events[i], records[i])
			returned <- err
		}(i)
	}
	for i := 0; i < 2; i++ {
		select {
		case id := <-entered:
			if id != "0002" && id != "0003" {
				t.Fatalf("expected concurrent inline save, got %s", id)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("full count queue did not persist inline")
		}
	}
	if m := w.Metrics(); m.PendingBytes != 4*weight || m.PeakPendingBytes != 4*weight || m.Enqueued != 2 || m.Inline != 2 {
		t.Fatalf("queued + flushing + inline leases not all charged: %+v", m)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	waitCtx := &findingMemoryWaitContext{Context: cancelCtx, observed: make(chan struct{})}
	rejected := make(chan error, 1)
	go func() { rejected <- w.Save(waitCtx, events[4], records[4], "scan", "project") }()
	findingMemoryAwait(t, waitCtx.observed)
	cancel()
	if err := findingMemoryAwaitError(t, rejected); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting Save error = %v, want cancellation", err)
	}

	// All remaining producers must wait before cloning. Releasing the DB gate
	// then admits each one; none may bypass the shared byte limit via inline IO.
	for i := 5; i < count; i++ {
		waitCtx := &findingMemoryWaitContext{Context: context.Background(), observed: make(chan struct{})}
		go func(i int, ctx context.Context) {
			err := w.Save(ctx, events[i], records[i], "scan", "project")
			findingMemoryMutateProducer(events[i], records[i])
			returned <- err
		}(i, waitCtx)
		findingMemoryAwait(t, waitCtx.observed)
	}
	if m := w.Metrics(); m.PendingBytes != 4*weight || m.AdmissionFailed != 1 || m.Written != 0 || m.Errors != 0 || m.InlineFailed != 0 {
		t.Fatalf("blocked admission changed acceptance/persistence accounting: %+v", m)
	}
	unblock()
	for i := 0; i < count-3; i++ {
		if err := findingMemoryAwaitError(t, returned); err != nil {
			t.Fatal(err)
		}
	}
	outcome := w.Shutdown()
	m := w.Metrics()
	if m.PendingBytes != 0 || m.PeakPendingBytes != w.cfg.MaxPendingBytes || m.Enqueued+m.Inline != count-1 ||
		m.Written+m.Errors != m.Enqueued || m.Errors != 0 || m.InlineFailed != 0 || m.AdmissionFailed != 1 {
		t.Fatalf("unexpected final memory/persistence accounting: %+v", m)
	}
	// The cancelled finding was never accepted. All other findings committed,
	// but that one rejection still makes overall persistence incomplete.
	if outcome.Accepted != count-1 || outcome.Committed != count-1 || outcome.Rejected != 1 ||
		outcome.Failed != 0 || outcome.Unknown != 0 || outcome.TimedOut || outcome.Clean() {
		t.Fatalf("accepted findings were lost or rejection was hidden: %+v", outcome)
	}
	seenMu.Lock()
	defer seenMu.Unlock()
	for i := 0; i < count; i++ {
		want := 1
		if i == 4 {
			want = 0
		}
		if got := seen[fmt.Sprintf("%04d", i)]; got != want {
			t.Errorf("persistence calls for finding %d = %d, want %d", i, got, want)
		}
	}
}

func TestFindingWriterMemory_CancellationBeforeClone(t *testing.T) {
	const payloadBytes = 8 << 20
	seed, candidate := findingMemoryEvent(0, payloadBytes), findingMemoryEvent(1, payloadBytes)
	weight := estimateFindingBytes(seed, nil, "", "")
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	w := NewFindingWriter(nil, FindingWriterConfig{
		BatchSize:       1,
		MaxPendingBytes: weight,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			close(entered)
			<-release
			return make([]FindingSaveResult, len(writes))
		},
	})
	t.Cleanup(func() { unblock(); w.Close() })
	if err := w.Save(context.Background(), seed, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	findingMemoryAwait(t, entered)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	waitCtx := &findingMemoryWaitContext{Context: ctx, observed: make(chan struct{})}
	returned := make(chan error, 1)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	go func() { returned <- w.Save(waitCtx, candidate, nil, "", "") }()
	findingMemoryAwait(t, waitCtx.observed)
	cancel()
	if err := findingMemoryAwaitError(t, returned); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save error = %v, want cancellation", err)
	}
	runtime.ReadMemStats(&after)
	// TotalAlloc (not live heap) detects a clone even if it was freed on cancel.
	// The fixture's raw response alone would allocate 8 MiB if cloned too early.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= payloadBytes {
		t.Fatalf("cancelled admission allocated %d bytes; evidence appears cloned before admission", allocated)
	}
	if m := w.Metrics(); m.PendingBytes != weight || m.Enqueued != 1 || m.Inline != 0 || m.AdmissionFailed != 1 {
		t.Fatalf("cancelled waiter was accepted or released someone else's lease: %+v", m)
	}
	if allocations := testing.AllocsPerRun(3, func() {
		if err := w.Save(ctx, candidate, nil, "", ""); !errors.Is(err, context.Canceled) {
			t.Errorf("already-cancelled Save error = %v", err)
		}
	}); allocations != 0 {
		t.Fatalf("already-cancelled Save allocates %.0f objects before rejecting admission", allocations)
	}
}

func TestFindingWriterMemory_OversizeExplicitError(t *testing.T) {
	event := findingMemoryEvent(0, 1<<20)
	before := snapshotFindingEvent(event)
	weight := estimateFindingBytes(event, nil, "", "")
	w := NewFindingWriter(nil, FindingWriterConfig{
		MaxPendingBytes: weight - 1,
		saveBatch: func(context.Context, []FindingWrite) []FindingSaveResult {
			t.Error("oversize finding reached persistence")
			return nil
		},
	})
	t.Cleanup(w.Close)
	if err := w.Save(context.Background(), event, nil, "", ""); err == nil || !strings.Contains(err.Error(), "MaxPendingBytes") {
		t.Fatalf("oversize Save error = %v, want explicit byte limit error", err)
	}
	if !reflect.DeepEqual(event, before) {
		t.Fatal("estimating/rejecting admission changed the producer event or typed metadata")
	}
	if m := w.Metrics(); m.PendingBytes != 0 || m.PeakPendingBytes != 0 || m.AdmissionFailed != 1 ||
		m.Enqueued != 0 || m.Written != 0 || m.Errors != 0 || m.Inline != 0 || m.InlineFailed != 0 {
		t.Fatalf("oversize rejection miscounted persistence: %+v", m)
	}
	if outcome := w.Shutdown(); outcome.Accepted != 0 || outcome.Committed != 0 || outcome.Rejected != 1 ||
		outcome.Failed != 0 || outcome.Unknown != 0 || outcome.TimedOut || outcome.Clean() {
		t.Fatalf("admission failure was fabricated into acceptance or hidden: %+v", outcome)
	}
}

func TestFindingWriterMemory_ShutdownWakesWaitersWithoutBudgetBypass(t *testing.T) {
	event := findingMemoryEvent(0, 256<<10)
	weight := estimateFindingBytes(event, nil, "", "")
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	w := NewFindingWriter(nil, FindingWriterConfig{
		BatchSize:        1,
		MaxPendingBytes:  weight,
		FlushTimeout:     50 * time.Millisecond,
		OperationTimeout: time.Hour,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			enteredOnce.Do(func() { close(entered) })
			<-release // deliberately ignores deadlines, like a wedged DB driver
			return make([]FindingSaveResult, len(writes))
		},
	})
	t.Cleanup(func() { unblock(); w.Close() })
	if err := w.Save(context.Background(), event, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	findingMemoryAwait(t, entered)
	waitCtx := &findingMemoryWaitContext{Context: context.Background(), observed: make(chan struct{})}
	returned := make(chan error, 1)
	go func() { returned <- w.Save(waitCtx, event, nil, "", "") }()
	findingMemoryAwait(t, waitCtx.observed)
	shutdownResult := make(chan PersistenceOutcome, 1)
	go func() { shutdownResult <- w.Shutdown() }()
	if err := findingMemoryAwaitError(t, returned); err == nil || !strings.Contains(err.Error(), "shut down") {
		t.Fatalf("shutdown waiter error = %v, want explicit rejection", err)
	}
	var outcome PersistenceOutcome
	select {
	case outcome = <-shutdownResult:
	case <-time.After(time.Second):
		t.Fatal("byte waiter held lifecycle RLock and blocked Shutdown")
	}
	if !outcome.TimedOut || outcome.Accepted != 1 || outcome.Unknown != 1 || outcome.Committed != 0 || outcome.Failed != 0 {
		t.Fatalf("wedged accepted flush should remain unknown: %+v", outcome)
	}
	// After Close the inline fallback must NOT ignore an outstanding byte lease.
	if err := w.Save(context.Background(), event, nil, "", ""); err == nil {
		t.Fatal("post-shutdown inline save bypassed the occupied byte budget")
	}
	if m := w.Metrics(); m.PendingBytes != weight || m.PeakPendingBytes != weight || m.AdmissionFailed != 2 || m.Inline != 0 {
		t.Fatalf("shutdown released a still-retained snapshot or accepted a waiter: %+v", m)
	}
	unblock()
	finished := make(chan struct{})
	go func() { w.wg.Wait(); close(finished) }()
	findingMemoryAwait(t, finished)
	if m := w.Metrics(); m.PendingBytes != 0 || m.Written != 1 {
		t.Fatalf("finished timed-out flush did not release its lease: %+v", m)
	}
	if err := w.Save(context.Background(), event, nil, "", ""); err != nil {
		t.Fatalf("post-close save with available bytes must remain synchronous: %v", err)
	}
	if m := w.Metrics(); m.PendingBytes != 0 || m.Inline != 1 || m.InlineFailed != 0 {
		t.Fatalf("post-close inline lease leaked: %+v", m)
	}
	if got := w.Shutdown(); !reflect.DeepEqual(got, outcome) {
		t.Fatalf("late completion changed the once-only shutdown outcome: got %+v, want %+v", got, outcome)
	}
}

func TestFindingWriterMemory_FailedFlushReleasesWaitingSave(t *testing.T) {
	first, second := findingMemoryEvent(0, 256<<10), findingMemoryEvent(1, 256<<10)
	weight := estimateFindingBytes(first, nil, "", "")
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	failure := errors.New("controlled flush failure")
	calls := 0 // only the background writer can enter: the budget fits one finding
	w := NewFindingWriter(nil, FindingWriterConfig{
		BufferSize:      1,
		BatchSize:       1,
		MaxPendingBytes: weight,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			calls++
			if calls == 1 {
				close(entered)
				<-release
				return []FindingSaveResult{{Err: failure}}
			}
			return make([]FindingSaveResult, len(writes))
		},
	})
	t.Cleanup(func() { unblock(); w.Close() })
	if err := w.Save(context.Background(), first, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	findingMemoryAwait(t, entered)
	waitCtx := &findingMemoryWaitContext{Context: context.Background(), observed: make(chan struct{})}
	returned := make(chan error, 1)
	go func() { returned <- w.Save(waitCtx, second, nil, "", "") }()
	findingMemoryAwait(t, waitCtx.observed)
	unblock()
	if err := findingMemoryAwaitError(t, returned); err != nil {
		t.Fatalf("failure did not release bytes for the next Save: %v", err)
	}
	outcome := w.Shutdown()
	if m := w.Metrics(); m.PendingBytes != 0 || m.PeakPendingBytes != weight || m.Enqueued != 2 || m.Written != 1 ||
		m.Errors != 1 || m.Inline != 0 || m.AdmissionFailed != 0 {
		t.Fatalf("accepted failure or released lease miscounted: %+v", m)
	}
	if outcome.Accepted != 2 || outcome.Committed != 1 || outcome.Failed != 1 || outcome.Unknown != 0 || outcome.TimedOut {
		t.Fatalf("flush failure disappeared from shutdown accounting: %+v", outcome)
	}
}

func TestFindingWriterMemory_FlushReleasesAndClearsEveryOutcome(t *testing.T) {
	failure := errors.New("controlled per-item failure")
	for _, tc := range []struct {
		name    string
		results []FindingSaveResult
		panic   bool
		written int64
		failed  int64
	}{
		{name: "success", results: make([]FindingSaveResult, 3), written: 3},
		{name: "partial", results: []FindingSaveResult{{}, {Err: failure}, {}}, written: 2, failed: 1},
		{name: "short", results: []FindingSaveResult{{}}, written: 1, failed: 2},
		{name: "failure", results: []FindingSaveResult{{Err: failure}, {Err: failure}, {Err: failure}}, failed: 3},
		{name: "panic", panic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var retainedWrites []FindingWrite
			w := NewFindingWriter(nil, FindingWriterConfig{
				saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
					retainedWrites = writes // observe backing slots, not a copied event
					if tc.panic {
						panic("controlled flush panic")
					}
					return tc.results
				},
			})
			w.Close() // invoke flush directly so panic can be recovered by this test
			batch := make([]findingWrite, 3)
			for i := range batch {
				event := findingMemoryEvent(i, 64<<10)
				weight := estimateFindingBytes(event, nil, "", "")
				if err := w.acquireBytes(context.Background(), weight); err != nil {
					t.Fatal(err)
				}
				batch[i] = findingWrite{event: snapshotFindingEvent(event), pendingBytes: weight}
			}
			w.enqueued.Add(3)
			var panicValue interface{}
			func() {
				defer func() { panicValue = recover() }()
				w.flush(context.Background(), batch)
			}()
			if (panicValue != nil) != tc.panic {
				t.Fatalf("panic = %v, want panic=%v", panicValue, tc.panic)
			}
			for i := range batch {
				if !reflect.DeepEqual(batch[i], findingWrite{}) || !reflect.DeepEqual(retainedWrites[i], FindingWrite{}) {
					t.Fatalf("completed backing slot %d still retains snapshot references", i)
				}
			}
			if reused := resetFindingBatch(batch); len(reused) != 0 || cap(reused) != 3 {
				t.Fatal("completed batch did not preserve cleared storage for reuse")
			}
			if m := w.Metrics(); m.PendingBytes != 0 || m.Written != tc.written || m.Errors != tc.failed || m.AdmissionFailed != 0 {
				t.Fatalf("lease or exact per-finding outcomes incorrect: %+v", m)
			}
		})
	}
}

func TestFindingWriterMemory_InlineReleasesOnFailureAndPanic(t *testing.T) {
	failure := errors.New("controlled inline failure")
	for _, tc := range []struct {
		name    string
		results []FindingSaveResult
		panic   bool
		failed  int64
	}{
		{name: "success", results: []FindingSaveResult{{}}},
		{name: "failure", results: []FindingSaveResult{{Err: failure}}, failed: 1},
		{name: "missing-outcome", failed: 1},
		{name: "panic", panic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var retainedWrites []FindingWrite
			w := NewFindingWriter(nil, FindingWriterConfig{
				saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
					retainedWrites = writes
					if tc.panic {
						panic("controlled inline panic")
					}
					return tc.results
				},
			})
			w.Close()
			var err error
			var panicValue interface{}
			func() {
				defer func() { panicValue = recover() }()
				err = w.Save(context.Background(), findingMemoryEvent(0, 64<<10), nil, "", "")
			}()
			if (panicValue != nil) != tc.panic || (err != nil) != (tc.failed != 0) {
				t.Fatalf("inline error/panic = %v/%v, want failed=%d panic=%v", err, panicValue, tc.failed, tc.panic)
			}
			if len(retainedWrites) != 1 || !reflect.DeepEqual(retainedWrites[0], FindingWrite{}) {
				t.Fatal("inline temporary backing slot retained a completed snapshot")
			}
			if m := w.Metrics(); m.PendingBytes != 0 || m.Inline != 1 || m.InlineFailed != tc.failed || m.Enqueued != 0 || m.Errors != 0 {
				t.Fatalf("inline byte lease or existing counters changed: %+v", m)
			}
		})
	}
}

func TestFindingWriterMemory_EstimatePayloadMetadataAndSaturation(t *testing.T) {
	base := estimateFindingBytes(&output.ResultEvent{}, nil, "", "")
	for _, tc := range []struct {
		name  string
		apply func(*output.ResultEvent)
	}{
		{"request", func(e *output.ResultEvent) { e.Request = strings.Repeat("r", 4096) }},
		{"response", func(e *output.ResultEvent) { e.Response = strings.Repeat("r", 4096) }},
		{"additional", func(e *output.ResultEvent) { e.AdditionalEvidence = []string{strings.Repeat("r", 4096)} }},
		{"extracted", func(e *output.ResultEvent) { e.ExtractedResults = []string{strings.Repeat("r", 4096)} }},
		{"payload", func(e *output.ResultEvent) { e.Payload = strings.Repeat("r", 4096) }},
		{"description", func(e *output.ResultEvent) { e.Info.Description = strings.Repeat("r", 4096) }},
		{"evidence-request", func(e *output.ResultEvent) {
			e.Evidence = []evidence.Entry{{Exchange: &evidence.Exchange{Request: make([]byte, 4096)}}}
		}},
		{"evidence-response", func(e *output.ResultEvent) {
			e.Evidence = []evidence.Entry{{Exchange: &evidence.Exchange{Response: make([]byte, 4096)}}}
		}},
		{"evidence-label", func(e *output.ResultEvent) { e.Evidence = []evidence.Entry{{Label: strings.Repeat("r", 4096)}} }},
		{"typed-metadata", func(e *output.ResultEvent) {
			e.Metadata = map[string]interface{}{"typed": findingMemoryTypedMetadata{Text: strings.Repeat("r", 4096)}}
		}},
		{"metadata-bytes", func(e *output.ResultEvent) { e.Metadata = map[string]interface{}{"bytes": make([]byte, 4096)} }},
		{"metadata-capacity", func(e *output.ResultEvent) { e.Metadata = map[string]interface{}{"bytes": make([]byte, 0, 4096)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := &output.ResultEvent{}
			tc.apply(event)
			if got := estimateFindingBytes(event, nil, "", ""); got < base+4096 {
				t.Fatalf("estimate %d did not charge %s payload (base %d)", got, tc.name, base)
			}
		})
	}
	metadata := make(map[string]interface{}, 512)
	for i := 0; i < 512; i++ {
		metadata[fmt.Sprint(i)] = false
	}
	if got := estimateFindingBytes(&output.ResultEvent{Metadata: metadata}, nil, "", ""); got < base+512*128 {
		t.Fatalf("tiny metadata map overhead not charged: %d", got)
	}
	if got := estimateFindingBytes(&output.ResultEvent{}, []string{strings.Repeat("r", 4096)}, strings.Repeat("s", 4096), strings.Repeat("p", 4096)); got < base+3*4096 {
		t.Fatalf("record/scan/project strings not charged: %d", got)
	}
	if addFindingBytes(maxFindingBytes-1, 2) != maxFindingBytes || multiplyFindingBytes(maxFindingBytes/2+1, 2) != maxFindingBytes ||
		addFindingBytes(2, 3) != 5 || multiplyFindingBytes(2, 3) != 6 || multiplyFindingBytes(maxFindingBytes, 0) != 0 {
		t.Fatal("byte arithmetic does not saturate correctly")
	}
	cycle := make(map[string]interface{})
	cycle["self"] = cycle
	event := &output.ResultEvent{Metadata: cycle}
	if got := estimateFindingBytes(event, nil, "", ""); got != maxFindingBytes {
		t.Fatalf("cyclic metadata estimate = %d, want saturation", got)
	}
	w := NewFindingWriter(nil, FindingWriterConfig{MaxPendingBytes: maxFindingBytes})
	w.Close()
	if err := w.Save(context.Background(), event, nil, "", ""); err == nil {
		t.Fatal("saturated estimate was admitted at the largest configured budget")
	}
	for _, configured := range []int64{0, -1} {
		cfg := FindingWriterConfig{MaxPendingBytes: configured}
		if got := cfg.withDefaults().MaxPendingBytes; got != 64<<20 {
			t.Fatalf("default byte budget = %d, want 64 MiB", got)
		}
	}
}
