package core

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func payloadBudgetTestAcquire(t *testing.T, budget *PayloadBudget, bytes int64) *PayloadLease {
	t.Helper()
	lease, changed, err := budget.TryAcquire(bytes)
	if lease == nil || changed != nil || err != nil {
		t.Fatalf("TryAcquire(%d): lease=%v changed=%v error=%v", bytes, lease, changed, err)
	}
	return lease
}

func payloadBudgetTestChannelOpen(t *testing.T, changed <-chan struct{}) {
	t.Helper()
	if changed == nil {
		t.Fatal("missing capacity-change channel")
	}
	select {
	case <-changed:
		t.Fatal("capacity-change channel is unexpectedly closed")
	default:
	}
}

func TestPayloadBudgetFiniteDefaultsAndProcessSharing(t *testing.T) {
	for _, limit := range []int64{0, -1, math.MinInt64} {
		stats := NewPayloadBudget(limit).Stats()
		if stats != (PayloadBudgetStats{LimitBytes: DefaultPayloadBudgetBytes}) {
			t.Fatalf("limit %d: unexpected default stats %+v", limit, stats)
		}
	}
	var zero PayloadBudget
	if zero.Stats().LimitBytes != DefaultPayloadBudgetBytes {
		t.Fatal("zero-value budget must not disable admission")
	}
	if ProcessPayloadBudget() != ProcessPayloadBudget() {
		t.Fatal("process default was recreated")
	}
	if ProcessPayloadBudget().Stats().LimitBytes != 1<<30 {
		t.Fatal("process default is not the finite 1 GiB budget")
	}
	if NewPayloadBudget(0) == ProcessPayloadBudget() {
		t.Fatal("explicit constructor unexpectedly reused the process default")
	}
}

func TestPayloadBudgetAccountingAndLifetimePeak(t *testing.T) {
	budget := NewPayloadBudget(10)
	first := payloadBudgetTestAcquire(t, budget, 6)
	defer first.Release()
	second := payloadBudgetTestAcquire(t, budget, 4)
	defer second.Release()
	if stats := budget.Stats(); stats != (PayloadBudgetStats{UsedBytes: 10, PeakBytes: 10, LimitBytes: 10}) {
		t.Fatalf("full budget: %+v", stats)
	}
	lease, changed, err := budget.TryAcquire(1)
	if lease != nil || changed == nil || err != nil {
		t.Fatalf("pressure must return only a channel: %v %v %v", lease, changed, err)
	}
	payloadBudgetTestChannelOpen(t, changed)
	first.Release()
	select {
	case <-changed:
	default:
		t.Fatal("release did not wake the subscriber")
	}
	if stats := budget.Stats(); stats.UsedBytes != 4 || stats.PeakBytes != 10 {
		t.Fatalf("after release: %+v", stats)
	}
	second.Release()
	if stats := budget.Stats(); stats.UsedBytes != 0 || stats.PeakBytes != 10 {
		t.Fatalf("peak must survive empty budget: %+v", stats)
	}
}

func TestPayloadBudgetImpossibleRequestsAreTypedAndPermanent(t *testing.T) {
	budget := NewPayloadBudget(8)
	for _, required := range []int64{-1, math.MinInt64, 9, math.MaxInt64} {
		lease, changed, err := budget.TryAcquire(required)
		var admission *MemoryAdmissionError
		if lease != nil || changed != nil || !errors.As(err, &admission) {
			t.Fatalf("%d: expected only MemoryAdmissionError, got %v %v %v", required, lease, changed, err)
		}
		if admission.RequiredBytes != required || admission.LimitBytes != 8 || admission.Stage != "payload" {
			t.Fatalf("wrong error context: %+v", admission)
		}
	}
	if stats := budget.Stats(); stats.UsedBytes != 0 || stats.PeakBytes != 0 {
		t.Fatalf("impossible request changed accounting: %+v", stats)
	}
}

func TestMemoryAdmissionErrorBoundsOwnedDiagnostics(t *testing.T) {
	stage := strings.Repeat("stage\n", 1<<16)
	record := strings.Repeat("record\n", 1<<16)
	err := NewMemoryAdmissionError(stage, 999, 888, record)
	if len(err.Stage) > memoryAdmissionStageBytes || len(err.RecordUUID) > memoryAdmissionRecordUUIDBytes {
		t.Fatal("error retained unbounded diagnostic strings")
	}
	if !strings.HasSuffix(err.Stage, "...") || !strings.HasSuffix(err.RecordUUID, "...") {
		t.Fatal("truncation is not visible")
	}
	message := err.Error()
	if strings.Contains(message, "\n") || !strings.Contains(message, "999") || !strings.Contains(message, "888") {
		t.Fatalf("unsafe or incomplete error text: %q", message)
	}
	// Error also bounds display if a caller bypasses the owning constructor.
	literal := &MemoryAdmissionError{Stage: stage, RecordUUID: record, RequiredBytes: 999, LimitBytes: 888}
	if len(literal.Error()) > 1024 {
		t.Fatal("literal error produced unbounded output")
	}
}

func TestPayloadBudgetReleaseIsConcurrentIdempotentAndDoesNotFreeAnotherLease(t *testing.T) {
	budget := NewPayloadBudget(10)
	first := payloadBudgetTestAcquire(t, budget, 6)
	second := payloadBudgetTestAcquire(t, budget, 4)
	defer second.Release()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			first.Release()
		}()
	}
	close(start)
	wg.Wait()
	if used := budget.Stats().UsedBytes; used != 4 {
		t.Fatalf("duplicate release freed another lease: used=%d", used)
	}
	third := payloadBudgetTestAcquire(t, budget, 6)
	defer third.Release()
	_, changed, err := budget.TryAcquire(1)
	if err != nil {
		t.Fatal(err)
	}
	first.Release() // Late release cannot free third's replacement reservation.
	payloadBudgetTestChannelOpen(t, changed)
	if used := budget.Stats().UsedBytes; used != 10 {
		t.Fatalf("late release corrupted accounting: used=%d", used)
	}
	var missing *PayloadLease
	missing.Release()
}

func TestPayloadBudgetBroadcastAndChannelEpochs(t *testing.T) {
	budget := NewPayloadBudget(1)
	owner := payloadBudgetTestAcquire(t, budget, 1)
	defer owner.Release()
	_, first, _ := budget.TryAcquire(1)
	_, second, _ := budget.TryAcquire(1)
	if first == nil || first != second {
		t.Fatal("waiters did not subscribe to the same capacity epoch")
	}
	owner.Release() // Deliberately release BEFORE selecting: no lost wake.
	for _, changed := range []<-chan struct{}{first, second} {
		select {
		case <-changed:
		default:
			t.Fatal("broadcast was lost before select")
		}
	}
	owner = payloadBudgetTestAcquire(t, budget, 1)
	defer owner.Release()
	_, next, _ := budget.TryAcquire(1)
	if next == first {
		t.Fatal("released epoch was reused")
	}
	payloadBudgetTestChannelOpen(t, next)
}

func TestPayloadBudgetAcquireRacingReleaseCannotLoseWake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 256 {
		budget := NewPayloadBudget(1)
		owner := payloadBudgetTestAcquire(t, budget, 1)
		start, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			<-start
			owner.Release()
		}()
		close(start)
		lease, changed, err := budget.TryAcquire(1)
		if err != nil {
			t.Fatal(err)
		}
		if lease == nil {
			if changed == nil {
				t.Fatal("temporary pressure had no subscription")
			}
			select {
			case <-changed:
			case <-ctx.Done():
				t.Fatal("release raced subscription and the wake was lost")
			}
			lease = payloadBudgetTestAcquire(t, budget, 1)
		}
		lease.Release()
		<-done
		if budget.Stats().UsedBytes != 0 {
			t.Fatal("racing admission leaked its lease")
		}
	}
}

func TestPayloadBudgetInt64BoundaryAndZeroReservation(t *testing.T) {
	budget := NewPayloadBudget(math.MaxInt64)
	owner := payloadBudgetTestAcquire(t, budget, math.MaxInt64)
	defer owner.Release()
	zero := payloadBudgetTestAcquire(t, budget, 0)
	zero.Release()
	lease, changed, err := budget.TryAcquire(1)
	if lease != nil || changed == nil || err != nil {
		t.Fatal("overflow bypassed a full MaxInt64 budget")
	}
	if stats := budget.Stats(); stats.UsedBytes != math.MaxInt64 || stats.PeakBytes != math.MaxInt64 {
		t.Fatalf("boundary accounting overflow: %+v", stats)
	}
	owner.Release()
	if budget.Stats().UsedBytes != 0 {
		t.Fatal("boundary release overflowed")
	}
}

func TestPayloadBudgetDefaultAdmits64MiBExchangeEstimate(t *testing.T) {
	request := []byte("GET /large HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := make([]byte, 64<<20)
	copy(response, "HTTP/1.1 200 OK\r\n\r\n")
	input := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequest(request), httpmsg.NewHttpResponse(response))
	budget := NewPayloadBudget(0)
	for _, receipt := range []bool{false, true} {
		if receipt {
			x := evidence.NewExchange("http://example.test:80", "http://example.test/large", request, response, evidence.ProvenanceSupplied)
			input = input.WithEvidence(x)
		}
		required := input.EstimatedScanPayloadBytes()
		if required < int64(cap(response)) || required > DefaultPayloadBudgetBytes {
			t.Fatalf("receipt=%v: 64 MiB input estimate %d does not fit finite default", receipt, required)
		}
		lease := payloadBudgetTestAcquire(t, budget, required)
		if budget.Stats().UsedBytes != required {
			t.Fatal("accepted estimate was not fully charged")
		}
		lease.Release()
	}
	if budget.Stats().UsedBytes != 0 {
		t.Fatal("64 MiB admission leaked")
	}
}
