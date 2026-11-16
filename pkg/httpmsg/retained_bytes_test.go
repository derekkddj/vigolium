package httpmsg

import (
	"bytes"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestEstimatedScanPayloadBytesNilAndTinyObjects(t *testing.T) {
	var missing *HttpRequestResponse
	if missing.EstimatedScanPayloadBytes() != 0 {
		t.Fatal("nil exchange was charged")
	}
	for _, rr := range []*HttpRequestResponse{
		NewHttpRequestResponse(nil, nil),
		NewHttpRequestResponse(NewHttpRequest(nil), nil),
		NewHttpRequestResponse(nil, NewHttpResponse(nil)),
		NewHttpRequestResponse(NewHttpRequest(nil), NewHttpResponse(nil)),
	} {
		if got := rr.EstimatedScanPayloadBytes(); got != scanPayloadMinimumBytes {
			t.Fatalf("empty object needs finite admission quantum: got %d", got)
		}
	}
}

func TestEstimatedScanPayloadBytesBackingCapacitySurvivesTruncation(t *testing.T) {
	requestHead := []byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 512\r\n\r\n")
	responseHead := []byte("HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n")
	requestRaw := make([]byte, len(requestHead)+512, 1<<20)
	responseRaw := make([]byte, len(responseHead)+512, 2<<20)
	copy(requestRaw, requestHead)
	copy(responseRaw, responseHead)
	request := NewHttpRequest(requestRaw)
	response := NewHttpResponse(responseRaw)
	rr := NewHttpRequestResponse(request, response)
	before := rr.EstimatedScanPayloadBytes()
	request.TruncateBody(8)
	response.TruncateBody(8)
	if len(request.Raw()) != len(requestHead)+8 || len(response.Raw()) != len(responseHead)+8 {
		t.Fatal("fixture bodies were not truncated")
	}
	if cap(request.Raw()) != 1<<20 || cap(response.Raw()) != 2<<20 {
		t.Fatal("fixture lost its backing arrays")
	}
	after := rr.EstimatedScanPayloadBytes()
	if after != before || after < int64(cap(requestRaw)+cap(responseRaw)) {
		t.Fatalf("truncation discounted retained backing storage: before=%d after=%d", before, after)
	}
}

func TestEstimatedScanPayloadBytesPrivateReceiptCapacityWithoutSelection(t *testing.T) {
	// No live messages, so the estimate isolates receipt capacity. WithEvidence
	// owns copies; the accessor must not select another copy with Evidence().
	x := &evidence.Exchange{ID: "deliberately-unvalidated", Request: bytes.Repeat([]byte{'r'}, 257), Response: bytes.Repeat([]byte{'s'}, 1025)}
	rr := NewHttpRequestResponse(nil, nil).WithEvidence(x)
	if &rr.snapshot.Request[0] == &x.Request[0] || &rr.snapshot.Response[0] == &x.Response[0] {
		t.Fatal("WithEvidence did not own its private receipt")
	}
	x.Request[0], x.Response[0] = 'X', 'Y'
	if rr.snapshot.Request[0] != 'r' || rr.snapshot.Response[0] != 's' {
		t.Fatal("producer mutation changed the private receipt")
	}
	// Prepare shortened views before publication to the accessor. Their backing
	// capacities still own the full copied receipt, unlike their visible lengths.
	rr.snapshot.Request = rr.snapshot.Request[:1]
	rr.snapshot.Response = rr.snapshot.Response[:2]
	want := int64(cap(rr.snapshot.Request) + cap(rr.snapshot.Response))
	snapshot := rr.snapshot
	if got := rr.EstimatedScanPayloadBytes(); got != want {
		t.Fatalf("receipt capacity: got %d want %d", got, want)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if rr.EstimatedScanPayloadBytes() != want {
			t.Fatal("receipt charge changed")
		}
	}); allocations != 0 {
		t.Fatalf("private receipt measurement allocated %g times (Evidence must not be called)", allocations)
	}
	if rr.snapshot != snapshot || len(snapshot.Request) != 1 || len(snapshot.Response) != 2 {
		t.Fatal("measurement mutated the private receipt")
	}
}

func TestEstimatedScanPayloadBytesReservesMissingSuppliedReceipt(t *testing.T) {
	request := NewHttpRequest(make([]byte, 129))
	response := NewHttpResponse(make([]byte, 1025))
	rr := NewHttpRequestResponse(request, response)
	withoutReceipt := rr.EstimatedScanPayloadBytes()
	rawBytes := int64(cap(request.raw) + cap(response.raw))
	futureCopies := scanPayloadMultiply(scanPayloadAdd(scanPayloadMultiply(rawBytes, 2), scanPayloadCapacityPad), 2)
	// Empty but PRESENT receipt deliberately isolates presence semantics. Do not
	// parse, validate, or fabricate evidence during measurement.
	rr.snapshot = &evidence.Exchange{}
	withReceipt := rr.EstimatedScanPayloadBytes()
	if withoutReceipt-withReceipt != futureCopies {
		t.Fatalf("missing receipt allowance: got %d want %d", withoutReceipt-withReceipt, futureCopies)
	}
	if withoutReceipt < rawBytes+futureCopies {
		t.Fatal("supplied receipt copies were not reserved before creation")
	}
}

func TestEstimatedScanPayloadBytesDoesNotParseOrWarmCaches(t *testing.T) {
	request := NewHttpRequest([]byte("not a parsed request"))
	response := NewHttpResponse([]byte("not a parsed response"))
	rr := NewHttpRequestResponse(request, response)
	want := rr.EstimatedScanPayloadBytes()
	if allocations := testing.AllocsPerRun(1000, func() {
		if rr.EstimatedScanPayloadBytes() != want {
			t.Fatal("cold estimate changed")
		}
	}); allocations != 0 {
		t.Fatalf("cold measurement allocated %g times", allocations)
	}
	request.mu.RLock()
	requestUntouched := !request.parsed && request.cachedID == "" && request.cachedURL == nil && !request.urlComputed && request.headers == nil
	request.mu.RUnlock()
	response.mu.RLock()
	responseUntouched := !response.parsed && !response.bodyStringOK && !response.bodyLowerStrOK && !response.ratioSigOK && response.headers == nil
	response.mu.RUnlock()
	if !requestUntouched || !responseUntouched || rr.HasEvidence() {
		t.Fatal("estimator parsed, warmed caches, or fabricated a receipt")
	}
}

func TestEstimatedScanPayloadBytesUnicodeCachesAndZeroAllocations(t *testing.T) {
	// U+023A lowercases from two UTF-8 bytes to three. Invalid UTF-8 is another
	// expansion case; an ASCII-only body would not exercise the required bound.
	body := strings.Repeat("\u023a\u0130\u00c4\u03a3\U0001f600\xff", 128)
	response := NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\n" + body))
	rr := NewHttpRequestResponse(NewHttpRequest([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")), response)
	before := rr.EstimatedScanPayloadBytes()
	if response.BodyToString() != body || response.BodyLowerString() != strings.ToLower(body) {
		t.Fatal("unexpected body derivations")
	}
	after := rr.EstimatedScanPayloadBytes()
	if after != before {
		t.Fatalf("warming caches needed an unreserved upgrade: before=%d after=%d", before, after)
	}
	response.mu.RLock()
	cachedBytes := int64(len(response.bodyString) + len(response.bodyLowerString))
	response.mu.RUnlock()
	if after < int64(cap(response.raw))+cachedBytes {
		t.Fatal("cached forms were not included")
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if rr.EstimatedScanPayloadBytes() != before {
			t.Fatal("warm estimate changed")
		}
	}); allocations != 0 {
		t.Fatalf("warm measurement allocated %g times", allocations)
	}
}

func TestEstimatedScanPayloadBytesCountsExistingStringsButExcludesOpaqueSignature(t *testing.T) {
	response := NewHttpResponse([]byte{'x'})
	response.bodyString = strings.Repeat("b", 4096)
	response.bodyLowerString = strings.Repeat("l", 32768)
	// Count storage even if validity flags are false; do not traverse opaque any.
	response.ratioSig = make([]byte, 1<<20)
	rr := NewHttpRequestResponse(nil, response)
	withSignature := rr.EstimatedScanPayloadBytes()
	if withSignature < int64(cap(response.raw)+len(response.bodyString)+len(response.bodyLowerString)) {
		t.Fatal("existing cached strings were discounted")
	}
	response.mu.Lock()
	response.ratioSig = nil
	response.mu.Unlock()
	if rr.EstimatedScanPayloadBytes() != withSignature {
		t.Fatal("opaque ratioSig leaked into the HTTP payload contract")
	}
}

func TestEstimatedScanPayloadBytesConcurrentCacheWarming(t *testing.T) {
	response := NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("\u023a\xffXYZ", 1024)))
	rr := NewHttpRequestResponse(nil, response)
	want := rr.EstimatedScanPayloadBytes()
	const workers = 16
	errors := make(chan int64, workers)
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 256 {
				if worker%2 == 0 {
					response.BodyLowerString()
				} else {
					response.BodyToString()
				}
				if got := rr.EstimatedScanPayloadBytes(); got != want {
					errors <- got
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for got := range errors {
		t.Errorf("concurrent cache warming changed reservation: got %d want %d", got, want)
	}
}

func TestScanPayloadArithmeticSaturates(t *testing.T) {
	if scanPayloadAdd(math.MaxInt64, 1) != math.MaxInt64 || scanPayloadAdd(math.MaxInt64-1, 2) != math.MaxInt64 {
		t.Fatal("addition overflow did not saturate")
	}
	if scanPayloadMultiply(math.MaxInt64, 2) != math.MaxInt64 || scanPayloadMultiply(math.MaxInt64/2+1, 2) != math.MaxInt64 {
		t.Fatal("multiplication overflow did not saturate")
	}
	if scanPayloadAdd(10, 20) != 30 || scanPayloadMultiply(10, 2) != 20 || scanPayloadMultiply(0, math.MaxInt64) != 0 {
		t.Fatal("ordinary arithmetic changed")
	}
}
