package httpmsg

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestHasEvidenceDoesNotCopyBytes(t *testing.T) {
	var missing *HttpRequestResponse
	if missing.HasEvidence() || NewHttpRequestResponse(nil, nil).HasEvidence() {
		t.Fatal("absence was reported as a receipt")
	}
	x := evidence.NewExchange("http://example.test:80", "http://example.test/", []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), bytes.Repeat([]byte{'x'}, 1<<20), evidence.ProvenanceSupplied)
	rr := NewHttpRequestResponse(nil, nil).WithEvidence(x)
	if allocations := testing.AllocsPerRun(100, func() {
		if !rr.HasEvidence() {
			t.Fatal("existing receipt was lost")
		}
	}); allocations != 0 {
		t.Fatalf("presence check allocated %g times", allocations)
	}
	selected := rr.Evidence()
	selected.Response[0] = 'Y'
	if rr.Evidence().Response[0] != 'x' {
		t.Fatal("presence optimization exposed mutable receipt bytes")
	}
}

func TestCloneEvidenceRetainedBytes(t *testing.T) {
	request := []byte("GET /bundle HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := append([]byte("HTTP/1.1 200 OK\r\n\r\n"), bytes.Repeat([]byte{'x'}, 1<<20)...)
	x := evidence.NewExchange("http://example.test:80", "http://example.test/bundle", request, response, evidence.ProvenanceSupplied)
	rr, err := FromEvidenceExchange(x)
	if err != nil {
		t.Fatal(err)
	}
	// Each clone must own its mutable analysis pair, but must not allocate a
	// second full pair for a private receipt that is immutable after publication.
	const count = 8
	clones := make([]*HttpRequestResponse, count)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range clones {
		clones[i] = rr.Clone()
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	limit := uint64(count * (len(request) + len(response)) * 3 / 2)
	t.Logf("clone allocations: %d bytes, maximum %d (live messages plus 50%% overhead)", allocated, limit)
	if allocated > limit {
		t.Errorf("cloning duplicated full immutable receipts: allocated %d bytes > %d", allocated, limit)
	}
	for _, clone := range clones {
		clone.Request().Raw()[0] = 'X'
		clone.Response().Raw()[len(response)-1] = 'Y'
		selected := clone.Evidence()
		if !reflect.DeepEqual(selected, x) || selected.Validate() != nil {
			t.Fatal("mutable analysis changed the canonical receipt")
		}
		selected.Request[0], selected.Response[len(response)-1] = 'A', 'B'
		if !reflect.DeepEqual(clone.Evidence(), x) || !reflect.DeepEqual(rr.Evidence(), x) {
			t.Fatal("public selection exposed the shared private receipt")
		}
	}
	runtime.KeepAlive(clones)
}
