package httpmsg

import "math"

const (
	// This is an admission quantum for tiny objects, not a measurement of Go
	// structs, parsed metadata, or allocator overhead.
	scanPayloadMinimumBytes int64 = 256
	// Conservative room for small clone/Builder capacity rounding. Large
	// backing-capacity growth is covered by the factors below, not this pad.
	scanPayloadCapacityPad int64 = 256
)

// EstimatedScanPayloadBytes estimates an exchange's retained HTTP payload and
// reserves future supplied-receipt and response body-string payload. It performs
// no parsing, cloning, Evidence selection, hashing, or cache mutation, and does
// not allocate. A nil exchange costs zero; a non-nil tiny exchange costs at least
// scanPayloadMinimumBytes. Arithmetic saturates at math.MaxInt64.
//
// Raw backing capacities are charged even after truncation. Private receipt
// capacities are charged independently, even if a Clone shares that receipt:
// conservative double accounting avoids unsafe pointer deduplication.
//
// This is NOT a heap/RSS bound. Opaque ratioSig state, parsed header/URL caches,
// module-created strings/clones, evidence selected by callers, pools, and writer
// copies need independent accounting. A baseline fetch needs an additional
// reservation in core; this method does not reserve future network responses.
//
// Message locks protect cache reads, so concurrent cache warming is supported.
// The exchange pointers and immutable private receipt must remain published and
// stable. Concurrent raw mutation/WithService replacement is not made safe here;
// in particular, HttpRequest.TruncateBody currently writes raw outside its lock.
func (h *HttpRequestResponse) EstimatedScanPayloadBytes() int64 {
	if h == nil {
		return 0
	}

	var requestCapacity, responseCapacity, bodyStringBytes, lowerStringBytes int64
	if h.request != nil {
		h.request.mu.RLock()
		requestCapacity = int64(cap(h.request.raw))
		h.request.mu.RUnlock()
	}
	if h.response != nil {
		h.response.mu.RLock()
		responseCapacity = int64(cap(h.response.raw))
		bodyStringBytes = int64(len(h.response.bodyString))
		lowerStringBytes = int64(len(h.response.bodyLowerString))
		h.response.mu.RUnlock()
	}

	rawBytes := scanPayloadAdd(requestCapacity, responseCapacity)
	total := rawBytes
	if h.snapshot != nil {
		// Inspect the immutable private receipt directly. Evidence() would
		// allocate and could hide receipt bytes exceeding the live projection.
		total = scanPayloadAdd(total, int64(cap(h.snapshot.Request)))
		total = scanPayloadAdd(total, int64(cap(h.snapshot.Response)))
	} else if h.request != nil {
		// The supplied-input path currently uses NewExchange followed by
		// WithEvidence: TWO owned pairs can overlap before the first dies.
		// Each clone is allowed 2*n + pad for byte-slice capacity rounding.
		// Use raw capacity, not parsed length; this remains conservative after
		// truncation and avoids reading/parsing the body or warming any cache.
		if rawBytes > 0 {
			oneCopy := scanPayloadAdd(scanPayloadMultiply(rawBytes, 2), scanPayloadCapacityPad)
			total = scanPayloadAdd(total, scanPayloadMultiply(oneCopy, 2))
		}
	}

	if h.response != nil {
		// With no parsing, the WHOLE raw capacity bounds the future body.
		// Keep the allowance after caches warm, and include existing strings
		// even if a cache-valid flag is false. Do not count a cache twice.
		bodyBytes := max(responseCapacity, bodyStringBytes)
		total = scanPayloadAdd(total, bodyBytes)

		// Unicode simple lowercasing emits one rune per decoded input rune;
		// even a one-byte invalid UTF-8 input consumes at most utf8.UTFMax
		// (4) output bytes. A 2x capacity allowance plus pad covers Builder
		// growth/rounding over that output bound, including an initial Grow
		// based on input length. Thus this is NOT a 1x lowercase allowance.
		// Also charge any already cached larger result, without inspecting it.
		lowerBytes := max(scanPayloadMultiply(bodyBytes, 4), lowerStringBytes)
		if lowerBytes > 0 {
			lowerBytes = scanPayloadAdd(scanPayloadMultiply(lowerBytes, 2), scanPayloadCapacityPad)
		}
		total = scanPayloadAdd(total, lowerBytes)
	}
	return max(scanPayloadMinimumBytes, total)
}

// scanPayloadAdd and scanPayloadMultiply accept non-negative byte counts only.
// Saturation is preferable to an overflow that would admit a huge payload cheaply.
func scanPayloadAdd(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

func scanPayloadMultiply(n, factor int64) int64 {
	if n != 0 && factor > math.MaxInt64/n {
		return math.MaxInt64
	}
	return n * factor
}
