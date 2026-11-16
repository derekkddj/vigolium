package http

import (
	"errors"
	"sync/atomic"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// PlantingReceiptObserver selectively observes actual sends, including probes
// that return no finding. The predicate sees planting intent only; the sink
// must correlate again against the receipt's CURRENT emitted request bytes.
// Neither a cache hit nor an earlier redirect request establishes a new send.
// Implementations must be concurrency-safe, cheap, and non-blocking.
type PlantingReceiptObserver interface {
	WantsPlantingReceipt(input, raw []byte, requestTarget string) bool
	ObservePlantingReceipt(*evidence.Exchange) error
}

type plantingObserver struct {
	sink atomic.Pointer[PlantingReceiptObserver]
}

// WithPlantingReceiptObserver returns a scan-scoped view. Existing views are not
// retargeted when another executor is created on the shared requester. Subsequent
// context, lane, and credential clones share this view's observer, not a global
// last response or a process-wide observer.
func (r *Requester) WithPlantingReceiptObserver(sink PlantingReceiptObserver) *Requester {
	if r == nil {
		return nil
	}
	clone := *r
	clone.plantingObserver = &plantingObserver{}
	if sink != nil {
		clone.plantingObserver.sink.Store(&sink)
	}
	return &clone
}

func (r *Requester) wantsPlantingReceipt(input *httpmsg.HttpRequestResponse, opts Options) (sink PlantingReceiptObserver) {
	if r.plantingObserver == nil {
		return nil
	}
	p := r.plantingObserver.sink.Load()
	if p == nil {
		return nil
	}
	defer func() {
		if v := recover(); v != nil {
			zap.L().Warn("HTTP: planting receipt selector panicked", zap.Any("panic", v))
			sink = nil
		}
	}()
	var raw []byte
	if input != nil && input.Request() != nil {
		raw = input.Request().Raw()
	}
	if (*p).WantsPlantingReceipt(raw, opts.RawBytes, opts.RawRequestTarget) {
		return *p
	}
	return nil
}

func observePlantingReceipt(sink PlantingReceiptObserver, chain *httpUtils.ResponseChain) {
	if sink == nil || chain == nil {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			zap.L().Warn("HTTP: planting receipt observer panicked", zap.Any("panic", v))
		}
	}()
	// A followed redirect may carry the original nonce incidentally in Referer
	// while dropping the actual query/body planting slot. The final response
	// cannot identify which earlier execution triggered the callback. Preserve
	// all real forwarded headers, but fail closed instead of splicing exchanges.
	if req := chain.Request(); req != nil && req.Response != nil {
		return
	}
	observePlantingExchange(sink, CaptureEvidence(chain))
}

func observePlantingFailure(sink PlantingReceiptObserver, err error) {
	if sink == nil {
		return
	}
	var failure *RequestCaptureError
	if !errors.As(err, &failure) || failure.followedRedirect {
		return // incidental Referer tokens cannot prove an earlier planting slot
	}
	observePlantingExchange(sink, CaptureFailureEvidence(err))
}

func observePlantingExchange(sink PlantingReceiptObserver, x *evidence.Exchange) {
	if sink == nil || x == nil || x.Provenance == evidence.ProvenanceCached || x.Provenance == evidence.ProvenanceLegacy || x.RequestState == evidence.StateMissing || len(x.Request) == 0 {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			zap.L().Warn("HTTP: planting receipt observer panicked", zap.Any("panic", v))
		}
	}()
	// Both helpers provide an independent snapshot. The sink cannot mutate a
	// live chain, or the immutable receipt shared by singleflight error callers.
	if err := sink.ObservePlantingReceipt(x); err != nil {
		zap.L().Warn("HTTP: planting receipt observer failed", zap.Error(err))
	}
}
