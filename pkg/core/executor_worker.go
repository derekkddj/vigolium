package core

import (
	"context"
	"errors"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/storagesig"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// fatalSourceError lets a source declare that retrying cannot make progress.
// The structural contract avoids coupling input adapters to the executor or DB.
// errors.As also recognizes this declaration through wrapped errors.
type fatalSourceError interface {
	FatalSourceError() bool
}

// feedItems returns exhausted only on EOF. A declared terminal source failure
// stops further pulls and is returned unchanged after Execute drains accepted
// work. It is never acknowledged, silently skipped, or retried indefinitely.
func (e *Executor) feedItems(ctx context.Context, itemCh chan<- *work.WorkItem) (exhausted bool, feedErr error) {
	// Ordinary per-item errors retain their historical retry/skip behavior:
	// TargetSource, for example, advances past an invalid URL before returning
	// its error. Only an explicitly fatal error forbids reading another item.
	// Backoff prevents a non-fatal, non-progressing source from spinning a CPU.
	const spinGuardThreshold = 4
	consecutiveErrors := 0
	next := e.source.Next
	if !e.cfg.DisableFeedback {
		pull, stop := e.sourceReader(ctx, itemCh)
		defer stop()
		next = func(context.Context) (*work.WorkItem, error) { return pull() }
	}
	for {
		select {
		case <-ctx.Done():
			return false, nil
		default:
		}

		// Drain pending feedback before pulling from source.
		e.drainFeedback(ctx, itemCh)
		if !e.requeueDeferred(ctx, itemCh, false) {
			return false, nil
		}

		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return false, nil
			}
		}

		item, err := next(ctx)
		if err != nil {
			var fatal fatalSourceError
			if errors.As(err, &fatal) && fatal.FatalSourceError() {
				return false, err
			}
			if source.IsEOF(err) {
				return true, nil
			}
			if ctx.Err() != nil {
				return false, nil
			}
			consecutiveErrors++
			zap.L().Warn("Error reading from source",
				zap.Error(err),
				zap.Int("consecutive_errors", consecutiveErrors))
			if consecutiveErrors >= spinGuardThreshold {
				select {
				case <-ctx.Done():
					return false, nil
				case <-time.After(50 * time.Millisecond):
				}
			}
			continue
		}
		consecutiveErrors = 0

		if !e.sendItem(ctx, item, itemCh) {
			return false, nil
		}
	}
}

// drainFeedback non-blocking drains all pending feedback items into itemCh,
// then a batch of the feeder's overflow list.
func (e *Executor) drainFeedback(ctx context.Context, itemCh chan<- *work.WorkItem) {
	for {
		select {
		case fb := <-e.pool.feedbackCh:
			if !e.sendItem(ctx, fb, itemCh) {
				return
			}
		default:
			e.drainFeedbackOverflow(ctx, itemCh)
			return
		}
	}
}

// feedbackOverflowBatch is how many overflow items one drain pass moves, so
// the source pump keeps interleaving its own items with discovered ones.
const feedbackOverflowBatch = 256

// drainFeedbackOverflow sends one batch of overflow items to itemCh. Items a
// cancelled send leaves behind are counted unacked.
func (e *Executor) drainFeedbackOverflow(ctx context.Context, itemCh chan<- *work.WorkItem) bool {
	batch := e.pool.feeder.takeOverflow(feedbackOverflowBatch)
	for i, it := range batch {
		if !e.sendItem(ctx, it, itemCh) {
			e.unacked.Add(int64(len(batch) - i - 1))
			return false
		}
	}
	return true
}

// sendItem applies scope/static filters and sends the item to itemCh.
// Returns false if context is cancelled.
func (e *Executor) sendItem(ctx context.Context, item *work.WorkItem, itemCh chan<- *work.WorkItem) bool {
	// A stored request-only stub with a state-changing method is a template:
	// fetching its baseline would perform the write it only describes. Refused
	// before the send unless the run allows writes.
	if e.refusesWriteTemplate(item) {
		e.writeTemplatesSkipped.Add(1)
		e.noteUnanswered(item, SkipWriteTemplate, nil)
		item.Complete()
		return true
	}
	if !e.admitRequest(item, item.Request) {
		item.Complete()
		return true
	}

	// Admission precedes enqueue so EOF cannot look idle while a worker is
	// unscheduled or between dequeue and tracker creation. Filtered items above
	// are already complete and never enter this run's pending count.
	pending := runPendingFromContext(ctx)
	if pending != nil {
		pending.Add(1)
	}
	select {
	case <-ctx.Done():
		if pending != nil {
			pending.Add(-1)
		}
		return false
	case itemCh <- item:
		return true
	}
}

// admitRequest is shared by initial admission and transformed pre-hook requests.
// It must run before fetch; a post-response scope check cannot undo an egress.
func (e *Executor) admitRequest(item *work.WorkItem, req *httpmsg.HttpRequestResponse) bool {
	if req == nil || req.Request() == nil || req.Service() == nil {
		return false
	}
	item.StaticMeta = false
	// Always filter static files before HTTP fetch — EXCEPT object-storage
	// assets, which are kept and recorded metadata-only (HEAD, body stripped)
	// so the CDN traversal modules can probe storage-fronted static URLs.
	if e.cfg.StaticFileMatcher != nil &&
		e.cfg.StaticFileMatcher.IsStaticFile(req.Request().Path()) {
		if e.staticStorageCandidate(req) {
			item.StaticMeta = true
		} else {
			e.noteUnanswered(item, SkipStaticFile, nil)
			return false
		}
	}

	// Pre-request scope check (host/path only — avoids HTTP call)
	if e.cfg.ScopeMatcher != nil {
		host, path := req.Service().Host(), req.Request().Path()
		if class := e.cfg.ScopeMatcher.RequestRejectClass(host, path, e.cfg.FetchStaticFiles); class != "" {
			e.noteScopeRejected(class)
			e.noteUnanswered(item, DropOutOfScope, nil)
			return false
		}
	}

	// Dead-host breaker: drop items for a quarantined host:port, with a count
	// (skipped_quarantined). Read-only — see skipQuarantined.
	if e.skipQuarantined(req) {
		e.noteUnanswered(item, DropQuarantined, hosterrors.ErrUnresponsiveHost)
		return false
	}
	return true
}

// worker pulls items and runs each one up to the end of its dispatch phase:
// baseline fetch, passive stage, persist/scope, then dispatching the active
// tasks. It does NOT wait for those tasks. The item's itemTracker finishes it
// (ack, Processed(), buffer return) when its last task returns, so a slow
// module task no longer pins the worker that dispatched it — the worker is
// already fetching the next baseline.
//
// Before every dequeue the worker takes an outstanding-item slot
// (MaxOutstandingItems, released by the tracker). That keeps the number of
// open items, and with them live response buffers, bounded, and it is what
// turns slow tasks into backpressure on itemCh and the feeder instead of an
// unbounded pile of half-finished items.
//
// stop is closed by Execute right after itemCh, so a worker blocked waiting
// for a slot (every slot held by a stuck task) still exits at shutdown.
func (e *Executor) worker(ctx context.Context, _ int, itemCh <-chan *work.WorkItem, stop <-chan struct{}) {
	for {
		// Block if paused, abort if context cancelled
		if e.cfg.PauseCtrl != nil {
			if !e.cfg.PauseCtrl.WaitIfPaused(ctx) {
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case e.pool.itemSlots <- struct{}{}:
		}

		select {
		case <-ctx.Done():
			<-e.pool.itemSlots
			return
		case item, ok := <-itemCh:
			if !ok {
				<-e.pool.itemSlots
				return
			}
			// Item fairness: an item for a host whose task backlog is already
			// far over its cap would only queue more tasks behind it; park it
			// and let this worker dispatch another host's item instead. The
			// feeder re-sends it once the host drains (requeueDeferred).
			if e.parkIfOverloaded(item) {
				<-e.pool.itemSlots
				continue
			}
			t := e.newItemTracker(ctx, item, true)
			t.runPending = runPendingFromContext(ctx)
			// PauseCtrl covers the worker's own part only. Tasks already
			// dispatched keep running after Pause returns; see PauseController.
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.AcquireWorker()
			}
			e.dispatchItem(t)
			if e.cfg.PauseCtrl != nil {
				e.cfg.PauseCtrl.ReleaseWorker()
			}
			t.done() // drop the dispatcher's reference
		}
	}
}

// dispatchItem runs processItemDetached under panic recovery. A recovered
// panic marks the tracker so the item is acknowledged anyway when it
// completes; the caller still owns the dispatcher reference and must call
// t.done().
func (e *Executor) dispatchItem(t *itemTracker) {
	var panicked bool
	func() {
		defer e.recoverFromPanicInto("processItem", &panicked)
		e.processItemDetached(t)
	}()
	if panicked {
		t.panicked.Store(true)
	}
}

// finishItem acknowledges an item only if it was actually processed.
//
// The worker's select can win a dequeue in the same instant the context is
// cancelled, and processItemDetached's first act is to bail out on a cancelled context —
// so the item came off the queue, did no work, and was then acknowledged anyway.
// For a DB-backed source an ack is a durable cursor advance: the scan's cursor
// moved past records nothing ever looked at, and because a curtailed scan still
// recorded "completed", the next scan-on-receive run inherited that cursor and
// skipped them permanently. Withholding the ack is what makes those records get
// re-served.
//
// force is for a recovered panic: a poison item that keeps failing must still be
// acknowledged, or it comes back every run and the cursor never moves past it.
func (e *Executor) finishItem(ctx context.Context, item *work.WorkItem, force bool) {
	if !force && ctx.Err() != nil {
		e.unacked.Add(1)
		return
	}
	item.Complete()
}

// processItem runs one work item through the fetch, passive and active stages
// and waits until its last active task has finished and the item has been
// completed (acknowledged unless the context was cancelled). It returns whether
// a panic was recovered. The worker loop does not use it — it dispatches and
// moves on (see worker) — but it gives tests and one-shot callers a synchronous
// view of the same code path.
func (e *Executor) processItem(ctx context.Context, item *work.WorkItem) (panicked bool) {
	t := e.newItemTracker(ctx, item, false)
	e.dispatchItem(t)
	t.done()
	<-t.finished
	return t.panicked.Load()
}

// processItemDetached runs t's item through the fetch, passive and active
// stages, returning as soon as every active task has been dispatched. The
// tasks hold references on t; the item completes when the last one returns.
// It records the pooled baseline buffer on t, which returns it to the pool in
// complete() unless an abandoned module call flagged it as escaped.
func (e *Executor) processItemDetached(t *itemTracker) {
	// t.ctx carries t's response-buffer guard (see withResponseBufferGuard).
	ctx := t.ctx
	item := t.item

	// Bail out early if context is cancelled (graceful shutdown)
	select {
	case <-ctx.Done():
		return
	default:
	}

	req := item.Request
	enableModules := item.EnableModules

	zap.L().Debug("Processing item",
		zap.String("url", req.Target()),
		zap.Strings("enable_modules", enableModules))

	// Check context before expensive HTTP fetch
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Pre-hooks transform what will be sent, not an already answered exchange.
	// Retaining the previous response for a changed request would fabricate a
	// pair before even reaching evidence selection.
	if e.hooks != nil {
		// Only the mutable request and destination are needed to detect a hook
		// transformation. Copying the response/receipt here doubled large inputs,
		// including on the overwhelmingly common path with no hooks at all.
		before := httpmsg.NewHttpRequestResponse(req.Request().Clone(), nil)
		var ok bool
		req, ok = e.applyPreHooks(req)
		if !ok {
			return
		}
		if !sameInputRequest(before, req) {
			req = req.WithResponse(nil)
			if !e.admitRequest(item, req) {
				return
			}
		}
	}

	var fetched baselineFetch
	var ok bool
	if item.StaticMeta {
		// Object-storage metadata items record the URL + headers (status,
		// content-type, content-length), never the (large/binary) object body:
		// a HEAD, falling back to a ranged GET for origins that reject HEAD.
		fetched, ok = e.fetchStaticMetaResponse(ctx, req)
	} else {
		fetched, ok = e.fetchBaseline(ctx, req)
	}
	if !ok {
		if fetched.drop != "" {
			e.noteDrop(req.Target(), fetched.drop, fetched.dropErr)
			e.noteUnanswered(item, fetched.drop, fetched.dropErr)
		}
		return
	}
	// Counted here rather than when the item completes: this is the exact point
	// where a server answered, and every later return in this function is a
	// policy decision about an answer we already have.
	e.responded.Add(1)
	// From here the tracker owns the pooled buffer: complete() returns it once
	// the last active task is done with the item.
	httpResp := fetched.resp
	req, t.pooledBuf = fetched.req, fetched.pooledBuf
	req = suppliedInputSnapshot(req)
	redirectHops := fetched.hops
	if fetched.blockedRemark != "" {
		item.Remarks = append(item.Remarks, fetched.blockedRemark)
	}

	// Learn object-storage-backed hosts from any storage-signalled response so
	// the static-file carve-out keeps sibling assets on the same host.
	if req.Service() != nil && storagesig.ResponseHasStorageSignal(httpResp) {
		e.markStorageHost(req.Service().Host())
	}

	// Static metadata items: keep only genuine storage assets, body stripped.
	if item.StaticMeta {
		if !storagesig.ResponseHasStorageSignal(httpResp) &&
			!storagesig.LooksLikeStorageObjectPath(req.Request().Path()) {
			return // storage hint did not pan out; drop without recording
		}
		httpResp.TruncateBody(0)
	}

	if e.cfg.OnResponse != nil {
		e.cfg.OnResponse(item, req)
	}

	// Notify traffic callback
	if e.cfg.OnTraffic != nil {
		ct := getHeaderValue(httpResp.Headers(), "Content-Type")
		e.cfg.OnTraffic(req.Request().Method(), req.Target(), httpResp.StatusCode(), ct)
	}

	// Report a chain the transport stopped at an authentication wall. Read off
	// the stored 3xx rather than signalled out of CheckRedirect: the policy can
	// only answer with ErrUseLastResponse, and — decisively — the request
	// clusterer replays cached responses WITHOUT running CheckRedirect at all,
	// so anything recorded inside the policy would be missing on every cache
	// hit. Re-deriving is uniform across live and replayed responses.
	//
	// Status first: everything after it allocates (a header scan and a URL
	// rebuild), and the overwhelming majority of items are not redirects.
	if e.cfg.OnAuthWall != nil && httpmsg.IsRedirectStatus(httpResp.StatusCode()) {
		if wall, ok := http.StoppedAtAuthWall(req.Target(), httpResp.StatusCode(),
			getHeaderValue(httpResp.Headers(), "Location")); ok {
			e.cfg.OnAuthWall(req.Target(), wall)
		}
	}

	// Body size enforcement — truncate oversized bodies but defer drop/skip
	// decisions until after passive modules run (they are read-only).
	var bodySizeAction config.BodySizeAction
	if e.cfg.ScopeMatcher != nil {
		reqBodyLen := len(req.Request().Body())
		respBodyLen := len(httpResp.Body())
		var maxReq, maxResp int
		bodySizeAction, maxReq, maxResp = e.cfg.ScopeMatcher.CheckBodySize(reqBodyLen, respBodyLen)

		if bodySizeAction != config.BodySizeOK {
			if reqBodyLen > maxReq {
				req.Request().TruncateBody(maxReq)
				zap.L().Debug("Request body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", reqBodyLen),
					zap.Int("truncated_to", maxReq))
			}
			if respBodyLen > maxResp {
				httpResp.TruncateBody(maxResp)
				zap.L().Debug("Response body truncated",
					zap.String("url", req.Target()),
					zap.Int("original", respBodyLen),
					zap.Int("truncated_to", maxResp))
			}
		}
	}

	// Module filter setup (needed by passive modules below)
	var filter moduleFilter
	if len(enableModules) == 0 {
		filter = allModulesFilter
	} else {
		filter = newModuleFilter(enableModules)
	}

	// Pre-register requestUUIDs for DB-sourced items so passive module
	// findings can link to the existing http_record instead of creating
	// duplicate "finding" records.
	if item.RecordUUID != "" && e.repo != nil {
		record, err := e.repo.GetRecordByUUID(ctx, item.RecordUUID)
		if err == nil && e.recordMatchesInput(record, req) {
			e.caches.requestUUIDs.Store(req.Request().ID(), item.RecordUUID)
		}
	}

	// Pre-compute scope status before passive modules so scope-aware
	// passive modules can be skipped for out-of-scope items.
	scopeClass := ""
	if e.cfg.ScopeMatcher != nil && req.Service() != nil {
		scopeClass = e.cfg.ScopeMatcher.RejectClassBytes(
			req.Service().Host(),
			req.Request().Path(),
			httpResp.StatusCode(),
			getHeaderValue(req.Request().Headers(), "Content-Type"),
			getHeaderValue(httpResp.Headers(), "Content-Type"),
			req.Request().Raw(),
			httpResp.Body(),
		)
	}
	inScope := scopeClass == ""

	// The passive stage already ran on this record in an earlier pass or run
	// (coverage ledger): skip it.
	if item.Coverage == nil || !item.Coverage.PassiveDone {
		e.runPassiveStage(ctx, req, &filter, inScope)
		if t.prog != nil {
			t.prog.mu.Lock()
			t.prog.passiveRan = true
			t.prog.mu.Unlock()
		}
	}

	// Body size gate — drop/skip only affects active modules
	if bodySizeAction == config.BodySizeDrop {
		zap.L().Debug("Body size exceeded, dropping item (active scan skipped)",
			zap.String("url", req.Target()))
		return
	}
	if bodySizeAction == config.BodySizeSkipScan {
		e.saveToDatabase(ctx, item, req, redirectHops)
		return
	}
	skipActive := bodySizeAction == config.BodySizePassiveOnly

	if !e.persistAndCheckScope(ctx, item, req, scopeClass, redirectHops) {
		return
	}

	elig := computeEligibility(req)

	if !skipActive && !e.methodPolicyAllows(req) {
		skipActive = true
	}
	if !skipActive {
		e.runActiveStage(ctx, t, req, &filter, &elig)
	}
}

// refusesWriteTemplate reports whether item is a store stub (it came from a
// stored record and carries no response) whose method is not
// GET/HEAD/OPTIONS, on an executor that does not allow writes.
func (e *Executor) refusesWriteTemplate(item *work.WorkItem) bool {
	if e.cfg.AllowWrites || item == nil || item.RecordUUID == "" || item.Request == nil ||
		item.Request.Response() != nil || item.Request.Request() == nil {
		return false
	}
	return !httpmsg.IsSafeMethod(item.Request.Request().Method())
}
