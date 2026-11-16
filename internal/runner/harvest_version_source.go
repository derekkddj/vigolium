package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/work"
)

// harvestVersionSource admits receive-mode versions independently of the durable
// cursor. It holds UUID metadata only and hydrates one actual saved exchange per
// Next. Underlying input is untouched until all explicit work is acknowledged:
// a missing receipt or failed acknowledgement cannot checkpoint past its seed.
// Cursor and activity/status ownership remain with the original database source.
type harvestVersionSource struct {
	base                  source.InputSource
	repo                  *database.Repository
	adoptions             *harvestVersionAdoptions
	scanUUID, projectUUID string
	generation, owner     uint64
	ids                   []string
	explicitCount         int64 // pending UUID estimate at source creation, not a kept count
	excluded              map[string]struct{}
	matcher               *config.ScopeMatcher
	hosts                 []database.HostTarget
	nextMu                sync.Mutex // serializes Next; callbacks never take it
	index                 int
	barrierPassed         bool
	closed                atomic.Bool
	closeOnce             sync.Once
	closeErr              error
	closeCtx              context.Context
	stopNext              context.CancelFunc
	done                  chan struct{}
	errMu                 sync.Mutex
	err                   error
	stop                  context.CancelFunc // stops the child executor, not the receive cursor/run
}

func (r *Runner) newHarvestVersionSource(infra *phaseInfra, hosts []database.HostTarget, base source.InputSource, stop context.CancelFunc) *harvestVersionSource {
	if r.options == nil || (!r.options.ScanOnReceive && !r.options.FullNativeScanOnReceive) {
		return nil
	}
	generation, seeds, versions := r.harvestAdmissionSnapshot(infra.scanUUID)
	if len(versions) == 0 {
		return nil
	}
	a := &r.harvestVersions
	a.mu.Lock()
	a.nextOwner++
	owner := a.nextOwner
	var explicitCount int64
	if a.generation == generation {
		for _, id := range versions {
			if ack := a.explicit[id]; ack != nil && !ack.complete {
				explicitCount++
			}
		}
	}
	a.mu.Unlock()
	s := &harvestVersionSource{
		base: base, repo: r.repository, adoptions: a, scanUUID: infra.scanUUID, projectUUID: r.options.ProjectUUID,
		generation: generation, owner: owner, ids: versions, explicitCount: explicitCount, excluded: make(map[string]struct{}, len(seeds)+len(versions)),
		matcher: infra.scopeMatcher, hosts: append([]database.HostTarget(nil), hosts...), done: make(chan struct{}), stop: stop,
	}
	for _, id := range append(seeds, versions...) {
		s.excluded[id] = struct{}{}
	}
	s.closeCtx, s.stopNext = context.WithCancel(context.Background())
	return s
}

func (s *harvestVersionSource) fail(err error) error {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	err = s.err
	s.errMu.Unlock()
	// Wake an ACK-barrier waiter even when a test/embedding has no executor
	// cancel hook. A callback failure must not leave Next asleep indefinitely.
	s.adoptions.mu.Lock()
	s.adoptions.signalLocked()
	s.adoptions.mu.Unlock()
	if s.stop != nil {
		s.stop()
	}
	return err
}

func (s *harvestVersionSource) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *harvestVersionSource) wait(ctx context.Context, changed <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return io.EOF
	case <-changed:
		return nil
	}
}

func (s *harvestVersionSource) Next(ctx context.Context) (*work.WorkItem, error) {
	// Close must unblock a polling/blocked base.Next as well as the ACK barrier.
	ctx, cancel := context.WithCancel(ctx)
	unhook := context.AfterFunc(s.closeCtx, cancel)
	defer cancel()
	defer unhook()
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	for {
		if s.closed.Load() {
			return nil, io.EOF
		}
		if err := s.Err(); err != nil {
			return nil, err // latch failures: the executor otherwise skips Next errors
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a := s.adoptions
		a.mu.Lock()
		if a.generation != s.generation || a.scanUUID != s.scanUUID || a.projectUUID != s.projectUUID {
			a.mu.Unlock()
			return nil, s.fail(fmt.Errorf("harvest version admission: invocation identity changed"))
		}
		if s.index < len(s.ids) {
			id := s.ids[s.index]
			ack := a.explicit[id]
			if ack.complete {
				s.index++
				a.mu.Unlock()
				continue
			}
			if ack.owner != 0 {
				changed := a.changed
				a.mu.Unlock()
				if err := s.wait(ctx, changed); err != nil {
					return nil, err
				}
				continue
			}
			ack.owner = s.owner
			a.mu.Unlock()
			rr, err := s.load(ctx, id)
			if err != nil {
				return nil, s.fail(err) // no underlying read/ack; Close releases the lease
			}
			if s.closed.Load() {
				return nil, io.EOF
			}
			a.mu.Lock()
			valid := a.generation == s.generation && a.scanUUID == s.scanUUID && a.projectUUID == s.projectUUID
			a.mu.Unlock()
			if !valid {
				return nil, s.fail(fmt.Errorf("harvest version admission: invocation changed during hydration"))
			}
			s.index++
			var once sync.Once
			item := work.NewWithCallback(rr, nil, func() { once.Do(func() { s.acknowledge(ctx, id) }) })
			item.RecordUUID = id
			return item, nil
		}
		// Keep the underlying cursor behind pending explicit proof, including
		// work handed to workers but left unacked on cancellation. A new source
		// can lease it again after Close; completed versions never reappear.
		pending := false
		if !s.barrierPassed {
			for _, id := range s.ids {
				if !a.explicit[id].complete {
					pending = true
					break
				}
			}
			s.barrierPassed = !pending // don't rescan the UUID inventory for every base item
		}
		changed := a.changed
		a.mu.Unlock()
		if pending {
			if err := s.wait(ctx, changed); err != nil {
				return nil, err
			}
			continue
		}
		item, err := s.base.Next(ctx)
		if s.closed.Load() {
			return nil, io.EOF
		}
		if err != nil {
			return nil, err
		}
		if item != nil {
			if _, suppressed := s.excluded[item.RecordUUID]; suppressed {
				// Continuous DBInputSource cannot exclude before querying. Exact
				// dedup may retain an ingest source, so suppress by explicit UUID,
				// preserving its own once-only callback/cursor slot. Native cursor
				// counters include resolved slots, just as for scope-filtered items.
				item.Complete()
				continue
			}
		}
		return item, nil
	}
}

func (s *harvestVersionSource) load(ctx context.Context, id string) (*httpmsg.HttpRequestResponse, error) {
	// Revalidate the owning scan before hydration as well as at ACK. A managed
	// scan reassigned since startup is not permission to analyze either project.
	scan, err := s.repo.GetScanByUUID(ctx, s.scanUUID)
	if err != nil {
		return nil, fmt.Errorf("validate adopted harvest version %s scan: %w", id, err)
	}
	if scan.ProjectUUID != s.projectUUID {
		return nil, fmt.Errorf("adopted harvest version %s scan ownership: %w", id, database.ErrScanProjectMismatch)
	}
	// Exact scoped hydration applies the project predicate BEFORE raw bytes are
	// loaded. A foreign/missing UUID never reveals another project's exchange.
	rows, err := s.repo.GetFindingRecordsScoped(ctx, s.projectUUID, []string{id})
	if err != nil {
		return nil, fmt.Errorf("load adopted harvest version %s: %w", id, err)
	}
	if len(rows) != 1 || rows[0].UUID != id || rows[0].ProjectUUID != s.projectUUID {
		return nil, fmt.Errorf("adopted harvest version %s unavailable in invocation project", id)
	}
	record := rows[0]
	// Parent-owned API: reuse applyHostScopeFilter's exact-origin semantics,
	// including unconstrained scheme/port, rather than deriving origin from URL.
	if !database.RecordMatchesHostScopes(record, s.hosts) {
		return nil, fmt.Errorf("adopted harvest version %s outside assessment origins", id)
	}
	reqState, respState, err := record.EffectiveCaptureStates()
	if err != nil || !record.HasResponse || reqState != evidence.StateComplete || respState != evidence.StateComplete {
		return nil, fmt.Errorf("adopted harvest version %s lacks complete saved exchange", id)
	}
	rr, err := database.RecordToHttpRequestResponse(record)
	if err != nil {
		return nil, fmt.Errorf("restore adopted harvest version %s: %w", id, err)
	}
	if rr.Request() == nil || rr.Response() == nil || rr.Service() == nil || rr.Evidence() == nil {
		return nil, fmt.Errorf("adopted harvest version %s lacks response/capture", id)
	}
	if s.matcher != nil && !s.matcher.InScopeRequest(rr.Service().Host(), rr.Request().Path(), rr.Request().Header("Content-Type"), string(rr.Request().Raw())) {
		return nil, fmt.Errorf("adopted harvest version %s outside assessment request scope", id)
	}
	return rr, nil
}

func (s *harvestVersionSource) acknowledge(ctx context.Context, id string) {
	a := s.adoptions
	a.mu.Lock()
	ack := a.explicit[id]
	if s.closed.Load() || a.generation != s.generation || ack == nil || ack.owner != s.owner || ack.complete {
		a.mu.Unlock()
		return
	}
	// This work has no underlying cursor slot. Persist one acknowledged input,
	// without assigning a cursor or touching evidence. Project-scoped SQL avoids
	// the unscoped IncrementProcessedCount API; affected-row failures are errors.
	ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cursorFlushBudget)
	res, err := s.repo.DB().NewUpdate().Model((*database.Scan)(nil)).
		Set("processed_count = processed_count + 1").Set("updated_at = CURRENT_TIMESTAMP").
		Where("uuid = ?", s.scanUUID).Where("project_uuid = ?", s.projectUUID).Exec(ackCtx)
	cancel()
	if err == nil {
		var n int64
		n, err = res.RowsAffected()
		if err == nil && n != 1 {
			err = database.ErrScanProjectMismatch
		}
	}
	if err == nil {
		ack.complete = true
	} else {
		// Latch before releasing the lease mutex: Close/report cannot race a
		// completed failed callback and miss its actual persistence error.
		err = fmt.Errorf("acknowledge adopted harvest version %s: %w", id, err)
		s.errMu.Lock()
		if s.err == nil {
			s.err = err
		}
		s.errMu.Unlock()
	}
	a.signalLocked()
	a.mu.Unlock()
	if err != nil {
		s.fail(err)
	}
}

func (s *harvestVersionSource) Unresolved() int {
	a := s.adoptions
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.generation != s.generation {
		return len(s.ids)
	}
	var n int
	for _, id := range s.ids {
		if !a.explicit[id].complete {
			n++
		}
	}
	return n
}

// Count reports this source's initial pending UUID estimate plus the base's own
// candidate estimate, when available. Base counts may include suppressed UUID
// slots; this is not a kept/coalesced count and never requires hydration.
func (s *harvestVersionSource) Count() int64 {
	n := s.explicitCount
	if base, ok := s.base.(source.Countable); ok {
		n += base.Count()
	}
	return n
}

func (s *harvestVersionSource) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.stopNext()
		close(s.done)
		a := s.adoptions
		a.mu.Lock()
		if a.generation == s.generation {
			for _, id := range s.ids {
				if ack := a.explicit[id]; ack != nil && ack.owner == s.owner && !ack.complete {
					ack.owner = 0
				}
			}
			a.signalLocked()
		}
		a.mu.Unlock()
		s.closeErr = s.base.Close()
	})
	return s.closeErr
}

// reportHarvestAdmission is called only after executor workers/callbacks drain.
// Errors in callbacks cannot be returned through WorkItem.Complete; surface them
// here instead of allowing a failed explicit admission to look like a clean EOF.
func (r *Runner) reportHarvestAdmission(s *harvestVersionSource) error {
	if s == nil {
		return nil
	}
	tracker := r.currentPhase.Load()
	err := s.Err()
	if err != nil && tracker != nil {
		tracker.markPartial(database.ReasonPersistence)
	}
	if pending := s.Unresolved(); pending > 0 {
		if tracker != nil {
			tracker.markPartial(database.ReasonRoundError)
		}
		err = errors.Join(err, fmt.Errorf("harvest version admission: %d explicit inputs remain unacknowledged", pending))
	}
	return err
}
