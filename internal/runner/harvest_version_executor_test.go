package runner

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/work"
)

// These integration fixtures run a real executor, but never initialize a
// requester: both adopted input and module feedback have captured responses.
// Source callbacks own durable ACK/cursor persistence. The executor is stateless
// so feedback cannot create a second, timing-dependent database input snapshot.
type harvestExecutorInput struct {
	*harvestVersionSource
	nexts       atomic.Int64
	barrierNext chan struct{}
	issued      atomic.Pointer[work.WorkItem]
}

func (s *harvestExecutorInput) Next(ctx context.Context) (*work.WorkItem, error) {
	n := s.nexts.Add(1)
	if n == 2 {
		close(s.barrierNext)
	}
	item, err := s.harvestVersionSource.Next(ctx)
	if n == 1 && err == nil {
		s.issued.Store(item)
	}
	return item, err
}

type harvestExecutorBaseSnapshot struct {
	scan    *database.Scan
	pending int64
	err     error
}

type harvestExecutorBase struct {
	*database.RiskPrioritizedDBInputSource
	once   sync.Once
	before func(context.Context)
}

func (s *harvestExecutorBase) Next(ctx context.Context) (*work.WorkItem, error) {
	s.once.Do(func() { s.before(ctx) })
	return s.RiskPrioritizedDBInputSource.Next(ctx)
}

// A scope-aware passive discovery stand-in feeds ready endpoints from the exact
// adopted capture. Waiting for the next source read makes the old ACK-barrier /
// feedback deadlock reproducible without sleeps or a simulated manual ACK.
type harvestExecutorPassive struct {
	adoptedPath string
	barrierNext <-chan struct{}
	feedback    []*httpmsg.HttpRequestResponse
	hold        bool
	started     chan struct{}
	startOnce   sync.Once
	mu          sync.Mutex
	seen        map[string][]*httpmsg.HttpRequestResponse
	accepted    int
}

func (m *harvestExecutorPassive) ID() string                                   { return "harvest-executor-feedback" }
func (m *harvestExecutorPassive) Name() string                                 { return m.ID() }
func (m *harvestExecutorPassive) Description() string                          { return "" }
func (m *harvestExecutorPassive) ShortDescription() string                     { return "" }
func (m *harvestExecutorPassive) ConfirmationCriteria() string                 { return "" }
func (m *harvestExecutorPassive) Severity() severity.Severity                  { return 0 }
func (m *harvestExecutorPassive) Confidence() severity.Confidence              { return 0 }
func (m *harvestExecutorPassive) ScanScopes() modules.ScanScope                { return modkit.ScanScopeRequest }
func (m *harvestExecutorPassive) Tags() []string                               { return nil }
func (m *harvestExecutorPassive) ScopeAware() bool                             { return true }
func (m *harvestExecutorPassive) CanProcess(*httpmsg.HttpRequestResponse) bool { return true }
func (m *harvestExecutorPassive) Scope() modules.PassiveScanScope {
	return modkit.PassiveScanScopeBoth
}
func (m *harvestExecutorPassive) ScanPerHost(*httpmsg.HttpRequestResponse, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *harvestExecutorPassive) ScanPerHostContext(context.Context, *httpmsg.HttpRequestResponse, *modules.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}
func (m *harvestExecutorPassive) ScanPerRequest(rr *httpmsg.HttpRequestResponse, sc *modules.ScanContext) ([]*output.ResultEvent, error) {
	return m.ScanPerRequestContext(context.Background(), rr, sc)
}
func (m *harvestExecutorPassive) ScanPerRequestContext(ctx context.Context, rr *httpmsg.HttpRequestResponse, sc *modules.ScanContext) ([]*output.ResultEvent, error) {
	path := rr.Request().Path()
	m.mu.Lock()
	if m.seen == nil {
		m.seen = make(map[string][]*httpmsg.HttpRequestResponse)
	}
	m.seen[path] = append(m.seen[path], rr.Clone())
	m.mu.Unlock()
	if path != m.adoptedPath {
		return nil, nil
	}
	select {
	case <-m.barrierNext:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if m.started != nil {
		m.startOnce.Do(func() { close(m.started) })
	}
	if m.hold {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	for _, endpoint := range m.feedback {
		if sc.Feeder().Feed(endpoint) {
			m.mu.Lock()
			m.accepted++
			m.mu.Unlock()
		}
	}
	return nil, nil
}

func harvestExecutorFixture(t *testing.T, r *Runner, infra *phaseInfra) (version, ordinary string, observed *httpmsg.HttpRequestResponse, hosts []database.HostTarget) {
	t.Helper()
	observed = harvestAdmissionExchange(t, "http://adoption.test:80", "http://authority.test/spec",
		"GET http://authority.test/spec HTTP/1.1\r\nHost: authority.test\r\nAuthorization: Bearer actual\r\n\r\n",
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nspec\x00\xff"))
	version = harvestAdmissionSave(t, r, observed, database.RecordSourceIngestCLI, r.options.ProjectUUID, 2020)
	intended, err := httpmsg.GetRawRequestFromURL("http://adoption.test/spec")
	if err != nil {
		t.Fatal(err)
	}
	seed := harvestAdmissionSave(t, r, httpmsg.NewHttpRequestResponse(intended.Request().WithHeader("Authorization", "Bearer archive"), nil), database.RecordSourceHarvest, r.options.ProjectUUID, 2022)
	returned, err := r.repository.SaveRecordVersion(context.Background(), seed, observed)
	if err != nil || returned != version {
		t.Fatalf("fixture did not dedup to the version before the retained cursor: got=%q want=%q err=%v", returned, version, err)
	}
	r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, seed, returned)
	ordinaryRR := harvestAdmissionExchange(t, "http://adoption.test:80", "http://adoption.test/ordinary",
		"GET /ordinary HTTP/1.1\r\nHost: adoption.test\r\nAuthorization: Bearer actual\r\n\r\n", []byte("HTTP/1.1 200 OK\r\n\r\nordinary"))
	ordinary = harvestAdmissionSave(t, r, ordinaryRR, database.RecordSourceIngestCLI, r.options.ProjectUUID, 2023)
	cfg := *config.DefaultScopeConfig()
	cfg.CLIOriginMode = "strict"
	cfg.Host.Include = []string{"adoption.test"}
	cfg.Path.Include = []string{observed.Request().Path(), "/ordinary", "/feedback-*"}
	cfg.RequestString.Include = []string{"Bearer actual"}
	infra.scopeMatcher = config.NewScopeMatcher(cfg, "adoption.test")
	hosts = []database.HostTarget{{Scheme: "http", Hostname: "adoption.test", Port: 80}}
	return version, ordinary, observed, hosts
}

func harvestExecutorConfig(r *Runner, infra *phaseInfra, shallow bool) core.ExecutorConfig {
	return core.ExecutorConfig{
		Workers: 1, SkipBaseline: true, DisableFeedback: shallow,
		ScopeMatcher: infra.scopeMatcher, ScanUUID: infra.scanUUID, ProjectUUID: r.options.ProjectUUID,
		PassiveModuleTimeout: 3 * time.Second, FeedbackDrainMaxStall: 3 * time.Second, WorkerExitGrace: time.Second,
	}
}

func assertHarvestExecutorCapture(t *testing.T, got, want *httpmsg.HttpRequestResponse) {
	t.Helper()
	if got == nil || got.Service() == nil || got.Request() == nil || got.Response() == nil ||
		got.Service().Host() != want.Service().Host() || got.Service().Port() != want.Service().Port() || got.Service().Protocol() != want.Service().Protocol() ||
		!bytes.Equal(got.Request().Raw(), want.Request().Raw()) || !bytes.Equal(got.Response().Raw(), want.Response().Raw()) ||
		got.Evidence() == nil || got.Evidence().RequestState != evidence.StateComplete || got.Evidence().ResponseState != evidence.StateComplete {
		t.Fatal("executor substituted the captured request, response, destination or completeness")
	}
}

func TestHarvestVersionSource_ExecutorFeedbackCrossesACKBarrier(t *testing.T) {
	for _, shallow := range []bool{false, true} {
		t.Run(fmt.Sprintf("shallow=%v", shallow), func(t *testing.T) {
			r, infra := harvestAdmissionRunner(t, !shallow, 2021)
			_, ordinary, observed, hosts := harvestExecutorFixture(t, r, infra)
			before := harvestAdmissionScan(t, r)
			dbSource := r.newDynamicAssessmentSource(infra, hosts)
			baseRead := make(chan harvestExecutorBaseSnapshot, 1)
			base := &harvestExecutorBase{RiskPrioritizedDBInputSource: dbSource, before: func(ctx context.Context) {
				scan, err := r.repository.GetScanByUUID(ctx, infra.scanUUID)
				baseRead <- harvestExecutorBaseSnapshot{scan: scan, pending: r.pendingHarvestVersionCount(infra.scanUUID), err: err}
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			admission := r.newHarvestVersionSource(infra, hosts, base, cancel)
			defer admission.Close()
			input := &harvestExecutorInput{harvestVersionSource: admission, barrierNext: make(chan struct{})}
			mod := &harvestExecutorPassive{adoptedPath: observed.Request().Path(), barrierNext: input.barrierNext}
			// One worker's feedback channel has 16 slots. The 17th endpoint must
			// be drained while Next is waiting for the adopted item's real ACK.
			for i := range 17 {
				path := fmt.Sprintf("/feedback-%02d", i)
				mod.feedback = append(mod.feedback, harvestAdmissionExchange(t, "http://adoption.test:80", "http://adoption.test"+path,
					"GET "+path+" HTTP/1.1\r\nHost: adoption.test\r\nAuthorization: Bearer actual\r\n\r\n", []byte("HTTP/1.1 200 OK\r\n\r\nready")))
			}
			executor := core.NewExecutor(harvestExecutorConfig(r, infra, shallow), input, nil, []modules.PassiveModule{mod})
			if _, err := executor.Execute(ctx); err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil || !executor.Report().Clean() || executor.FeedbackDropped() != 0 {
				t.Fatalf("executor did not drain barrier feedback cleanly: ctx=%v report=%+v dropped=%d", ctx.Err(), executor.Report(), executor.FeedbackDropped())
			}
			if err := admission.Close(); err != nil {
				t.Fatal(err)
			}
			if err := r.reportHarvestAdmission(admission); err != nil {
				t.Fatal(err)
			}
			select {
			case first := <-baseRead:
				if first.err != nil || first.scan == nil || first.pending != 0 || first.scan.ProcessedCount != before.ProcessedCount+1 {
					t.Fatalf("original source crossed an unacknowledged explicit item: %+v", first)
				}
				assertHarvestCursor(t, before, first.scan)
			default:
				t.Fatal("executor never resumed the original database source")
			}
			mod.mu.Lock()
			defer mod.mu.Unlock()
			wantFeedback := len(mod.feedback)
			if shallow {
				wantFeedback = 0
			}
			if mod.accepted != wantFeedback || len(mod.seen) != wantFeedback+2 || executor.Processed() != int64(wantFeedback+2) {
				t.Fatalf("accepted=%d paths=%d processed=%d, want feedback=%d plus adopted and ordinary input", mod.accepted, len(mod.seen), executor.Processed(), wantFeedback)
			}
			for path, captures := range mod.seen {
				if len(captures) != 1 {
					t.Fatalf("endpoint %q processed %d times", path, len(captures))
				}
			}
			adopted := mod.seen[observed.Request().Path()]
			if len(adopted) != 1 || len(mod.seen["/ordinary"]) != 1 {
				t.Fatal("adopted or original database endpoint was not processed exactly once")
			}
			assertHarvestExecutorCapture(t, adopted[0], observed)
			if !shallow {
				for _, endpoint := range mod.feedback {
					seen := mod.seen[endpoint.Request().Path()]
					if len(seen) != 1 {
						t.Fatalf("feedback endpoint %q not processed", endpoint.Request().Path())
					}
					assertHarvestExecutorCapture(t, seen[0], endpoint)
				}
			}
			if err := dbSource.FlushCursor(context.Background()); err != nil {
				t.Fatal(err)
			}
			after := harvestAdmissionScan(t, r)
			if after.CursorAt.Before(before.CursorAt) || after.CursorUUID != ordinary || after.ProcessedCount != before.ProcessedCount+2 || dbSource.Unresolved() != 0 {
				t.Fatalf("original cursor/ACK flow lost: before=%+v after=%+v unresolved=%d", before, after, dbSource.Unresolved())
			}
		})
	}
}

func TestHarvestVersionSource_ExecutorCancelledUnackedVersionRetries(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, true, 2021)
	version, ordinary, observed, hosts := harvestExecutorFixture(t, r, infra)
	before := harvestAdmissionScan(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base := r.newDynamicAssessmentSource(infra, hosts)
	admission := r.newHarvestVersionSource(infra, hosts, base, cancel)
	defer admission.Close()
	input := &harvestExecutorInput{harvestVersionSource: admission, barrierNext: make(chan struct{})}
	mod := &harvestExecutorPassive{adoptedPath: observed.Request().Path(), barrierNext: input.barrierNext, hold: true, started: make(chan struct{})}
	executor := core.NewExecutor(harvestExecutorConfig(r, infra, false), input, nil, []modules.PassiveModule{mod})
	done := make(chan error, 1)
	go func() { _, err := executor.Execute(ctx); done <- err }()
	select {
	case <-mod.started:
		cancel()
	case <-ctx.Done():
		t.Fatal("executor never held the adopted item at the real ACK barrier")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled executor did not release the source reader and worker")
	}
	if err := admission.Close(); err != nil {
		t.Fatal(err)
	}
	if executor.Report().Clean() || executor.Report().Unacked != 1 || admission.Unresolved() != 1 || r.reportHarvestAdmission(admission) == nil || base.Count() != 0 {
		t.Fatalf("cancellation acknowledged or advanced unprocessed work: report=%+v unresolved=%d base=%d", executor.Report(), admission.Unresolved(), base.Count())
	}
	issued := input.issued.Load()
	if issued == nil || issued.RecordUUID != version {
		t.Fatal("real executor did not receive the deduplicated saved UUID")
	}
	issued.Complete() // closed lease must fence a late completion from the old run
	afterCancel := harvestAdmissionScan(t, r)
	assertHarvestCursor(t, before, afterCancel)
	if afterCancel.ProcessedCount != before.ProcessedCount || r.pendingHarvestVersionCount(infra.scanUUID) != 1 {
		t.Fatal("cancelled or late callback consumed the retry association")
	}
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer retryCancel()
	retryBase := r.newDynamicAssessmentSource(infra, hosts)
	retry := r.newHarvestVersionSource(infra, hosts, retryBase, retryCancel)
	defer retry.Close()
	retryInput := &harvestExecutorInput{harvestVersionSource: retry, barrierNext: make(chan struct{})}
	retryMod := &harvestExecutorPassive{adoptedPath: observed.Request().Path(), barrierNext: retryInput.barrierNext}
	retryExecutor := core.NewExecutor(harvestExecutorConfig(r, infra, false), retryInput, nil, []modules.PassiveModule{retryMod})
	if _, err := retryExecutor.Execute(retryCtx); err != nil {
		t.Fatal(err)
	}
	if err := retry.Close(); err != nil {
		t.Fatal(err)
	}
	if retryCtx.Err() != nil || !retryExecutor.Report().Clean() || r.reportHarvestAdmission(retry) != nil || retryExecutor.Processed() != 2 {
		t.Fatalf("retry did not complete both real input ACKs: report=%+v processed=%d admission=%v", retryExecutor.Report(), retryExecutor.Processed(), r.reportHarvestAdmission(retry))
	}
	retryMod.mu.Lock()
	adopted := retryMod.seen[observed.Request().Path()]
	ordinarySeen := len(retryMod.seen["/ordinary"])
	retryMod.mu.Unlock()
	if len(adopted) != 1 || ordinarySeen != 1 {
		t.Fatal("retry lost or repeated the adopted/original endpoint")
	}
	assertHarvestExecutorCapture(t, adopted[0], observed)
	if err := retryBase.FlushCursor(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := harvestAdmissionScan(t, r)
	if after.CursorAt.Before(before.CursorAt) || after.CursorUUID != ordinary || after.ProcessedCount != before.ProcessedCount+2 || r.pendingHarvestVersionCount(infra.scanUUID) != 0 {
		t.Fatalf("retry did not preserve original cursor monotonicity: before=%+v after=%+v", before, after)
	}
}
