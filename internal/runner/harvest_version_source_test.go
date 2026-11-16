package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
)

// These fixtures parse supplied captures and use an in-memory DB only. They do
// not initialize a requester, start a server, send traffic, or run an executor.
func harvestAdmissionRunner(t *testing.T, full bool, cursorYear int) (*Runner, *phaseInfra) {
	t.Helper()
	repo, _ := newHarvestTestRepo(t)
	opts := types.DefaultOptions()
	opts.ScanUUID, opts.ProjectUUID = "receive-admission", database.DefaultProjectUUID
	opts.ScanOnReceive, opts.FullNativeScanOnReceive, opts.Silent = true, full, true
	r := &Runner{options: opts, repository: repo, settings: config.DefaultSettings()}
	r.settings.DynamicAssessment.MaxParamShapeSamples = 1
	r.resetHarvestProbeState(opts.ScanUUID, opts.ProjectUUID)
	r.currentPhase.Store(newLedger(string(PhaseDynamicAssessment)))
	if err := repo.CreateScan(context.Background(), &database.Scan{
		UUID: opts.ScanUUID, ProjectUUID: opts.ProjectUUID, Status: "running", ProcessedCount: 7,
		CursorAt: time.Date(cursorYear, 1, 1, 0, 0, 0, 0, time.UTC), CursorUUID: "retained-cursor",
	}); err != nil {
		t.Fatal(err)
	}
	return r, &phaseInfra{scanUUID: opts.ScanUUID}
}

func harvestAdmissionExchange(t *testing.T, service, target, request string, response []byte) *httpmsg.HttpRequestResponse {
	t.Helper()
	x := evidence.NewExchange(service, target, []byte(request), response, evidence.ProvenanceCaptured)
	x.CapturedAt = time.Date(2020, 2, 3, 4, 5, 6, 0, time.UTC)
	rr, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func harvestAdmissionSave(t *testing.T, r *Runner, rr *httpmsg.HttpRequestResponse, origin, project string, year int) string {
	t.Helper()
	id, err := r.repository.SaveRecord(context.Background(), rr, origin, project)
	if err != nil {
		t.Fatal(err)
	}
	// Fixture chronology only: evidence bytes, destination and capture stay immutable.
	if _, err := r.repository.DB().NewUpdate().Model((*database.HTTPRecord)(nil)).
		Set("created_at = ?", time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)).Where("uuid = ?", id).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	return id
}

func harvestAdmissionFixture(t *testing.T, r *Runner) (seed, version, other string, observed *httpmsg.HttpRequestResponse) {
	t.Helper()
	ctx := context.Background()
	observed = harvestAdmissionExchange(t, "http://adoption.test:80", "http://adoption.test/item?q=1",
		"GET /item?q=1 HTTP/1.1\r\nHost: adoption.test\r\nAuthorization: Bearer actual\r\n\r\n",
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nactual\x00\xff"))
	version = harvestAdmissionSave(t, r, observed, database.RecordSourceIngestCLI, r.options.ProjectUUID, 2020)
	intended, err := httpmsg.GetRawRequestFromURL("http://adoption.test/item?q=1")
	if err != nil {
		t.Fatal(err)
	}
	intended = httpmsg.NewHttpRequestResponse(intended.Request().WithHeader("Authorization", "Bearer archive"), nil)
	seed = harvestAdmissionSave(t, r, intended, database.RecordSourceHarvest, r.options.ProjectUUID, 2022)
	insertions := 0
	r.repository.OnRecordSaved = func(*database.HTTPRecord) { insertions++ }
	returned, err := r.repository.SaveRecordVersion(ctx, seed, observed)
	r.repository.OnRecordSaved = nil
	if err != nil || returned != version || insertions != 0 {
		t.Fatalf("dedup result=%q insertions=%d err=%v, want existing %q without insertion callback", returned, insertions, err, version)
	}
	r.rememberHarvestVersion(r.options.ScanUUID, r.options.ProjectUUID, seed, returned)
	r.rememberHarvestVersion(r.options.ScanUUID, r.options.ProjectUUID, "another-explicit-seed", returned)
	otherRR := harvestAdmissionExchange(t, "http://adoption.test:80", "http://adoption.test/item?q=2",
		"GET /item?q=2 HTTP/1.1\r\nHost: adoption.test\r\n\r\n", []byte("HTTP/1.1 200 OK\r\n\r\nother"))
	other = harvestAdmissionSave(t, r, otherRR, database.RecordSourceIngestCLI, r.options.ProjectUUID, 2023)
	if err := r.repository.UpdateRiskScores(ctx, map[string]int{seed: 100, version: 90}); err != nil {
		t.Fatal(err)
	}
	return seed, version, other, observed
}

func harvestAdmissionScan(t *testing.T, r *Runner) *database.Scan {
	t.Helper()
	scan, err := r.repository.GetScanByUUID(context.Background(), r.options.ScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func assertHarvestCursor(t *testing.T, before, after *database.Scan) {
	t.Helper()
	if !after.CursorAt.Equal(before.CursorAt) || after.CursorUUID != before.CursorUUID {
		t.Fatalf("explicit admission moved cursor: %s/%s -> %s/%s", before.CursorAt, before.CursorUUID, after.CursorAt, after.CursorUUID)
	}
}

func TestHarvestVersionSource_ReceiveDedupAndOriginalCursor(t *testing.T) {
	for _, full := range []bool{false, true} {
		for _, older := range []bool{false, true} {
			t.Run(fmt.Sprintf("full=%v/older-than-cursor=%v", full, older), func(t *testing.T) {
				ctx := context.Background()
				year := 2019
				if older {
					year = 2021
				}
				r, infra := harvestAdmissionRunner(t, full, year)
				seed, version, other, observed := harvestAdmissionFixture(t, r)
				historical, err := r.repository.GetRecordByUUID(ctx, seed)
				if err != nil {
					t.Fatal(err)
				}
				before := harvestAdmissionScan(t, r)
				hosts := []database.HostTarget{{Scheme: "http", Hostname: "adoption.test", Port: 80}}
				var base source.InputSource
				var risk *database.RiskPrioritizedDBInputSource
				var continuous *database.DBInputSource
				var activities atomic.Int64
				if full {
					risk = r.newDynamicAssessmentSource(infra, hosts)
					base = risk
				} else {
					continuous = database.NewDBInputSource(r.repository.DB(), r.repository, infra.scanUUID, time.Millisecond).
						WithHostScopes(hosts).WithIncludeSources(database.IngestRecordSources).
						WithIdleTimeout(20 * time.Millisecond).
						WithOnActivity(func(n int, idle time.Duration, first bool) {
							activities.Add(1)
							if n < 1 || idle < 0 || !first {
								t.Errorf("original activity callback n=%d idle=%s first=%v", n, idle, first)
							}
						})
					base = continuous
				}
				execCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				src := r.newHarvestVersionSource(infra, hosts, base, cancel)
				if src == nil {
					t.Fatal("receive admission not constructed")
				}
				defer src.Close()
				item, err := src.Next(execCtx)
				if err != nil || item.RecordUUID != version || item.Request.Response() == nil {
					t.Fatalf("explicit item=%v err=%v, want saved %s with response", item, err, version)
				}
				if !bytes.Equal(item.Request.Request().Raw(), observed.Request().Raw()) ||
					!bytes.Equal(item.Request.Response().Raw(), observed.Response().Raw()) ||
					item.Request.Request().Header("Authorization") != "Bearer actual" ||
					item.Request.Evidence().RequestState != evidence.StateComplete ||
					item.Request.Evidence().ResponseState != evidence.StateComplete {
					t.Fatal("queued exchange substituted historical authentication, response or capture")
				}
				if risk != nil && (risk.Count() != 0 || risk.ExcludedRecords() != 0) || activities.Load() != 0 {
					t.Fatal("underlying cursor source read before explicit acknowledgement")
				}
				assertHarvestCursor(t, before, harvestAdmissionScan(t, r))
				item.Complete()
				item.Complete()
				afterAck := harvestAdmissionScan(t, r)
				assertHarvestCursor(t, before, afterAck)
				if afterAck.ProcessedCount != before.ProcessedCount+1 || src.Unresolved() != 0 || r.pendingHarvestVersionCount(infra.scanUUID) != 0 {
					t.Fatal("unique explicit ACK was not persisted exactly once")
				}
				ordinary, err := src.Next(execCtx)
				if err != nil || ordinary.RecordUUID != other {
					t.Fatalf("underlying item=%v err=%v, want unaffected %s", ordinary, err, other)
				}
				ordinary.Complete()
				if _, err := src.Next(execCtx); !errors.Is(err, io.EOF) {
					t.Fatalf("source repeated mapped seed/version: %v", err)
				}
				if risk != nil {
					if err := risk.FlushCursor(ctx); err != nil {
						t.Fatal(err)
					}
					wantExcluded := 2 // seed and version, before shape coalescing
					if older {
						wantExcluded = 1 // old version never enters the DB window
					}
					if risk.ExcludedRecords() != wantExcluded || risk.CoalescedDropped() != 0 || risk.Unresolved() != 0 {
						t.Fatalf("Risk excluded=%d coalesced=%d unresolved=%d", risk.ExcludedRecords(), risk.CoalescedDropped(), risk.Unresolved())
					}
				} else if activities.Load() != 1 || continuous.IdleFor() <= 0 {
					t.Fatal("wrapper lost original polling activity/idle state")
				}
				after := harvestAdmissionScan(t, r)
				wantProcessed := before.ProcessedCount + 2 // explicit plus ordinary work
				if !full && !older {
					wantProcessed++ // suppressed ingest version retains its native resolved-slot ACK
				}
				if after.CursorAt.Before(before.CursorAt) || after.CursorUUID != other || after.ProcessedCount != wantProcessed {
					t.Fatalf("original cursor/counters after receive: %+v, want UUID=%s processed=%d", after, other, wantProcessed)
				}
				if remaining, err := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, hosts); err != nil || remaining != 0 {
					t.Fatalf("remaining=%d err=%v", remaining, err)
				}
				if err := src.Close(); err != nil {
					t.Fatal(err)
				}
				feedbackBase := r.newDynamicAssessmentSource(infra, hosts)
				feedback := r.newHarvestVersionSource(infra, hosts, feedbackBase, nil)
				defer feedback.Close()
				if _, err := feedback.Next(ctx); !errors.Is(err, io.EOF) {
					t.Fatalf("completed explicit UUID repeated on later feedback: %v", err)
				}
				history, err := r.repository.GetRecordByUUID(ctx, seed)
				if err != nil || history.HasResponse || history.CaptureResponseState == evidence.StateComplete ||
					!bytes.Equal(history.RawRequest, historical.RawRequest) || !bytes.Equal(history.RawResponse, historical.RawResponse) ||
					history.CaptureRequestState != historical.CaptureRequestState || history.CaptureResponseState != historical.CaptureResponseState ||
					history.RequestHash != historical.RequestHash || history.ResponseHash != historical.ResponseHash ||
					history.ScanUUID != historical.ScanUUID || history.RootUUID != historical.RootUUID ||
					!history.SentAt.Equal(historical.SentAt) || !bytes.Contains(history.RawRequest, []byte("Bearer archive")) {
					t.Fatalf("historical seed changed: %v err=%v", history, err)
				}
			})
		}
	}
}

// A metadata-only fake proves that even a feed explicitly containing both UUID
// kinds is suppressed through its original callbacks, not by resetting it.
type harvestAdmissionBase struct {
	mu       sync.Mutex
	items    []*work.WorkItem
	nexts    int
	closes   int
	closeErr error
	block    bool
	entered  chan struct{}
}

func (s *harvestAdmissionBase) Next(ctx context.Context) (*work.WorkItem, error) {
	s.mu.Lock()
	s.nexts++
	if len(s.items) > 0 {
		item := s.items[0]
		s.items = s.items[1:]
		s.mu.Unlock()
		return item, nil
	}
	block := s.block
	entered := s.entered
	s.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, io.EOF
}

func (s *harvestAdmissionBase) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	return s.closeErr
}

func (s *harvestAdmissionBase) calls() (nexts, closes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nexts, s.closes
}

func TestHarvestVersionSource_ACKBarrierSuppressionAndRetry(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, false, 2025)
	seed, version, other, _ := harvestAdmissionFixture(t, r)
	var suppressed atomic.Int64
	var ordinary atomic.Int64
	makeBase := func() *harvestAdmissionBase {
		base := &harvestAdmissionBase{}
		for _, id := range []string{seed, version, other} {
			callback := func() { suppressed.Add(1) }
			if id == other {
				callback = func() { ordinary.Add(1) }
			}
			item := work.NewWithCallback(nil, nil, callback)
			item.RecordUUID = id
			base.items = append(base.items, item)
		}
		return base
	}
	base := makeBase()
	src := r.newHarvestVersionSource(infra, nil, base, nil)
	item, err := src.Next(context.Background())
	if err != nil || item.RecordUUID != version {
		t.Fatalf("queued version=%v err=%v", item, err)
	}
	blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := src.Next(blockedCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unacked explicit item did not hold ACK barrier: %v", err)
	}
	if n, _ := base.calls(); n != 0 {
		t.Fatal("base cursor read crossed explicit ACK barrier")
	}
	if err := r.reportHarvestAdmission(src); err == nil {
		t.Fatal("unacknowledged version was reported as complete")
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if _, n := base.calls(); n != 1 {
		t.Fatal("Close did not delegate exactly once")
	}
	before := harvestAdmissionScan(t, r)
	item.Complete() // old source's lease is fenced; cannot acknowledge retry work
	if harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount {
		t.Fatal("late callback after closure persisted an acknowledgement")
	}
	if n, err := r.countRemainingDynamicAssessmentRecords(context.Background(), infra.scanUUID, nil); err != nil || n != 1 {
		t.Fatalf("older unacked UUID invisible to receive remaining count: n=%d err=%v", n, err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	if err := r.waitForNewRecords(waitCtx, infra.scanUUID, time.Hour); err != nil {
		t.Fatalf("receive wait failed to see pending work before retained cursor: %v", err)
	}
	retryBase := makeBase()
	retry := r.newHarvestVersionSource(infra, nil, retryBase, nil)
	defer retry.Close()
	retried, err := retry.Next(context.Background())
	if err != nil || retried.RecordUUID != version {
		t.Fatalf("unacked lease did not retry after close: item=%v err=%v", retried, err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); retried.Complete() }()
	}
	wg.Wait()
	admitted, err := retry.Next(context.Background())
	if err != nil || admitted.RecordUUID != other || suppressed.Load() != 2 {
		t.Fatalf("suppression did not preserve both original callbacks: item=%v err=%v callbacks=%d", admitted, err, suppressed.Load())
	}
	admitted.Complete()
	if ordinary.Load() != 1 || r.reportHarvestAdmission(retry) != nil || retry.Unresolved() != 0 {
		t.Fatal("ordinary or explicit acknowledgement lost")
	}
	if _, err := retry.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("dedup UUID emitted twice: %v", err)
	}
	assertHarvestCursor(t, before, harvestAdmissionScan(t, r))
	if harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount+1 {
		t.Fatal("concurrent explicit callbacks persisted more than one acknowledged input")
	}
}

func TestHarvestVersionSource_LazyScopedProofFailureBlocksCursor(t *testing.T) {
	for _, failure := range []string{"missing", "foreign-project", "foreign-scan", "wrong-origin", "wrong-scheme", "wrong-port", "request-scope", "request-string", "unknown-capture", "unknown-request-capture", "truncated-capture", "missing-response", "read-error"} {
		t.Run(failure, func(t *testing.T) {
			r, infra := harvestAdmissionRunner(t, true, 2021)
			project := r.options.ProjectUUID
			if failure == "foreign-project" {
				project = "foreign-project"
			}
			observed := harvestAdmissionExchange(t, "http://actual.test:8080", "http://authority.test/keep",
				"GET http://authority.test/keep HTTP/1.1\r\nHost: authority.test\r\nAuthorization: Bearer actual\r\n\r\n", []byte("HTTP/1.1 200 OK\r\n\r\nprivate-proof"))
			if failure == "unknown-capture" || failure == "unknown-request-capture" || failure == "truncated-capture" {
				x := observed.Evidence().Clone()
				switch failure {
				case "unknown-capture":
					x.ResponseState = evidence.StateUnknown
				case "unknown-request-capture":
					x.RequestState = evidence.StateUnknown
				case "truncated-capture":
					x.ResponseState = evidence.StateTruncated
				}
				x.ContentHash = x.Hash()
				observed = observed.WithEvidence(x)
			}
			if failure == "missing-response" {
				observed = harvestAdmissionExchange(t, "http://actual.test:8080", "http://authority.test/keep",
					"GET /keep HTTP/1.1\r\nHost: authority.test\r\n\r\n", nil)
			}
			id := harvestAdmissionSave(t, r, observed, database.RecordSourceIngestCLI, project, 2020)
			hosts := []database.HostTarget{{Hostname: "actual.test"}} // scheme/port unconstrained
			switch failure {
			case "wrong-origin":
				hosts = []database.HostTarget{{Hostname: "authority.test"}}
			case "wrong-scheme":
				hosts[0].Scheme = "https"
			case "wrong-port":
				hosts[0].Port = 80
			case "request-scope":
				cfg := *config.DefaultScopeConfig()
				// Scope globs use filepath.Match: '*' cannot cross '/'. Path
				// retains an absolute-form request target, so exclude that exact
				// target without rewriting the capture or service destination.
				cfg.Path.Exclude = []string{observed.Request().Path()}
				infra.scopeMatcher = config.NewScopeMatcher(cfg)
				if infra.scopeMatcher.InScopeRequest(observed.Service().Host(), observed.Request().Path(), "", string(observed.Request().Raw())) {
					t.Fatal("request-scope fixture did not exclude the captured target")
				}
			case "request-string":
				cfg := *config.DefaultScopeConfig()
				cfg.RequestString.Exclude = []string{"Bearer actual"}
				infra.scopeMatcher = config.NewScopeMatcher(cfg)
			}
			r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, "explicit-seed", id)
			base := r.newDynamicAssessmentSource(infra, hosts)
			childCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			src := r.newHarvestVersionSource(infra, hosts, base, cancel)
			defer src.Close()
			before := harvestAdmissionScan(t, r)
			// Change availability AFTER construction: admission must be lazy and
			// must not silently fall back to the base on hydration failure.
			if failure == "missing" {
				if _, err := r.repository.DB().NewDelete().Model((*database.HTTPRecord)(nil)).Where("uuid = ?", id).Exec(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "foreign-scan" {
				if _, err := r.repository.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "foreign-project").
					Where("uuid = ?", infra.scanUUID).Exec(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "read-error" {
				if _, err := r.repository.DB().NewRaw("ALTER TABLE http_records RENAME TO unavailable_http_records").Exec(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			item, err := src.Next(childCtx)
			if err == nil || item != nil || src.Err() == nil || childCtx.Err() == nil {
				t.Fatalf("proof failure returned raw work or lacked latched cancellation: item=%v err=%v latched=%v", item, err, src.Err())
			}
			if base.Count() != 0 || base.ExcludedRecords() != 0 || src.Unresolved() != 1 {
				t.Fatal("failed queue advanced/pruned underlying cursor or lost explicit association")
			}
			if err := base.FlushCursor(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertHarvestCursor(t, before, harvestAdmissionScan(t, r))
			if err := r.reportHarvestAdmission(src); err == nil {
				t.Fatal("failed hydration reported clean phase")
			}
			out := r.currentPhase.Load().finish(context.Background(), nil)
			if out.State != database.PhasePartial || !slices.Contains(out.Reasons, database.ReasonPersistence) {
				t.Fatalf("failed admission not marked partial: %+v", out)
			}
		})
	}
}

func TestHarvestVersionSource_ActualOriginAndRequestScope(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, true, 2021)
	observed := harvestAdmissionExchange(t, "http://actual.test:8080", "http://authority.test/keep",
		"GET http://authority.test/keep HTTP/1.1\r\nHost: authority.test\r\nAuthorization: Bearer actual\r\n\r\n", []byte("HTTP/1.1 200 OK\r\n\r\nactual"))
	id := harvestAdmissionSave(t, r, observed, database.RecordSourceIngestCLI, r.options.ProjectUUID, 2020)
	r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, "explicit-seed", id)
	cfg := *config.DefaultScopeConfig()
	cfg.RequestString.Include = []string{"Bearer actual"}
	infra.scopeMatcher = config.NewScopeMatcher(cfg, "actual.test")
	src := r.newHarvestVersionSource(infra, []database.HostTarget{{Hostname: "actual.test"}}, &harvestAdmissionBase{}, nil)
	defer src.Close()
	item, err := src.Next(context.Background())
	if err != nil || item.Request.Service().Host() != "actual.test" || item.Request.Service().Port() != 8080 ||
		!bytes.Equal(item.Request.Request().Raw(), observed.Request().Raw()) {
		t.Fatalf("actual service was replaced with URL/Host authority: item=%v err=%v", item, err)
	}
	item.Complete()
}

func TestHarvestVersionSource_CallbackFailureIsPartialAndRetryable(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, true, 2025)
	_, version, _, _ := harvestAdmissionFixture(t, r)
	before := harvestAdmissionScan(t, r)
	if _, err := r.repository.DB().NewRaw("CREATE TRIGGER reject_explicit_ack BEFORE UPDATE OF processed_count ON scans BEGIN SELECT RAISE(ABORT, 'ack rejected'); END").Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	base := &harvestAdmissionBase{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := r.newHarvestVersionSource(infra, nil, base, cancel)
	item, err := src.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item.Complete()
	item.Complete()
	if src.Err() == nil || ctx.Err() == nil || src.Unresolved() != 1 || r.reportHarvestAdmission(src) == nil {
		t.Fatal("callback persistence failure was silently acknowledged")
	}
	if n, _ := base.calls(); n != 0 {
		t.Fatal("callback failure advanced underlying feed")
	}
	assertHarvestCursor(t, before, harvestAdmissionScan(t, r))
	if harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount {
		t.Fatal("failed callback invented processed inputs")
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.repository.DB().NewRaw("DROP TRIGGER reject_explicit_ack").Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	retry := r.newHarvestVersionSource(infra, nil, &harvestAdmissionBase{}, nil)
	defer retry.Close()
	item, err = retry.Next(context.Background())
	if err != nil || item.RecordUUID != version {
		t.Fatalf("failed ACK lost its retry association: item=%v err=%v", item, err)
	}
	item.Complete()
	if r.reportHarvestAdmission(retry) != nil || harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount+1 {
		t.Fatal("retry did not persist exactly one real acknowledgement")
	}
}

func TestHarvestVersionSource_ResetFencesCallbacksAndLeases(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, false, 2025)
	seed, version, _, _ := harvestAdmissionFixture(t, r)
	old := r.newHarvestVersionSource(infra, nil, &harvestAdmissionBase{}, nil)
	defer old.Close()
	item, err := old.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before := harvestAdmissionScan(t, r)
	generation, _, _ := r.harvestAdmissionSnapshot(infra.scanUUID)
	r.resetHarvestProbeState(infra.scanUUID, r.options.ProjectUUID) // same IDs, new run
	r.rememberHarvestVersionForRun(generation, infra.scanUUID, r.options.ProjectUUID, seed, version)
	if r.pendingHarvestVersionCount(infra.scanUUID) != 0 {
		t.Fatal("new invocation inherited pending work")
	}
	r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, seed, version)
	fresh := r.newHarvestVersionSource(infra, nil, &harvestAdmissionBase{}, nil)
	defer fresh.Close()
	newItem, err := fresh.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	item.Complete()
	_ = old.Close() // old lease owner must not release new generation's lease
	if fresh.Unresolved() != 1 || harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount {
		t.Fatal("old invocation callback/Close affected current generation")
	}
	newItem.Complete()
	if fresh.Unresolved() != 0 || harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount+1 {
		t.Fatal("fresh generation could not acknowledge saved version")
	}
	r.options.ProjectUUID = "new-project"
	r.resetHarvestProbeState(infra.scanUUID, r.options.ProjectUUID)
	if r.pendingHarvestVersionCount(infra.scanUUID) != 0 || len(r.harvestAssessmentExcludedUUIDs(infra.scanUUID)) != 0 {
		t.Fatal("new project inherited completed/queued associations")
	}
}

func TestHarvestVersionSource_EverySuccessfulReturnHasUniqueACK(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, true, 2025)
	seed, first, _, _ := harvestAdmissionFixture(t, r)
	different := harvestAdmissionExchange(t, "http://adoption.test:80", "http://adoption.test/item?q=1",
		"GET /item?q=1 HTTP/1.1\r\nHost: adoption.test\r\nAuthorization: Bearer actual\r\n\r\n", []byte("HTTP/1.1 200 OK\r\n\r\nlater-observation"))
	second, err := r.repository.SaveRecordVersion(context.Background(), seed, different)
	if err != nil || second == first {
		t.Fatalf("different successful return=%q err=%v", second, err)
	}
	r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, seed, second)
	r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, second, second) // even a successful unchanged return is inventoried
	before := harvestAdmissionScan(t, r)
	src := r.newHarvestVersionSource(infra, nil, &harvestAdmissionBase{}, nil)
	defer src.Close()
	seen := make(map[string]bool)
	for range 2 {
		item, err := src.Next(context.Background())
		if err != nil || item == nil || seen[item.RecordUUID] {
			t.Fatalf("overwritten mapping lost or repeated successful return: item=%v err=%v", item, err)
		}
		seen[item.RecordUUID] = true
		item.Complete()
	}
	if !seen[first] || !seen[second] || src.Count() != 2 || r.reportHarvestAdmission(src) != nil {
		t.Fatalf("successful UUID inventory/ACKs=%v count=%d", seen, src.Count())
	}
	if _, err := src.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("shared dedup/unchanged result repeated: %v", err)
	}
	if harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount+2 {
		t.Fatal("shared results invented processed inputs or lost an earlier observation")
	}
	r.rememberHarvestVersion(infra.scanUUID, r.options.ProjectUUID, seed, first) // later feedback returns an already ACKed dedup UUID
	feedback := r.newHarvestVersionSource(infra, nil, &harvestAdmissionBase{}, nil)
	defer feedback.Close()
	if feedback.Count() != 0 {
		t.Fatal("completed UUIDs counted as newly admitted feedback work")
	}
	if _, err := feedback.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("completed UUID repeated after another successful save return: %v", err)
	}
}

func TestHarvestVersionSource_ScanProjectMismatchCannotACK(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, true, 2025)
	_, _, _, _ = harvestAdmissionFixture(t, r)
	base := &harvestAdmissionBase{}
	src := r.newHarvestVersionSource(infra, nil, base, nil)
	defer src.Close()
	item, err := src.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before := harvestAdmissionScan(t, r)
	if _, err := r.repository.DB().NewUpdate().Model((*database.Scan)(nil)).Set("project_uuid = ?", "foreign-scan-project").
		Where("uuid = ?", infra.scanUUID).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	item.Complete()
	if !errors.Is(src.Err(), database.ErrScanProjectMismatch) || src.Unresolved() != 1 || r.reportHarvestAdmission(src) == nil {
		t.Fatalf("wrong-project scan accepted explicit ACK: %v", src.Err())
	}
	if n, _ := base.calls(); n != 0 || harvestAdmissionScan(t, r).ProcessedCount != before.ProcessedCount {
		t.Fatal("wrong-project ACK advanced cursor/counters")
	}
}

func TestHarvestVersionSource_CloseUnblocksBaseAndDelegatesError(t *testing.T) {
	r, infra := harvestAdmissionRunner(t, false, 2025)
	_, _, _, _ = harvestAdmissionFixture(t, r)
	wantErr := errors.New("base close failed")
	base := &harvestAdmissionBase{block: true, closeErr: wantErr, entered: make(chan struct{}, 1)}
	src := r.newHarvestVersionSource(infra, nil, base, nil)
	item, err := src.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	item.Complete()
	done := make(chan error, 1)
	go func() { _, err := src.Next(context.Background()); done <- err }()
	select {
	case <-base.entered:
	case <-time.After(time.Second):
		t.Fatal("Next never reached blocking underlying source")
	}
	if err := src.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close swallowed delegate error: %v", err)
	}
	if err := src.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("repeated Close lost delegate error: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Next after Close = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close failed to unblock Next")
	}
	if _, n := base.calls(); n != 1 {
		t.Fatal("Close delegated more than once")
	}
}
