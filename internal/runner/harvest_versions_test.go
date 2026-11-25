package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestHarvestVersions_ScopedMetadataAndReset(t *testing.T) {
	r := &Runner{options: &types.Options{ScanUUID: "scan-a", ProjectUUID: "project-a"}}
	r.resetHarvestProbeState("scan-a", "project-a")
	r.rememberHarvestVersion("scan-a", "project-a", "seed-b", "version")
	r.rememberHarvestVersion("scan-a", "project-a", "seed-a", "version") // exact dedup may share the result
	for _, invalid := range []struct{ scan, project, seed, version string }{
		{"scan-b", "project-a", "foreign-scan", "version"},
		{"scan-a", "project-b", "foreign-project", "version"},
		{"", "project-a", "unbound", "version"},
		{"scan-a", "project-a", "failed-save", ""},
		{"scan-a", "project-a", "", "version"},
	} {
		r.rememberHarvestVersion(invalid.scan, invalid.project, invalid.seed, invalid.version)
	}
	want := []string{"seed-a", "seed-b"}
	ids := r.supersededHarvestSeedUUIDs("scan-a")
	if !slices.Equal(ids, want) || len(r.harvestVersions.versions) != 2 {
		t.Fatalf("exclusions = %v, mappings = %v, want %v only", ids, r.harvestVersions.versions, want)
	}
	ids[0] = "version" // callers receive an owned metadata slice
	if got := r.supersededHarvestSeedUUIDs("scan-a"); !slices.Equal(got, want) {
		t.Fatalf("caller changed retained mapping: %v", got)
	}
	if got := r.supersededHarvestSeedUUIDs("scan-b"); len(got) != 0 {
		t.Fatalf("foreign scan inherited exclusions: %v", got)
	}
	r.options.ProjectUUID = "project-b"
	if got := r.supersededHarvestSeedUUIDs("scan-a"); len(got) != 0 {
		t.Fatalf("foreign project inherited exclusions: %v", got)
	}
	r.options.ProjectUUID = "project-a"
	r.options.ScanUUID = "scan-b"
	if got := r.supersededHarvestSeedUUIDs("scan-a"); len(got) != 0 {
		t.Fatalf("changed invocation inherited exclusions: %v", got)
	}
	r.options.ScanUUID = "scan-a"
	r.harvestStubs = []harvestStub{{uuid: "previous-run"}}
	r.resetHarvestProbeState("scan-a", "project-a") // same UUID, new invocation
	if len(r.harvestVersions.versions) != 0 || len(r.harvestStubs) != 0 || len(r.supersededHarvestSeedUUIDs("scan-a")) != 0 {
		t.Fatal("same-identity new run inherited harvest state")
	}
}

func TestHarvestVersions_ResetBeforeRejectedRun(t *testing.T) {
	r := &Runner{
		options: &types.Options{ScanUUID: "rejected", ProjectUUID: "project-a", ManagedScanRecord: true},
		ctx:     context.Background(), done: make(chan struct{}),
	}
	r.resetHarvestProbeState("rejected", "project-a")
	r.rememberHarvestVersion("rejected", "project-a", "seed", "version")
	r.harvestStubs = []harvestStub{{uuid: "seed"}}
	if err := r.RunNativeScan(); err == nil {
		t.Fatal("managed scan without a repository unexpectedly initialized")
	}
	if r.harvestVersions.scanUUID != "" || r.harvestVersions.projectUUID != "" ||
		len(r.harvestVersions.versions) != 0 || len(r.harvestStubs) != 0 {
		t.Fatal("failed initialization retained previous invocation's harvest handoff")
	}
}

func TestHarvestVersions_ReceiveExcludesSeedAndExplicitVersion(t *testing.T) {
	for _, full := range []bool{false, true} {
		opts := &types.Options{ScanUUID: "receive", ProjectUUID: "project-a", ScanOnReceive: true,
			FullNativeScanOnReceive: full, ExternalHarvestEnabled: true, SkipIngestion: true}
		r := &Runner{options: opts}
		r.resetHarvestProbeState(opts.ScanUUID, opts.ProjectUUID)
		r.rememberHarvestVersion(opts.ScanUUID, opts.ProjectUUID, "seed-after-cursor", "exact-version-before-cursor")
		plan := BuildNativeScanPlan(opts)
		if !planRunsPhase(plan, PhaseExternalHarvest) || !planRunsPhase(plan, PhaseHarvestProbe) {
			t.Fatalf("receive plan unexpectedly gates harvest: %+v", plan)
		}
		got := r.harvestAssessmentExcludedUUIDs(opts.ScanUUID)
		if !slices.Equal(got, []string{"seed-after-cursor", "exact-version-before-cursor"}) || r.pendingHarvestVersionCount(opts.ScanUUID) != 1 {
			t.Fatalf("receive full=%v exclusions=%v pending=%d, want seed and queued version", full, got, r.pendingHarvestVersionCount(opts.ScanUUID))
		}
	}
}

// This uses the same DB source builder as runDynamicAssessmentRound. Its actual
// items must carry a response (SkipBaseline's reuse condition), never the seed's
// request/authentication. Completing those items acknowledges the normal source;
// no replacement work item or synthetic cursor callback is involved.
func TestHarvestVersions_DynamicAssessmentSourceAdoptsSavedExchange(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		dedup      bool
	}{
		{"queryless-new", "/keep", false},
		{"queried-new", "/lookup?id=1", false},
		{"queryless-exact-dedup", "/keep", true},
		{"queried-exact-dedup", "/lookup?id=1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			live := &pathLog{}
			body := []byte{'o', 'k', 0, 0xff}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				live.add(req.URL.RequestURI())
				if req.Header.Get("Authorization") != "Bearer fresh" {
					t.Errorf("actual send authorization = %q, want fresh", req.Header.Get("Authorization"))
				}
				// Stable actual response bytes let a second real send exercise exact
				// immutable dedup, independent of the wall clock's HTTP Date header.
				w.Header().Set("Date", "Mon, 01 Jan 2024 00:00:00 GMT")
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			r, infra, repo, _ := newHarvestProbeRunner(t)
			r.settings.DynamicAssessment.MaxParamShapeSamples = 1
			if err := repo.CreateScan(ctx, &database.Scan{UUID: infra.scanUUID, ProjectUUID: r.options.ProjectUUID, Status: "running"}); err != nil {
				t.Fatal(err)
			}
			rr, err := httpmsg.GetRawRequestFromURL(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			rr = httpmsg.NewHttpRequestResponse(rr.Request().WithHeader("Authorization", "Bearer archive"), nil)
			seedCapture := evidence.NewExchange(srv.URL, rr.Target(), rr.Request().Raw(), nil, evidence.ProvenanceSupplied)
			seedCapture.RequestState = evidence.StateUnknown
			seedCapture.ContentHash = seedCapture.Hash()
			rr = rr.WithEvidence(seedCapture)
			requester, err := infra.httpRequester.WithAdditionalHeaders([]string{"Authorization: Bearer fresh", "User-Agent: harvest-adoption-test"})
			if err != nil {
				t.Fatal(err)
			}
			p := newHarvestProber(r, requester, 1)
			var existingUUID string
			if tc.dedup {
				observed, err := p.fetch(ctx, rr)
				if err != nil {
					t.Fatal(err)
				}
				existingUUID, err = repo.SaveRecord(ctx, observed, database.RecordSourceScanner, r.options.ProjectUUID)
				if err != nil {
					t.Fatal(err)
				}
				// Only fixture chronology changes, never capture bytes/fidelity.
				// Prove ordinary DA's reset also admits a version older than the
				// seed/resume cursor, with the excluded seed as the snapshot bound.
				if _, err := repo.DB().NewUpdate().Model((*database.HTTPRecord)(nil)).
					Set("created_at = ?", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)).Where("uuid = ?", existingUUID).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			seedUUID, err := repo.SaveRecordWithLineage(ctx, rr, database.RecordSourceHarvest, r.options.ProjectUUID,
				database.RecordLineage{ScanUUID: infra.scanUUID})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := repo.GetRecordByUUID(ctx, seedUUID)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.UpdateRiskScores(ctx, map[string]int{seedUUID: 100}); err != nil {
				t.Fatal(err)
			}
			finding := &database.Finding{ProjectUUID: r.options.ProjectUUID, ModuleID: "history", FindingHash: "harvest-adoption-history",
				OriginRecordUUID: seedUUID, URL: rr.Target(), Status: database.StatusTriaged}
			if err := repo.SaveFindingDirect(ctx, finding); err != nil {
				t.Fatal(err)
			}
			if err := repo.AdvanceScanCursorBy(ctx, infra.scanUUID, seed.CreatedAt, seedUUID, 1); err != nil {
				t.Fatal(err)
			}
			insertions := 0
			repo.OnRecordSaved = func(*database.HTTPRecord) { insertions++ }
			r.harvestStubs = append(r.harvestStubs, harvestStub{uuid: seedUUID, req: rr})
			origins := groupHarvestOrigins(r.takeHarvestStubs())
			for _, origin := range origins {
				origin.alive = true // isolate survivor fetching/writing from liveness traffic
			}
			if drops := p.fetchStubs(ctx, origins); len(drops) != 0 || p.wfailed.Load() != 0 {
				t.Fatalf("survivor write failed: drops=%v failed=%d", drops, p.wfailed.Load())
			}
			versionUUID := r.harvestVersions.versions[seedUUID]
			if versionUUID == "" || versionUUID == seedUUID {
				t.Fatalf("successful save was not adopted: %v", r.harvestVersions.versions)
			}
			if tc.dedup {
				if versionUUID != existingUUID || insertions != 0 {
					t.Fatalf("exact dedup adoption=%q insertions=%d, want existing %q without callback", versionUUID, insertions, existingUUID)
				}
			} else if insertions != 1 {
				t.Fatalf("new observed exchange insertions=%d, want 1", insertions)
			}
			version, err := repo.GetRecordByUUID(ctx, versionUUID)
			if err != nil {
				t.Fatal(err)
			}
			if !version.HasResponse || version.CaptureRequestState != evidence.StateComplete || version.CaptureResponseState != evidence.StateComplete {
				t.Fatalf("observed version lost capture fidelity: %+v", version)
			}
			if err := version.ValidateCaptureStates(); err != nil {
				t.Fatal(err)
			}
			paidRequests := live.count(tc.path)
			wantPaid := 1
			if tc.dedup {
				wantPaid++ // one real send to seed the existing exact-exchange fixture
			}
			if paidRequests != wantPaid {
				t.Fatalf("probe/fixture sent %d requests, want %d", paidRequests, wantPaid)
			}

			if err := repo.ResetScanCursor(ctx, infra.scanUUID); err != nil { // ordinary DA's phase entry
				t.Fatal(err)
			}
			hosts := []database.HostTarget{{Hostname: "127.0.0.1"}}
			src := r.newDynamicAssessmentSource(infra, hosts)
			defer src.Close()
			item, err := src.Next(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if item.RecordUUID != versionUUID || item.Request.Response() == nil {
				t.Fatalf("DA admitted UUID=%q has_response=%v, want observed %q", item.RecordUUID, item.Request.Response() != nil, versionUUID)
			}
			if item.Request.Request().Header("Authorization") != "Bearer fresh" ||
				!bytes.Equal(item.Request.Request().Raw(), version.RawRequest) || !bytes.Equal(item.Request.Response().Raw(), version.RawResponse) ||
				!bytes.Equal(item.Request.Response().Body(), body) {
				t.Fatal("DA substituted seed authentication/bytes for the actual saved exchange")
			}
			capture := item.Request.Evidence()
			if capture == nil || capture.RequestState != evidence.StateComplete || capture.ResponseState != evidence.StateComplete {
				t.Fatal("DB admission lost the version's supplied capture fidelity")
			}
			if _, err := src.Next(ctx); !errors.Is(err, io.EOF) {
				t.Fatalf("DA source admitted a second item: %v", err)
			}
			if src.ExcludedRecords() != 1 || src.CoalescedDropped() != 0 || src.Unresolved() != 1 {
				t.Fatalf("exclusion/coalescing/ack = %d/%d/%d, want 1/0/1", src.ExcludedRecords(), src.CoalescedDropped(), src.Unresolved())
			}
			item.Complete() // preserve the source's original callback and UUID identity
			item.Complete() // source callback is once-only
			if err := src.FlushCursor(ctx); err != nil {
				t.Fatal(err)
			}
			if src.Unresolved() != 0 {
				t.Fatal("normal acknowledgement left an unresolved snapshot item")
			}
			remaining, err := r.countRemainingDynamicAssessmentRecords(ctx, infra.scanUUID, hosts)
			if err != nil || remaining != 0 {
				t.Fatalf("cursor failed to cover observed version and excluded seed: remaining=%d err=%v", remaining, err)
			}
			feedback := r.newDynamicAssessmentSource(infra, hosts)
			defer feedback.Close()
			if _, err := feedback.Next(ctx); !errors.Is(err, io.EOF) {
				t.Fatalf("feedback round replayed the seed/version: %v", err)
			}
			if got := live.count(tc.path); got != paidRequests {
				t.Fatalf("response-bearing DA admission sent another baseline: %d -> %d", paidRequests, got)
			}
			history, err := repo.GetRecordByUUID(ctx, seedUUID)
			if err != nil {
				t.Fatal(err)
			}
			if history.HasResponse || !bytes.Equal(history.RawRequest, seed.RawRequest) || !bytes.Equal(history.RawResponse, seed.RawResponse) ||
				history.CaptureRequestState != seed.CaptureRequestState || history.CaptureResponseState != seed.CaptureResponseState || history.ScanUUID != seed.ScanUUID {
				t.Fatal("admission rewrote/deleted the historical seed or its capture metadata")
			}
			var linked string
			if err := repo.DB().NewRaw("SELECT origin_record_uuid FROM findings WHERE finding_hash = ?", finding.FindingHash).Scan(ctx, &linked); err != nil {
				t.Fatal(err)
			}
			if linked != seedUUID {
				t.Fatalf("admission retargeted historical finding %q, want seed %q", linked, seedUUID)
			}
		})
	}
}
