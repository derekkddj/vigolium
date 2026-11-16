package runner

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// pathLog records every request path a test server saw.
type pathLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *pathLog) add(p string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paths = append(l.paths, p)
}

func (l *pathLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.paths...)
}

func (l *pathLog) count(p string) int {
	n := 0
	for _, got := range l.snapshot() {
		if got == p {
			n++
		}
	}
	return n
}

// refusedHost returns the base URL of a port nothing listens on: every dial is
// refused, the one failure that marks a harvested origin dead.
func refusedHost(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

// deadHost accepts connections, reads the request line, and hangs up without
// answering: an origin that resolves and listens but never speaks HTTP.
func deadHost(t *testing.T) (base string, log *pathLog) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	log = &pathLog{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			if f := strings.Fields(line); len(f) >= 2 {
				log.add(f[1])
			}
			_ = conn.Close()
		}
	}()
	return "http://" + ln.Addr().String(), log
}

func newHarvestProbeRunner(t *testing.T) (*Runner, *phaseInfra, *database.Repository, *phaseTracker) {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Silent = true
	opts.Retries = 0
	opts.Concurrency = 4
	opts.ProjectUUID = database.DefaultProjectUUID
	opts.ScanUUID = "harvest-probe-test"
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	requester, err := vighttp.NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	repo, _ := newHarvestTestRepo(t)
	r := &Runner{options: opts, repository: repo, settings: config.DefaultSettings()}
	r.resetHarvestProbeState(opts.ScanUUID, opts.ProjectUUID)
	tr := newLedger(string(PhaseHarvestProbe))
	r.currentPhase.Store(tr)
	return r, &phaseInfra{httpRequester: requester, scanUUID: "harvest-probe-test"}, repo, tr
}

// queueStubs stores each URL as external-harvest would and queues it for the probe.
func queueStubs(t *testing.T, r *Runner, repo *database.Repository, urls ...string) map[string]string {
	t.Helper()
	ids := make(map[string]string, len(urls))
	for _, u := range urls {
		rr, err := httpmsg.GetRawRequestFromURL(u)
		if err != nil {
			t.Fatalf("request for %s: %v", u, err)
		}
		id, err := repo.SaveRecord(context.Background(), rr, database.RecordSourceHarvest, r.options.ProjectUUID)
		if err != nil {
			t.Fatalf("save %s: %v", u, err)
		}
		ids[u] = id
		r.harvestStubs = append(r.harvestStubs, harvestStub{uuid: id, req: rr})
	}
	return ids
}

// TestHarvestProbe_KeepsLiveDropsDeadAndNotFound: the probe fetches each
// harvested URL on a live host exactly once, keeps what answers (new immutable
// versions, still source=harvest), deletes 404/410/soft-404 stubs, and drops a dead
// host's URLs wholesale after its single liveness request.
func TestHarvestProbe_KeepsLiveDropsDeadAndNotFound(t *testing.T) {
	logCore, logs := observer.New(zap.WarnLevel)
	restoreLogger := zap.ReplaceGlobals(zap.New(logCore))
	t.Cleanup(restoreLogger)
	live := &pathLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		live.add(req.URL.Path)
		switch req.URL.Path {
		case "/keep":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}`))
		case "/old-login":
			http.Redirect(w, req, "/auth/sign-in", http.StatusFound)
		case "/gone":
			http.NotFound(w, req)
		case "/removed":
			w.WriteHeader(http.StatusGone)
		default:
			// Catch-all: every unknown path gets the same SPA shell.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<html><body><div id=app></div>" + strings.Repeat("x", 400) + "</body></html>"))
		}
	}))
	defer srv.Close()
	dead := refusedHost(t)
	// A host that accepts and hangs up is reachable: one failed liveness
	// request is no reason to delete what the archive saw there.
	hangup, _ := deadHost(t)

	r, infra, repo, tr := newHarvestProbeRunner(t)
	ids := queueStubs(t, r, repo,
		srv.URL+"/keep", srv.URL+"/old-login", srv.URL+"/gone", srv.URL+"/removed", srv.URL+"/soft",
		dead+"/a", dead+"/b?id=1", dead+"/c", hangup+"/h1", hangup+"/h2")
	seeds := make(map[string]*database.HTTPRecord, 2)
	for _, u := range []string{srv.URL + "/keep", srv.URL + "/old-login"} {
		seed, err := repo.GetRecordByUUID(context.Background(), ids[u])
		if err != nil {
			t.Fatal(err)
		}
		seeds[u] = seed
	}
	// Saves publish a new snapshot identity, not a rewritten seed. The phase's
	// sole writer owns this map until runHarvestProbePhase has joined it.
	versions := make(map[string]string)
	repo.OnRecordSaved = func(rec *database.HTTPRecord) { versions[rec.URL] = rec.UUID }

	if err := r.runHarvestProbePhase(context.Background(), infra); err != nil {
		t.Fatalf("runHarvestProbePhase: %v", err)
	}
	for _, entry := range logs.FilterMessage("HarvestProbe: failed to store observed version").All() {
		t.Errorf("harvest persistence error: %v", entry.ContextMap())
	}
	if len(versions) != 2 {
		t.Errorf("saved %d versions, want 2: %v", len(versions), versions)
	}

	// Live host: one liveness request plus exactly one GET per harvested URL.
	for _, p := range []string{"/keep", "/old-login", "/gone", "/removed", "/soft"} {
		if n := live.count(p); n != 1 {
			t.Errorf("live host: %s requested %d times, want 1", p, n)
		}
	}
	if got := len(live.snapshot()); got != 6 {
		t.Errorf("live host saw %d requests, want 6 (1 liveness + 5 URLs): %v", got, live.snapshot())
	}
	// The redirect is recorded, not followed.
	if n := live.count("/auth/sign-in"); n != 0 {
		t.Errorf("redirect target fetched %d times; the probe must record redirects, not follow them", n)
	}
	ctx := context.Background()
	for _, u := range []string{hangup + "/h1", hangup + "/h2"} {
		if rec, err := repo.GetRecordByUUID(ctx, ids[u]); err != nil || rec == nil {
			t.Errorf("stub %s on a reachable-but-silent host was deleted; it must be kept", u)
		}
	}
	for u, want := range map[string]int{srv.URL + "/keep": 200, srv.URL + "/old-login": 302} {
		versionUUID := versions[u]
		if adopted := r.harvestVersions.versions[ids[u]]; adopted != versionUUID || adopted == "" {
			t.Errorf("survivor %s: native handoff = %q, want saved version %q", u, adopted, versionUUID)
		}
		if versionUUID == "" || versionUUID == ids[u] {
			t.Errorf("survivor %s: version UUID = %q, want a new UUID distinct from %s", u, versionUUID, ids[u])
			continue
		}
		rec, err := repo.GetRecordByUUID(ctx, versionUUID)
		if err != nil {
			t.Fatalf("survivor %s: %v", u, err)
		}
		if !rec.HasResponse || rec.StatusCode != want || rec.Source != database.RecordSourceHarvest {
			t.Errorf("survivor %s: has_response=%v status=%d source=%q, want true/%d/harvest",
				u, rec.HasResponse, rec.StatusCode, rec.Source, want)
		}
		if rec.CaptureRequestState != evidence.StateComplete || rec.CaptureResponseState != evidence.StateComplete {
			t.Errorf("survivor %s: capture states = %s/%s, want complete/complete", u, rec.CaptureRequestState, rec.CaptureResponseState)
		}
		if err := rec.ValidateCaptureStates(); err != nil {
			t.Errorf("survivor %s: invalid capture metadata: %v", u, err)
		}
		history, err := repo.GetRecordByUUID(ctx, ids[u])
		if err != nil {
			t.Fatalf("historical stub %s: %v", u, err)
		}
		seed := seeds[u]
		if history.HasResponse || history.StatusCode != 0 || !bytes.Equal(history.RawRequest, seed.RawRequest) || !bytes.Equal(history.RawResponse, seed.RawResponse) ||
			history.CaptureRequestState != seed.CaptureRequestState || history.CaptureResponseState != seed.CaptureResponseState {
			t.Errorf("historical stub %s was rewritten by the probe", u)
		}
		if want == 200 && string(rec.ParsedResponse().Body()) != `{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}` {
			t.Errorf("survivor %s: wrong actual response body", u)
		}
		if want == 302 && rec.ResponseLocation != "/auth/sign-in" {
			t.Errorf("survivor %s: Location = %q, want /auth/sign-in", u, rec.ResponseLocation)
		}
	}
	for _, u := range []string{srv.URL + "/gone", srv.URL + "/removed", srv.URL + "/soft", dead + "/a", dead + "/b?id=1", dead + "/c"} {
		if rec, err := repo.GetRecordByUUID(ctx, ids[u]); err == nil && rec != nil {
			t.Errorf("dropped URL %s is still stored (status=%d)", u, rec.StatusCode)
		}
	}

	out := tr.finish(ctx, nil)
	want := map[string]int64{
		harvestCountStubs:       10,
		harvestCountHosts:       3,
		harvestCountUnprobed:    2,
		harvestCountHostsDead:   1,
		harvestCountProbed:      5,
		harvestCountKept:        2,
		harvestCountDeadHost:    3,
		harvestCountNotFound:    2,
		harvestCountSoft404:     1,
		harvestCountDeleted:     6,
		harvestCountWriteFailed: 0,
	}
	for k, v := range want {
		if out.Counts[k] != v {
			t.Errorf("counts[%s] = %d, want %d (all: %v)", k, out.Counts[k], v, out.Counts)
		}
	}
	if out.State != database.PhaseCompleted {
		t.Errorf("state = %s, want completed", out.State)
	}
}

func TestHarvestProbe_FetchOwnsFreshExchangeInsteadOfSeedSnapshot(t *testing.T) {
	actual := make(chan *http.Request, 1)
	body := []byte{'o', 'k', 0, 0xff}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		actual <- req.Clone(req.Context())
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	r, infra, repo, _ := newHarvestProbeRunner(t)
	ctx := context.Background()
	target := srv.URL + "/keep"
	rr, err := httpmsg.GetRawRequestFromURL(target)
	if err != nil {
		t.Fatal(err)
	}
	// A supplied archive seed has unknown request fidelity and no response. It
	// must not donate its metadata or intended bytes to the transport receipt.
	seed := evidence.NewExchange(srv.URL, target, rr.Request().Raw(), nil, evidence.ProvenanceSupplied)
	seed.RequestState = evidence.StateUnknown
	seed.ContentHash = seed.Hash()
	rr = rr.WithEvidence(seed)
	oldUUID, err := repo.SaveRecord(ctx, rr, database.RecordSourceHarvest, r.options.ProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	finding := &database.Finding{ProjectUUID: r.options.ProjectUUID, ModuleID: "history", FindingHash: "harvest-probe-history",
		OriginRecordUUID: oldUUID, URL: target, Status: database.StatusTriaged}
	if err := repo.SaveFindingDirect(ctx, finding); err != nil {
		t.Fatal(err)
	}

	requester, err := infra.httpRequester.WithAdditionalHeaders([]string{"Authorization: Bearer fresh"})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := newHarvestProber(r, requester, 1).fetch(ctx, rr)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	capture := observed.Evidence()
	if capture == nil {
		t.Fatal("fetch returned no owned receipt")
	}
	if err := capture.Validate(); err != nil {
		t.Fatal(err)
	}
	if capture.ID == seed.ID || capture.Provenance != evidence.ProvenanceCaptured ||
		capture.RequestState != evidence.StateComplete || capture.ResponseState != evidence.StateComplete {
		t.Fatalf("fetch reused or degraded the seed receipt: %+v", capture)
	}
	if !bytes.Equal(observed.Request().Raw(), capture.Request) || !bytes.Equal(observed.Response().Raw(), capture.Response) || !bytes.Equal(observed.Response().Body(), body) {
		t.Fatal("closed transport chain changed the actual captured messages")
	}
	sent := <-actual
	if sent.Header.Get("Authorization") != "Bearer fresh" {
		t.Errorf("actual send lost fresh session authorization: %q", sent.Header.Get("Authorization"))
	}
	for _, name := range []string{"Host", "Authorization", "User-Agent", "Accept-Encoding"} {
		want := sent.Header.Get(name)
		if name == "Host" {
			want = sent.Host
		}
		if got := observed.Request().Header(name); got != want {
			t.Errorf("captured %s = %q, want actual sent %q", name, got, want)
		}
	}
	versionUUID, err := repo.SaveRecordVersion(ctx, oldUUID, observed)
	if err != nil {
		t.Fatalf("save actual captured version: %v", err)
	}
	if versionUUID == oldUUID {
		t.Fatal("observed exchange reused the request-only UUID")
	}
	version, err := repo.GetRecordByUUID(ctx, versionUUID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(version.RawRequest, capture.Request) || !bytes.Equal(version.RawResponse, capture.Response) ||
		version.CaptureRequestState != capture.RequestState || version.CaptureResponseState != capture.ResponseState {
		t.Fatal("saved version does not describe the fresh captured exchange")
	}
	history, err := repo.GetRecordByUUID(ctx, oldUUID)
	if err != nil {
		t.Fatal(err)
	}
	if history.HasResponse || !bytes.Equal(history.RawRequest, seed.Request) || len(history.RawResponse) != 0 ||
		history.CaptureRequestState != evidence.StateUnknown || history.CaptureResponseState != evidence.StateMissing {
		t.Fatal("probe changed the historical seed's bytes or capture states")
	}
	var linked string
	if err := repo.DB().NewRaw("SELECT origin_record_uuid FROM findings WHERE finding_hash = ?", finding.FindingHash).Scan(ctx, &linked); err != nil {
		t.Fatal(err)
	}
	if linked != oldUUID {
		t.Errorf("historical finding now links %s, want original stub %s", linked, oldUUID)
	}
}

// TestHarvestProbe_DisabledByConfig: external_harvester.probe: false sends
// nothing and leaves every stub for the later phases.
func TestHarvestProbe_DisabledByConfig(t *testing.T) {
	live := &pathLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		live.add(req.URL.Path)
		http.NotFound(w, req)
	}))
	defer srv.Close()

	r, infra, repo, _ := newHarvestProbeRunner(t)
	off := false
	r.settings.ExternalHarvester.Probe = &off
	ids := queueStubs(t, r, repo, srv.URL+"/a")

	if err := r.runHarvestProbePhase(context.Background(), infra); err != nil {
		t.Fatalf("runHarvestProbePhase: %v", err)
	}
	if got := live.snapshot(); len(got) != 0 {
		t.Fatalf("probe disabled by config sent %d request(s): %v", len(got), got)
	}
	rec, err := repo.GetRecordByUUID(context.Background(), ids[srv.URL+"/a"])
	if err != nil || rec.HasResponse {
		t.Fatalf("stub should be left untouched: rec=%v err=%v", rec, err)
	}
}

// TestDeleteRequestOnlyStubs_SparesFetchedRecords: a harvested URL that deduped
// onto an existing, fetched record shares its UUID; dropping the URL must not
// delete that record.
func TestDeleteRequestOnlyStubs_SparesFetchedRecords(t *testing.T) {
	repo, _ := newHarvestTestRepo(t)
	ctx := context.Background()

	stubRR, _ := httpmsg.GetRawRequestFromURL("http://example.test/stub")
	stubID, err := repo.SaveRecord(ctx, stubRR, database.RecordSourceHarvest, "")
	if err != nil {
		t.Fatal(err)
	}
	fetchedRR, _ := httpmsg.GetRawRequestFromURL("http://example.test/fetched")
	fetchedRR = fetchedRR.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")))
	fetchedID, err := repo.SaveRecord(ctx, fetchedRR, database.RecordSourceHarvest, "")
	if err != nil {
		t.Fatal(err)
	}
	otherRR, _ := httpmsg.GetRawRequestFromURL("http://example.test/other")
	otherID, err := repo.SaveRecord(ctx, otherRR, database.RecordSourceScanner, "")
	if err != nil {
		t.Fatal(err)
	}

	n, err := repo.DeleteRequestOnlyStubs(ctx, "", database.RecordSourceHarvest, []string{stubID, fetchedID, otherID})
	if err != nil {
		t.Fatalf("DeleteRequestOnlyStubs: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d rows, want 1 (only the request-only harvest stub)", n)
	}
	for _, id := range []string{fetchedID, otherID} {
		if _, err := repo.GetRecordByUUID(ctx, id); err != nil {
			t.Errorf("record %s was deleted: %v", id, err)
		}
	}
}

func TestClassifyHarvestResponse(t *testing.T) {
	resp := func(status int, ct, loc, body string) *httpmsg.HttpResponse {
		raw := "HTTP/1.1 " + strconv.Itoa(status) + " X\r\n"
		if ct != "" {
			raw += "Content-Type: " + ct + "\r\n"
		}
		if loc != "" {
			raw += "Location: " + loc + "\r\n"
		}
		return httpmsg.NewHttpResponse([]byte(raw + "\r\n" + body))
	}
	shell := strings.Repeat("s", 1000)
	catchAll := newNotFoundPrint(resp(200, "text/html", "", shell), "/vigolium-0123456789abcdef")
	realNotFound := newNotFoundPrint(resp(404, "text/html", "", "nope"), "/vigolium-0123456789abcdef")
	loginWall := newNotFoundPrint(resp(302, "", "/login?next=/vigolium-0123456789abcdef", ""), "/vigolium-0123456789abcdef")
	forbidden := newNotFoundPrint(resp(403, "text/html", "", shell), "/vigolium-0123456789abcdef")

	cases := []struct {
		name string
		fp   *notFoundPrint
		resp *httpmsg.HttpResponse
		want harvestVerdict
	}{
		{"404 always dropped", nil, resp(404, "", "", ""), harvestNotFound},
		{"410 always dropped", catchAll, resp(410, "", "", ""), harvestNotFound},
		{"same shell is soft-404", catchAll, resp(200, "text/html; charset=utf-8", "", shell), harvestSoft404},
		{"shell with reflected path is soft-404", catchAll, resp(200, "text/html", "", shell+"/x"), harvestSoft404},
		{"different media type kept", catchAll, resp(200, "application/json", "", shell), harvestKeep},
		{"different size kept", catchAll, resp(200, "text/html", "", strings.Repeat("s", 2000)), harvestKeep},
		{"real-404 host: 200 kept", realNotFound, resp(200, "text/html", "", "nope"), harvestKeep},
		{"same login redirect is soft-404", loginWall, resp(302, "", "/login?next=/admin", ""), harvestSoft404},
		{"different redirect kept", loginWall, resp(302, "", "/admin/", ""), harvestKeep},
		{"403-everywhere host: 403 kept", forbidden, resp(403, "text/html", "", shell), harvestKeep},
		{"no fingerprint: 200 kept", nil, resp(200, "text/html", "", shell), harvestKeep},
	}
	for _, tc := range cases {
		if got := classifyHarvestResponse(tc.fp, tc.resp, "/some/path"); got != tc.want {
			t.Errorf("%s: verdict %d, want %d", tc.name, got, tc.want)
		}
	}
}
