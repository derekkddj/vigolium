package database

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestUpdateScanHeartbeat(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScan(ctx, &Scan{UUID: "hb-1", Status: "running", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	at := time.Now().UTC().Truncate(time.Millisecond)
	sent := int64(42)
	if ok, _, err := repo.UpdateScanHeartbeat(ctx, "hb-1", ScanHeartbeat{At: at, Phase: "discovery", RequestsSent: &sent, PID: 1234, Host: "box"}); err != nil || !ok {
		t.Fatalf("update = %v, %v", ok, err)
	}
	got, err := repo.GetScanByUUID(ctx, "hb-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.HeartbeatAt == nil || !got.HeartbeatAt.Equal(at) {
		t.Errorf("heartbeat_at = %v, want %v", got.HeartbeatAt, at)
	}
	if got.CurrentPhase != "discovery" || got.PID != 1234 || got.RunnerHost != "box" || got.TotalRequests != 42 {
		t.Errorf("row = phase %q pid %d host %q total %d", got.CurrentPhase, got.PID, got.RunnerHost, got.TotalRequests)
	}

	// The final beat clears the phase; a nil count leaves total_requests alone.
	if _, _, err := repo.UpdateScanHeartbeat(ctx, "hb-1", ScanHeartbeat{At: at.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetScanByUUID(ctx, "hb-1")
	if got.CurrentPhase != "" || got.TotalRequests != 42 || got.PID != 1234 {
		t.Errorf("after final beat: phase %q total %d pid %d", got.CurrentPhase, got.TotalRequests, got.PID)
	}

	// A finalized row is never re-stamped, and the caller learns it.
	if err := repo.CompleteScan(ctx, "hb-1", ""); err != nil {
		t.Fatal(err)
	}
	late := at.Add(time.Hour)
	ok, _, err := repo.UpdateScanHeartbeat(ctx, "hb-1", ScanHeartbeat{At: late, Phase: "x"})
	if err != nil || ok {
		t.Fatalf("beat on a completed row = %v, %v; want false, nil", ok, err)
	}
	got, _ = repo.GetScanByUUID(ctx, "hb-1")
	if got.HeartbeatAt.Equal(late) || got.CurrentPhase != "" {
		t.Errorf("completed row was re-stamped: %v %q", got.HeartbeatAt, got.CurrentPhase)
	}
}

func TestLastScanLogTimes(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	base := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	logs := []*ScanLog{
		{ScanUUID: "a", Level: "info", Message: "1", CreatedAt: base},
		{ScanUUID: "a", Level: "info", Message: "2", CreatedAt: base.Add(3 * time.Minute)},
		{ScanUUID: "b", Level: "info", Message: "1", CreatedAt: base.Add(time.Minute)},
		{ScanUUID: "c", Level: "info", Message: "unlisted", CreatedAt: base.Add(time.Hour)},
	}
	if err := repo.CreateScanLogBatch(ctx, logs); err != nil {
		t.Fatal(err)
	}

	got, err := repo.LastScanLogTimes(ctx, nil, []string{"a", "b", "none"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries (%v), want 2", len(got), got)
	}
	if !got["a"].Equal(base.Add(3 * time.Minute)) {
		t.Errorf("a = %v, want %v", got["a"], base.Add(3*time.Minute))
	}
	if !got["b"].Equal(base.Add(time.Minute)) {
		t.Errorf("b = %v", got["b"])
	}

	// Project-narrowed read uses the stored (defaulted) project.
	scoped, err := repo.LastScanLogTimes(ctx, []string{defaultProjectUUID("")}, []string{"a"})
	if err != nil || scoped["a"].IsZero() {
		t.Fatalf("scoped = %v, %v", scoped, err)
	}
	empty, err := repo.LastScanLogTimes(ctx, []string{"other-project"}, []string{"a"})
	if err != nil || len(empty) != 0 {
		t.Fatalf("other project = %v, %v", empty, err)
	}
}

var reapAbandonedScanScenarios = []struct {
	name string
	run  func(*testing.T, *DB)
}{
	{"DiagnosticsAndPreservedData", scenarioReapDiagnosticsAndPreservedData},
	{"ConcurrentDiagnostics", scenarioReapConcurrentDiagnostics},
	{"ChangedCapturedRow", scenarioReapChangedCapturedRow},
	{"PausedThenResumed", scenarioReapPausedThenResumed},
	{"LegacyNullLiveness", scenarioReapLegacyNullLiveness},
	{"TimestampRepresentations", scenarioReapTimestampRepresentations},
}

func TestReapAbandonedScan(t *testing.T) {
	for _, sc := range reapAbandonedScanScenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, newTestDB(t)) })
	}
}

func TestPg_ReapAbandonedScan(t *testing.T) {
	for _, sc := range reapAbandonedScanScenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, openPGTestDB(t)) })
	}
}

// Always return a database-loaded capture: native PostgreSQL precision and
// SQLite's timestamp text representation must both survive the reaper guards.
func capturedReaperScan(t *testing.T, repo *Repository) *Scan {
	t.Helper()
	ctx := context.Background()
	started := time.Date(2026, 11, 6, 1, 2, 3, 123456789, time.UTC)
	heartbeat := started.Add(2*time.Minute + 654321*time.Nanosecond)
	scan := &Scan{
		UUID: "reaper-" + t.Name(), ProjectUUID: DefaultProjectUUID,
		Name: "preserve name", Description: "preserve description", Status: "running",
		Target: "https://example.test", Modules: "module-a", Threads: 3,
		ScopeOriginMode: "strict", Profile: "full", SourcePath: "source", SourceType: "local",
		Tags: []string{"keep"}, TriggeredBy: "user", AgenticScanUUID: "agent-scan",
		HTTPRecordUUID: "trigger-record", ScanSource: "cli", ScanMode: "incremental",
		StartCursorAt: started.Add(-time.Hour), StartCursorUUID: "start-cursor",
		CursorAt: started.Add(time.Minute), CursorUUID: "cursor", ProcessedCount: 23,
		StartedAt: started, TotalRequests: 101, TotalFindings: 21,
		CriticalCount: 1, HighCount: 2, MediumCount: 3, LowCount: 4, InfoCount: 5, SuspectCount: 6,
		ErrorMessage: "module-a: connection reset\nmodule-b: budget exhausted",
		StorageURL:   "file:///preserved", Completeness: CompletenessPartial, StopReason: ReasonPhaseError,
		PhaseOutcomes: []PhaseOutcome{
			{Phase: "discovery", State: PhaseCompleted, DurationMS: 123, Counts: map[string]int64{"kept": 7}},
			{Phase: "dynamic-assessment", State: PhasePartial, Reasons: []string{ReasonPhaseDeadline}, Errors: 2, Message: "keep phase diagnostics", Unprocessed: 9},
		},
		Plan:        json.RawMessage(`{"phases":["discovery","dynamic-assessment"]}`),
		HeartbeatAt: &heartbeat, CurrentPhase: "dynamic-assessment", PID: 1234, RunnerHost: "old-host",
		ModuleErrors: map[string]int64{"module-a": 2}, ExtensionsFailed: []string{"extension-a"},
		CreatedAt: started.Add(-time.Minute), UpdatedAt: started.Add(time.Minute),
	}
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	return loadReaperScan(t, repo, scan.UUID)
}

func loadReaperScan(t *testing.T, repo *Repository, uuid string) *Scan {
	t.Helper()
	scan, err := repo.GetScanByUUID(context.Background(), uuid)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

func assertReaperFinalization(t *testing.T, before, after *Scan, finishedAt time.Time, diagnostics string) {
	t.Helper()
	want := *before
	want.Status = "failed"
	want.Completeness = CompletenessPartial
	want.StopReason = ReasonAbandoned
	want.FinishedAt = finishedAt
	want.DurationMs = 0
	if finishedAt.After(before.StartedAt) {
		want.DurationMs = finishedAt.Sub(before.StartedAt).Milliseconds()
	}
	want.CurrentPhase = ""
	want.ErrorMessage = diagnostics
	if !after.UpdatedAt.After(before.UpdatedAt) {
		t.Errorf("updated_at = %v, want after %v", after.UpdatedAt, before.UpdatedAt)
	}
	want.UpdatedAt = after.UpdatedAt
	// Equal handles database location differences for timestamps. DeepEqual
	// below covers EVERY remaining column, not just the headline counts/phases.
	if !after.FinishedAt.Equal(finishedAt) {
		t.Errorf("finished_at = %v, want last observed write %v", after.FinishedAt, finishedAt)
	}
	want.FinishedAt = after.FinishedAt
	if !reflect.DeepEqual(&want, after) {
		t.Errorf("reaped row = %+v\nwant = %+v", after, &want)
	}
}

func scenarioReapDiagnosticsAndPreservedData(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	captured := capturedReaperScan(t, repo)
	log := &ScanLog{ProjectUUID: captured.ProjectUUID, ScanUUID: captured.UUID, Level: "error", Phase: "dynamic-assessment", Message: "original log", Metadata: `{"keep":true}`}
	if err := repo.CreateScanLog(ctx, log); err != nil {
		t.Fatal(err)
	}
	var logBefore ScanLog
	if err := db.NewSelect().Model(&logBefore).Where("id = ?", log.ID).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	x := evidence.NewExchange("https://example.test:443", "https://example.test/probe",
		[]byte("GET /probe HTTP/1.1\r\n\r\n\x00\xff"), []byte("HTTP/1.1 200 OK\r\n\r\nevidence\x00\xff"), evidence.ProvenanceCaptured)
	finding := &Finding{ProjectUUID: captured.ProjectUUID, ScanUUID: captured.UUID,
		FindingHash: "reaper-finding", ModuleID: "module-a", ModuleName: "Module A", Severity: "high",
		URL: x.URL, EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "preserve receipt")}}
	if err := repo.SaveFindingDirect(ctx, finding); err != nil {
		t.Fatal(err)
	}
	findingBefore, err := repo.GetFindingByID(ctx, finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	evidenceBefore, err := repo.GetEvidenceExchange(ctx, x.ID, captured.ProjectUUID)
	if err != nil {
		t.Fatal(err)
	}
	lastWrite := captured.HeartbeatAt.Add(time.Minute)
	msg := "abandoned: the scan's process stopped without finalizing its row (last write " + lastWrite.UTC().Format(time.RFC3339) + ")"
	if ok, err := repo.ReapAbandonedScan(ctx, captured, lastWrite); err != nil || !ok {
		t.Fatalf("reap = %v, %v; want true, nil", ok, err)
	}
	after := loadReaperScan(t, repo, captured.UUID)
	assertReaperFinalization(t, captured, after, lastWrite, captured.ErrorMessage+"\n"+msg)
	if ok, err := repo.ReapAbandonedScan(ctx, captured, lastWrite.Add(time.Hour)); err != nil || ok {
		t.Fatalf("repeat reap = %v, %v; want false, nil", ok, err)
	}
	if repeated := loadReaperScan(t, repo, captured.UUID); !reflect.DeepEqual(after, repeated) {
		t.Fatalf("repeat reap changed row: %+v", repeated)
	}
	var logAfter ScanLog
	if err := db.NewSelect().Model(&logAfter).Where("id = ?", log.ID).Scan(ctx); err != nil || !reflect.DeepEqual(logBefore, logAfter) {
		t.Fatalf("reaper changed scan log: %+v, %v", logAfter, err)
	}
	findingAfter, err := repo.GetFindingByID(ctx, finding.ID)
	if err != nil || !reflect.DeepEqual(findingBefore, findingAfter) {
		t.Fatalf("reaper changed finding/manifest: %+v, %v", findingAfter, err)
	}
	evidenceAfter, err := repo.GetEvidenceExchange(ctx, x.ID, captured.ProjectUUID)
	if err != nil || !reflect.DeepEqual(evidenceBefore, evidenceAfter) {
		t.Fatalf("reaper changed receipt: %+v, %v", evidenceAfter, err)
	}
}

func scenarioReapConcurrentDiagnostics(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	for _, diagnostics := range []struct {
		name   string
		value  any
		prefix string
	}{
		{"Changed", "new concurrent diagnostics\nkeep exactly ", "new concurrent diagnostics\nkeep exactly \n"},
		{"Null", nil, ""},
		{"Empty", "", ""},
	} {
		t.Run(diagnostics.name, func(t *testing.T) {
			captured := capturedReaperScan(t, repo)
			if _, err := db.NewUpdate().Model((*Scan)(nil)).Set("error_message = ?", diagnostics.value).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			current := loadReaperScan(t, repo, captured.UUID)
			lastWrite := *captured.HeartbeatAt
			msg := "abandoned: the scan's process stopped without finalizing its row (last write " + lastWrite.UTC().Format(time.RFC3339) + ")"
			if ok, err := repo.ReapAbandonedScan(ctx, captured, lastWrite); err != nil || !ok {
				t.Fatalf("reap = %v, %v; want true, nil", ok, err)
			}
			assertReaperFinalization(t, current, loadReaperScan(t, repo, captured.UUID), lastWrite, diagnostics.prefix+msg)
		})
	}
}

func scenarioReapChangedCapturedRow(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	for _, change := range []struct {
		name    string
		prepare string
		set     string
		value   func(*Scan) any
	}{
		{"OtherProject", "", "project_uuid = ?", func(*Scan) any { return "other-project" }},
		{"EmptyProjectNeverDefaults", "project_uuid = ''", "project_uuid = ?", func(*Scan) any { return DefaultProjectUUID }},
		{"AdvancedHeartbeat", "", "heartbeat_at = ?", func(s *Scan) any { return s.HeartbeatAt.Add(time.Microsecond) }},
		{"AdvancedHeartbeatSmallestPrecision", "", "heartbeat_at = ?", func(s *Scan) any {
			if db.Driver() == driverSQLite {
				// Bind text to preserve a stored nanosecond that Bun's time writer
				// would truncate; the guard must not round it back to the capture.
				return s.HeartbeatAt.Add(time.Nanosecond).UTC().Format("2006-01-02 15:04:05.999999999")
			}
			return s.HeartbeatAt.Add(time.Microsecond)
		}},
		{"HeartbeatCleared", "", "heartbeat_at = ?", func(*Scan) any { return nil }},
		{"FirstLegacyHeartbeat", "heartbeat_at = NULL", "heartbeat_at = ?", func(s *Scan) any { return s.StartedAt.Add(time.Minute) }},
		{"ChangedPID", "", "pid = ?", func(s *Scan) any { return s.PID + 1 }},
		{"PIDCleared", "", "pid = ?", func(*Scan) any { return nil }},
		{"FirstLegacyPID", "pid = NULL", "pid = ?", func(*Scan) any { return 9876 }},
		{"ChangedHost", "", "runner_host = ?", func(*Scan) any { return "new-host" }},
		{"HostCleared", "", "runner_host = ?", func(*Scan) any { return nil }},
		{"FirstLegacyHost", "runner_host = NULL", "runner_host = ?", func(*Scan) any { return "new-host" }},
		{"ChangedStart", "", "started_at = ?", func(s *Scan) any { return s.StartedAt.Add(time.Microsecond) }},
		{"ChangedEditTime", "", "updated_at = ?", func(s *Scan) any { return s.UpdatedAt.Add(time.Microsecond) }},
		{"ConcurrentCompleted", "", "status = ?", func(*Scan) any { return "completed" }},
		{"ConcurrentFailed", "", "status = ?", func(*Scan) any { return "failed" }},
		{"ConcurrentCancelled", "", "status = ?", func(*Scan) any { return "cancelled" }},
		{"ConcurrentPaused", "", "status = ?", func(*Scan) any { return "paused" }},
		{"ResumedRun", "", "started_at = ?", func(s *Scan) any { return s.StartedAt.Add(time.Hour) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			captured := capturedReaperScan(t, repo)
			if change.prepare != "" {
				if _, err := db.NewUpdate().Model((*Scan)(nil)).Set(change.prepare).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				captured = loadReaperScan(t, repo, captured.UUID)
			}
			if _, err := db.NewUpdate().Model((*Scan)(nil)).Set(change.set, change.value(captured)).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			current := loadReaperScan(t, repo, captured.UUID)
			if reflect.DeepEqual(captured, current) {
				t.Fatal("fixture did not change the captured row")
			}
			if ok, err := repo.ReapAbandonedScan(ctx, captured, captured.StartedAt.Add(3*time.Minute)); err != nil || ok {
				t.Fatalf("reap stale capture = %v, %v; want false, nil", ok, err)
			}
			if after := loadReaperScan(t, repo, captured.UUID); !reflect.DeepEqual(current, after) {
				t.Fatalf("reaper overwrote concurrently changed row: before=%+v after=%+v", current, after)
			}
		})
	}
}

func scenarioReapPausedThenResumed(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	captured := capturedReaperScan(t, repo)
	if err := repo.PauseScan(ctx, captured.UUID); err != nil {
		t.Fatal(err)
	}
	if err := repo.ResumeScan(ctx, captured.UUID); err != nil {
		t.Fatal(err)
	}
	current := loadReaperScan(t, repo, captured.UUID)
	if current.Status != "running" || !current.StartedAt.Equal(captured.StartedAt) ||
		!current.HeartbeatAt.Equal(*captured.HeartbeatAt) || current.UpdatedAt.Equal(captured.UpdatedAt) {
		t.Fatalf("fixture did not resume with an unchanged run/heartbeat and changed edit time: %+v", current)
	}
	if ok, err := repo.ReapAbandonedScan(ctx, captured, *captured.HeartbeatAt); err != nil || ok {
		t.Fatalf("reap resumed row = %v, %v; want false, nil", ok, err)
	}
	if after := loadReaperScan(t, repo, captured.UUID); !reflect.DeepEqual(current, after) {
		t.Fatalf("reaper overwrote resumed row: before=%+v after=%+v", current, after)
	}
}

func scenarioReapLegacyNullLiveness(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	for _, knownWrite := range []bool{true, false} {
		name := "KnownLastWrite"
		if !knownWrite {
			name = "NoLastWrite"
		}
		t.Run(name, func(t *testing.T) {
			captured := capturedReaperScan(t, repo)
			started := captured.StartedAt.Truncate(time.Second)
			if _, err := db.NewUpdate().Model((*Scan)(nil)).
				Set("heartbeat_at = NULL").Set("pid = NULL").Set("runner_host = NULL").
				Set("started_at = ?", started).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			captured = loadReaperScan(t, repo, captured.UUID)
			if captured.HeartbeatAt != nil || captured.PID != 0 || captured.RunnerHost != "" {
				t.Fatalf("fixture is not legacy null liveness: %+v", captured)
			}
			var lastWrite time.Time
			msg := "abandoned: the scan's process stopped without finalizing its row (no liveness signal ever written)"
			if knownWrite {
				lastWrite = started.Add(time.Minute)
				msg = "abandoned: the scan's process stopped without finalizing its row (last write " + lastWrite.UTC().Format(time.RFC3339) + ")"
			}
			earliest := time.Now().UTC().Truncate(time.Microsecond)
			if ok, err := repo.ReapAbandonedScan(ctx, captured, lastWrite); err != nil || !ok {
				t.Fatalf("legacy reap = %v, %v; want true, nil", ok, err)
			}
			latest := time.Now().UTC()
			after := loadReaperScan(t, repo, captured.UUID)
			if !knownWrite {
				if after.FinishedAt.Before(earliest) || after.FinishedAt.After(latest) {
					t.Errorf("unknown last write finish = %v, want within [%v, %v]", after.FinishedAt, earliest, latest)
				}
				lastWrite = after.FinishedAt
			}
			assertReaperFinalization(t, captured, after, lastWrite, captured.ErrorMessage+"\n"+msg)
		})
	}
}

func scenarioReapTimestampRepresentations(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	for _, representation := range []struct {
		name string
		set  string
	}{
		{"SQLCurrentTimestamp", "started_at = CURRENT_TIMESTAMP, heartbeat_at = CURRENT_TIMESTAMP"},
		{"FractionalTrailingZeros", "started_at = '2026-11-06 01:02:03.123400000+00:00', heartbeat_at = '2026-11-06 01:04:03.123400000+00:00'"},
		{"RawNanoseconds", "started_at = '2026-11-06 01:02:03.123456789+00:00', heartbeat_at = '2026-11-06 01:04:03.123456789+00:00'"},
		{"SQLWholeSeconds", "started_at = '2026-11-06 01:02:03', heartbeat_at = '2026-11-06 01:04:03'"},
	} {
		t.Run(representation.name, func(t *testing.T) {
			captured := capturedReaperScan(t, repo)
			if _, err := db.NewUpdate().Model((*Scan)(nil)).Set(representation.set).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			captured = loadReaperScan(t, repo, captured.UUID)
			// Keep the finish within Bun's write precision while guarding the
			// exact loaded start/heartbeat, including raw SQLite nanoseconds.
			lastWrite := captured.HeartbeatAt.Truncate(time.Second).Add(time.Minute)
			msg := "abandoned: the scan's process stopped without finalizing its row (last write " + lastWrite.UTC().Format(time.RFC3339) + ")"
			if ok, err := repo.ReapAbandonedScan(ctx, captured, lastWrite); err != nil || !ok {
				t.Fatalf("timestamp round-trip reap = %v, %v; want true, nil", ok, err)
			}
			assertReaperFinalization(t, captured, loadReaperScan(t, repo, captured.UUID), lastWrite, captured.ErrorMessage+"\n"+msg)
		})
	}
}

func TestReapAbandonedScanNil(t *testing.T) {
	if ok, err := NewRepository(newTestDB(t)).ReapAbandonedScan(context.Background(), nil, time.Time{}); err != nil || ok {
		t.Fatalf("nil reap = %v, %v; want false, nil", ok, err)
	}
}

var resumeNativeScanScenarios = []struct {
	name string
	run  func(*testing.T, *DB)
}{
	{"ClearsStopAndPreservesData", scenarioResumeNativeScanPreservesData},
	{"CapturedRowChanged", scenarioResumeNativeScanChangedRow},
	{"StopAfterTransition", scenarioResumeNativeScanStopAfterTransition},
	{"ConcurrentResumes", scenarioResumeNativeScanConcurrent},
}

func TestResumeNativeScan(t *testing.T) {
	for _, sc := range resumeNativeScanScenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, newTestDB(t)) })
	}
}

func TestPg_ResumeNativeScan(t *testing.T) {
	for _, sc := range resumeNativeScanScenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, openPGTestDB(t)) })
	}
}

func capturedStoppedScan(t *testing.T, repo *Repository, status string) *Scan {
	t.Helper()
	ctx := context.Background()
	scan := capturedReaperScan(t, repo) // Rich fixture: every preserved column is checked below.
	if ok, err := repo.RequestScanStop(ctx, scan.UUID, "cli:old-stop"); err != nil || !ok {
		t.Fatalf("fixture STOP = %v, %v", ok, err)
	}
	if _, err := repo.DB().NewUpdate().Model((*Scan)(nil)).
		Set("status = ?", status).Set("finished_at = ?", scan.StartedAt.Add(3*time.Minute)).
		Where("uuid = ?", scan.UUID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return loadReaperScan(t, repo, scan.UUID)
}

func scenarioResumeNativeScanPreservesData(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	for _, status := range []string{"completed", "failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			before := capturedStoppedScan(t, repo, status)
			if ok, err := repo.ResumeNativeScan(ctx, before); err != nil || !ok {
				t.Fatalf("resume = %v, %v; want true, nil", ok, err)
			}
			after := loadReaperScan(t, repo, before.UUID)
			want := *before
			want.Status = "running"
			if !after.UpdatedAt.After(before.UpdatedAt) {
				t.Errorf("updated_at = %v, want after %v", after.UpdatedAt, before.UpdatedAt)
			}
			want.UpdatedAt = after.UpdatedAt
			if !reflect.DeepEqual(&want, after) {
				t.Fatalf("resume changed preserved columns: got=%+v want=%+v", after, &want)
			}
			var stopColumns struct {
				At *time.Time `bun:"stop_requested_at"`
				By *string    `bun:"stop_requested_by"`
			}
			if err := db.NewSelect().TableExpr("scans").ColumnExpr("stop_requested_at, stop_requested_by").
				Where("uuid = ?", before.UUID).Scan(ctx, &stopColumns); err != nil {
				t.Fatal(err)
			}
			if stopColumns.At != nil || stopColumns.By != nil {
				t.Fatalf("resume did not clear BOTH STOP columns: %+v", stopColumns)
			}
			if ok, req, err := repo.UpdateScanHeartbeat(ctx, before.UUID, ScanHeartbeat{ProjectUUID: before.ProjectUUID, At: time.Now()}); err != nil || !ok || req != nil {
				t.Fatalf("resumed heartbeat = %v, %+v, %v", ok, req, err)
			}
		})
	}
}

func scenarioResumeNativeScanChangedRow(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	for _, change := range []struct {
		name string
		set  string
	}{
		{"ReassignedProject", "project_uuid = 'other-project'"},
		{"Running", "status = 'running'"},
		{"Paused", "status = 'paused'"},
		{"TerminalStatusChanged", "status = 'completed'"},
		{"Edited", "updated_at = '2026-11-06 01:03:04.123400'"},
		{"Deleted", ""},
	} {
		t.Run(change.name, func(t *testing.T) {
			captured := capturedStoppedScan(t, repo, "cancelled")
			if change.set == "" {
				if _, err := db.NewDelete().Model((*Scan)(nil)).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			} else if _, err := db.NewUpdate().Model((*Scan)(nil)).Set(change.set).Where("uuid = ?", captured.UUID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			var current *Scan
			if change.set != "" {
				current = loadReaperScan(t, repo, captured.UUID)
			}
			stopBefore, err := repo.ScanStopRequested(ctx, captured.UUID)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := repo.ResumeNativeScan(ctx, captured); err != nil || ok {
				t.Fatalf("resume stale capture = %v, %v; want false, nil", ok, err)
			}
			if current != nil && !reflect.DeepEqual(current, loadReaperScan(t, repo, captured.UUID)) {
				t.Fatal("resume overwrote a concurrently changed row")
			}
			if stopAfter, err := repo.ScanStopRequested(ctx, captured.UUID); err != nil || !reflect.DeepEqual(stopBefore, stopAfter) {
				t.Fatalf("refused resume changed STOP: before=%+v after=%+v err=%v", stopBefore, stopAfter, err)
			}
		})
	}
	for _, status := range []string{"running", "paused", "queued", ""} {
		t.Run("CapturedNonterminal-"+status, func(t *testing.T) {
			captured := capturedStoppedScan(t, repo, status)
			stopBefore, err := repo.ScanStopRequested(ctx, captured.UUID)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := repo.ResumeNativeScan(ctx, captured); err != nil || ok {
				t.Fatalf("nonterminal %q resume = %v, %v", status, ok, err)
			}
			if !reflect.DeepEqual(captured, loadReaperScan(t, repo, captured.UUID)) {
				t.Fatal("resume changed a live/nonterminal row")
			}
			if stopAfter, err := repo.ScanStopRequested(ctx, captured.UUID); err != nil || !reflect.DeepEqual(stopBefore, stopAfter) {
				t.Fatalf("resume changed a live STOP: %+v, %v", stopAfter, err)
			}
		})
	}
	if ok, err := repo.ResumeNativeScan(ctx, nil); err != nil || ok {
		t.Fatalf("nil resume = %v, %v", ok, err)
	}
}

// The hook interleaves a fresh STOP after the transition commits, BEFORE the
// resume method returns. It also catches splitting status and STOP resets into
// separate statements, without sleeps or scheduler-dependent timing.
type resumeStopHook struct {
	repo    *Repository
	uuid    string
	fired   atomic.Bool
	query   string
	stopErr error
	stopped bool
}

func (h *resumeStopHook) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (h *resumeStopHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	if event.Err != nil || !strings.HasPrefix(event.Query, "UPDATE ") ||
		!strings.Contains(event.Query, "status = 'running'") || !h.fired.CompareAndSwap(false, true) {
		return
	}
	h.query = event.Query
	h.stopped, h.stopErr = h.repo.RequestScanStop(ctx, h.uuid, "rest:after-transition")
}

func scenarioResumeNativeScanStopAfterTransition(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	captured := capturedStoppedScan(t, repo, "cancelled")
	hook := &resumeStopHook{repo: repo, uuid: captured.UUID}
	db.AddQueryHook(hook)
	if ok, err := repo.ResumeNativeScan(ctx, captured); err != nil || !ok {
		t.Fatalf("resume = %v, %v", ok, err)
	}
	if !hook.fired.Load() || hook.stopErr != nil || !hook.stopped {
		t.Fatalf("STOP at transition boundary = fired %v, stopped %v, err %v", hook.fired.Load(), hook.stopped, hook.stopErr)
	}
	if !strings.Contains(hook.query, "stop_requested_at = NULL") || !strings.Contains(hook.query, "stop_requested_by = NULL") {
		t.Fatalf("transition and STOP reset must be ONE statement: %s", hook.query)
	}
	newStop, err := repo.ScanStopRequested(ctx, captured.UUID)
	if err != nil || newStop == nil || newStop.By != "rest:after-transition" {
		t.Fatalf("STOP after transition was lost: %+v, %v", newStop, err)
	}
	// The losing resume must not clear the winner's newly received STOP.
	if ok, err := repo.ResumeNativeScan(ctx, captured); err != nil || ok {
		t.Fatalf("stale second resume = %v, %v", ok, err)
	}
	if ok, req, err := repo.UpdateScanHeartbeat(ctx, captured.UUID, ScanHeartbeat{ProjectUUID: captured.ProjectUUID, At: time.Now()}); err != nil || !ok || !reflect.DeepEqual(newStop, req) {
		t.Fatalf("heartbeat lost fresh STOP: %v, %+v, %v", ok, req, err)
	}
}

func scenarioResumeNativeScanConcurrent(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	captured := capturedStoppedScan(t, repo, "cancelled")
	start := make(chan struct{})
	type result struct {
		ok  bool
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			ok, err := repo.ResumeNativeScan(ctx, captured)
			results <- result{ok, err}
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		res := <-results
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent resumes had %d winners, want exactly one", winners)
	}
}
