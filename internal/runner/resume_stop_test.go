package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// No infrastructure, targets, or providers: exercise admission and the exact
// heartbeat STOP polling path against a temporary store.
func stoppedResumeRunner(t *testing.T) *Runner {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	repo := openStopTestRepo(t, t.TempDir())
	started := time.Date(2026, 11, 6, 1, 2, 3, 123400000, time.UTC)
	if err := repo.CreateScan(ctx, &database.Scan{
		UUID: "resume-stopped", ProjectUUID: database.DefaultProjectUUID,
		Status: "running", StartedAt: started,
		CursorAt: started.Add(time.Minute), CursorUUID: "preserved-cursor", ProcessedCount: 7,
		CoverageModules: []string{"preserved-module"},
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.RequestScanStop(ctx, "resume-stopped", "cli:old-stop"); err != nil || !ok {
		t.Fatalf("old STOP = %v, %v", ok, err)
	}
	if err := repo.CompleteScanWithOutcomeForProject(ctx, database.DefaultProjectUUID, "resume-stopped", "cancelled",
		database.ScanCompletion{Completeness: database.CompletenessPartial, StopReason: database.ReasonUserStopped}); err != nil {
		t.Fatal(err)
	}
	opts := types.DefaultOptions()
	opts.ProjectUUID = database.DefaultProjectUUID
	opts.ResumeScanUUID = "resume-stopped"
	return &Runner{ctx: ctx, cancel: cancel, options: opts, settings: config.DefaultSettings(), repository: repo}
}

func TestNativeResumeClearsOldStopBeforeHeartbeat(t *testing.T) {
	r := stoppedResumeRunner(t)
	ctx := context.Background()
	before, err := r.repository.GetScanByUUID(ctx, r.options.ResumeScanUUID)
	if err != nil {
		t.Fatal(err)
	}
	// ScanUUID is deliberately unset: admission must select the resume UUID,
	// not create a new row and leave the stopped row terminal.
	scope, err := r.initializeNativeScan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if scope.scanUUID != r.options.ResumeScanUUID || r.options.ScanUUID != scope.scanUUID {
		t.Fatalf("admitted identity = %+v, options UUID = %q", scope, r.options.ScanUUID)
	}
	after, err := r.repository.GetScanByUUID(ctx, scope.scanUUID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "running" || after.CursorUUID != before.CursorUUID ||
		!after.CursorAt.Equal(before.CursorAt) || after.ProcessedCount != before.ProcessedCount ||
		!reflect.DeepEqual(after.CoverageModules, before.CoverageModules) {
		t.Fatalf("resume lost persisted work: before=%+v after=%+v", before, after)
	}
	h := StartHeartbeat(HeartbeatConfig{Repo: r.repository, ScanUUID: scope.scanUUID,
		ProjectUUID: scope.projectUUID, Interval: time.Hour, OnStopRequest: r.handleStopRequest})
	defer h.Stop(ctx)
	rowDone, req := h.beat(ctx, false)
	if rowDone || req != nil {
		t.Fatalf("first resumed heartbeat = rowDone %v, STOP %+v", rowDone, req)
	}
	h.pollStopRequest(req)
	if r.ctx.Err() != nil || r.StopRequestedBy() != "" {
		t.Fatal("the old durable STOP cancelled the resumed runner")
	}

	// A STOP made after admission belongs to THIS run and must still cancel it.
	if ok, err := r.repository.RequestScanStop(ctx, scope.scanUUID, "rest:new-stop"); err != nil || !ok {
		t.Fatalf("new STOP = %v, %v", ok, err)
	}
	_, req = h.beat(ctx, false)
	h.pollStopRequest(req)
	if r.ctx.Err() == nil || r.StopRequestedBy() != "rest:new-stop" {
		t.Fatalf("new STOP was not delivered: ctx=%v by=%q", r.ctx.Err(), r.StopRequestedBy())
	}
}

func TestResumeScanRowRefusesForeignOwner(t *testing.T) {
	for _, owner := range []string{"other-project", ""} {
		t.Run("Owner-"+owner, func(t *testing.T) {
			r := stoppedResumeRunner(t)
			ctx := context.Background()
			if _, err := r.repository.DB().NewUpdate().Model((*database.Scan)(nil)).
				Set("project_uuid = ?", owner).Where("uuid = ?", r.options.ResumeScanUUID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			before, err := r.repository.GetScanByUUID(ctx, r.options.ResumeScanUUID)
			if err != nil {
				t.Fatal(err)
			}
			oldStop, err := r.repository.ScanStopRequested(ctx, before.UUID)
			if err != nil || oldStop == nil {
				t.Fatalf("fixture STOP = %+v, %v", oldStop, err)
			}
			err = r.resumeScanRow(ctx, before.UUID)
			var re *ResumeError
			if !errors.As(err, &re) || re.Code() != apicontract.CodeScanNotFound {
				t.Fatalf("foreign owner resume = %v, want scan_not_found", err)
			}
			after, err := r.repository.GetScanByUUID(ctx, before.UUID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("foreign owner row changed: %+v, %v", after, err)
			}
			if stop, err := r.repository.ScanStopRequested(ctx, before.UUID); err != nil || !reflect.DeepEqual(oldStop, stop) {
				t.Fatalf("foreign owner's STOP changed: %+v, %v", stop, err)
			}
		})
	}
}

func TestNativeResumeMissingDoesNotCreateRow(t *testing.T) {
	r := stoppedResumeRunner(t)
	r.options.ResumeScanUUID = "missing-resume"
	ctx := context.Background()
	before, err := r.repository.DB().NewSelect().Model((*database.Scan)(nil)).Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.initializeNativeScan(ctx)
	var re *ResumeError
	if !errors.As(err, &re) || re.Code() != apicontract.CodeScanNotFound {
		t.Fatalf("missing resume = %v, want scan_not_found", err)
	}
	after, err := r.repository.DB().NewSelect().Model((*database.Scan)(nil)).Count(ctx)
	if err != nil || before != after {
		t.Fatalf("missing resume inserted a row: before=%d after=%d err=%v", before, after, err)
	}
}

func TestNativeResumeRefusalPreservesOldStop(t *testing.T) {
	for _, refusal := range []struct {
		name    string
		code    apicontract.ErrorCode
		prepare func(*testing.T, *Runner)
	}{
		{"DifferentTargets", apicontract.CodeResumeMismatch, func(_ *testing.T, r *Runner) {
			r.options.Targets = []string{"https://different.example.test"}
		}},
		{"LiveRow", apicontract.CodeScanRunning, func(t *testing.T, r *Runner) {
			if _, err := r.repository.DB().NewUpdate().Model((*database.Scan)(nil)).
				Set("status = ?", "running").Where("uuid = ?", r.options.ResumeScanUUID).Exec(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.options.ResumeForce = true // --force must not steal a live run.
		}},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			r := stoppedResumeRunner(t)
			refusal.prepare(t, r)
			ctx := context.Background()
			before, err := r.repository.GetScanByUUID(ctx, r.options.ResumeScanUUID)
			if err != nil {
				t.Fatal(err)
			}
			oldStop, err := r.repository.ScanStopRequested(ctx, before.UUID)
			if err != nil || oldStop == nil {
				t.Fatalf("fixture STOP = %+v, %v", oldStop, err)
			}
			_, err = r.initializeNativeScan(ctx)
			var re *ResumeError
			if !errors.As(err, &re) || re.Code() != refusal.code {
				t.Fatalf("refused resume = %v, want %s", err, refusal.code)
			}
			after, err := r.repository.GetScanByUUID(ctx, before.UUID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("refused resume changed row: before=%+v after=%+v err=%v", before, after, err)
			}
			stop, err := r.repository.ScanStopRequested(ctx, before.UUID)
			if err != nil || !reflect.DeepEqual(oldStop, stop) {
				t.Fatalf("refused resume changed STOP: %+v, %v", stop, err)
			}
		})
	}
}
