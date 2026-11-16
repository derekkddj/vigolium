package runner

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
)

type nativeIsolationQueryHook struct {
	before func(context.Context, *bun.QueryEvent)
}

func (h nativeIsolationQueryHook) BeforeQuery(ctx context.Context, ev *bun.QueryEvent) context.Context {
	h.before(ctx, ev)
	return ctx
}

func (nativeIsolationQueryHook) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestLaunchReceiptSkipsRejectedIdentity(t *testing.T) {
	for _, cause := range []error{database.ErrScanProjectMismatch, sql.ErrNoRows, errors.New("selected store unavailable")} {
		t.Run(cause.Error(), func(t *testing.T) {
			repo := newBannerRepo(t)
			if err := repo.CreateScan(context.Background(), &database.Scan{UUID: "rejected", ProjectUUID: "project-a", Status: "completed", TotalFindings: 99}); err != nil {
				t.Fatal(err)
			}
			var queries atomic.Int64
			repo.DB().AddQueryHook(nativeIsolationQueryHook{before: func(context.Context, *bun.QueryEvent) { queries.Add(1) }})
			scope := nativeScanScope{repo: repo, scanUUID: "rejected", projectUUID: "project-b"}
			res := &LaunchResult{ScanUUID: scope.scanUUID, DurationMs: 123}
			before := *res
			runErr := scope.identityError(cause)
			if err := reconcileLaunchResult(context.Background(), scope, res, runErr); err != runErr || queries.Load() != 0 || *res != before {
				t.Fatalf("rejected receipt read/reconciled: result=%+v err=%v queries=%d", res, err, queries.Load())
			}
		})
	}
}

func TestLaunchReceiptRefusesReassignedProject(t *testing.T) {
	ctx := context.Background()
	repo := newBannerRepo(t)
	if err := repo.CreateScan(ctx, &database.Scan{UUID: "reassigned", ProjectUUID: "project-b", Status: "completed", TotalFindings: 99, TotalRequests: 123, CriticalCount: 77}); err != nil {
		t.Fatal(err)
	}
	for _, runErr := range []error{nil, errors.New("original scan failure")} {
		scope := nativeScanScope{repo: repo, scanUUID: "reassigned", projectUUID: "project-a"}
		res := &LaunchResult{ScanUUID: scope.scanUUID, DurationMs: 123}
		before := *res
		err := reconcileLaunchResult(ctx, scope, res, runErr)
		var identity *NativeScanIdentityError
		if !errors.Is(err, database.ErrScanProjectMismatch) || !errors.As(err, &identity) || (runErr != nil && !errors.Is(err, runErr)) || *res != before {
			t.Fatalf("foreign receipt copied metadata/lost cause: result=%+v err=%v", res, err)
		}
	}
}

func TestLaunchReceiptSameProjectOnCancelledContext(t *testing.T) {
	for _, project := range []string{"project-a", database.DefaultProjectUUID} {
		t.Run(project, func(t *testing.T) {
			repo := newBannerRepo(t)
			row := &database.Scan{UUID: "owned", ProjectUUID: project, Status: "completed", TotalFindings: 7, TotalRequests: 123, CriticalCount: 1, HighCount: 2, MediumCount: 3, LowCount: 4, InfoCount: 5, SuspectCount: 6}
			if err := repo.CreateScan(context.Background(), row); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			res := &LaunchResult{ScanUUID: row.UUID, DurationMs: 999}
			scope := nativeScanScope{repo: repo, scanUUID: row.UUID, projectUUID: project}
			if err := reconcileLaunchResult(ctx, scope, res, context.Canceled); err != context.Canceled {
				t.Fatalf("receipt lost cancellation: %v", err)
			}
			want := &LaunchResult{ScanUUID: row.UUID, DurationMs: 999, Status: row.Status, FindingCount: 7, TotalRequests: 123, Critical: 1, High: 2, Medium: 3, Low: 4, Info: 5, Suspect: 6}
			if !reflect.DeepEqual(res, want) {
				t.Fatalf("same-project receipt=%+v want=%+v", res, want)
			}
		})
	}
}
