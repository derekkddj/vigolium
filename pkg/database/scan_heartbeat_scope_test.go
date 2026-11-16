package database

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestScanHeartbeatCapturedProjectRefusesForeign(t *testing.T) {
	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	if err := repo.CreateScan(ctx, &Scan{UUID: "heartbeat-scan", ProjectUUID: "project-a", Status: "running", PID: 123, TotalRequests: 7}); err != nil {
		t.Fatal(err)
	}
	before, err := repo.GetScanByUUID(ctx, "heartbeat-scan")
	if err != nil {
		t.Fatal(err)
	}
	requests := int64(99)
	updated, _, err := repo.UpdateScanHeartbeat(ctx, before.UUID, ScanHeartbeat{ProjectUUID: "project-b", At: time.Now(), PID: 999, Phase: "dynamic-assessment", RequestsSent: &requests})
	if err != nil || updated {
		t.Fatalf("foreign heartbeat updated=%v err=%v", updated, err)
	}
	after, err := repo.GetScanByUUID(ctx, before.UUID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("foreign heartbeat changed row: after=%+v err=%v", after, err)
	}
	updated, _, err = repo.UpdateScanHeartbeat(ctx, before.UUID, ScanHeartbeat{ProjectUUID: "project-a", At: time.Now(), RequestsSent: &requests})
	if err != nil || !updated {
		t.Fatalf("same-project heartbeat updated=%v err=%v", updated, err)
	}
	after, err = repo.GetScanByUUID(ctx, before.UUID)
	if err != nil || after.TotalRequests != requests || after.HeartbeatAt == nil || after.ProjectUUID != before.ProjectUUID {
		t.Fatalf("same-project heartbeat row=%+v err=%v", after, err)
	}
}
