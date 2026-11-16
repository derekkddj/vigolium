package oast

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

func TestOASTServiceOwnsProjectAndScanIdentityForDelayedCallbacks(t *testing.T) {
	ctx := context.Background()
	repo := newOASTTestRepo(t)
	projectBytes := []byte("project-a")
	scanBytes := []byte("scan-a")
	project := unsafe.String(unsafe.SliceData(projectBytes), len(projectBytes))
	scan := unsafe.String(unsafe.SliceData(scanBytes), len(scanBytes))

	svc, err := New(&config.OASTConfig{Enabled: true, OastURL: "https://callbacks.example/{nonce}"}, nil, repo, scan, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	copy(projectBytes, "project-b")
	copy(scanBytes, "scan-b")

	// The poller callback can run after the request that supplied these strings
	// has released/reused its backing storage.
	svc.recordInteraction(&server.Interaction{UniqueID: "callback-1", Protocol: "dns", Timestamp: time.Unix(1, 0)}, PayloadContext{})

	rows, err := repo.GetOASTInteractionsByScan(ctx, "scan-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ProjectUUID != "project-a" || rows[0].ScanUUID != "scan-a" {
		t.Fatalf("delayed callback lost admitted identity: %+v", rows)
	}
	foreign, err := repo.GetOASTInteractionsByScan(ctx, "scan-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) != 0 {
		t.Fatalf("callback was written into reused identity: %+v", foreign)
	}
}

func TestIngestReceiptIdentityRetainsResponseAndNanoseconds(t *testing.T) {
	repo, ctx := newOASTTestRepo(t), context.Background()
	s := newFixedService(t, repo, "https://{nonce}.cb.example", "p", "s")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example/", "body", "xxe", "xxe", "baseline")
	nonce := s.NonceForCallback(cb)
	s.Close()
	at := time.Date(2026, 11, 3, 1, 2, 3, 123456789, time.UTC)
	original := Callback{Interaction: server.Interaction{UniqueID: nonce, Protocol: "http",
		RawRequest:  "GET / HTTP/1.1\r\nHost: " + nonce + ".cb.example\r\n\r\n",
		RawResponse: "HTTP/1.1 204 No Content\r\n\r\n", Timestamp: at}, Where: []string{cb}}
	first, err := Ingest(ctx, repo, "p", []Callback{original})
	if err != nil || len(first.Findings) != 1 {
		t.Fatalf("first callback: %+v %v", first, err)
	}
	again, err := Ingest(ctx, repo, "p", []Callback{original})
	if err != nil || again.Duplicates != 1 || len(again.Findings) != 0 {
		t.Fatalf("nanosecond callback was not recognized as an exact repeat: %+v %v", again, err)
	}
	rows, err := repo.GetOASTInteractionsByScan(ctx, "s")
	if err != nil || len(rows) != 1 || !rows[0].InteractedAt.Equal(at) {
		t.Fatalf("collector timestamp lost nanoseconds: %+v %v", rows, err)
	}
	for _, changed := range []Callback{
		{Interaction: server.Interaction{UniqueID: nonce, Protocol: "http", RawRequest: original.Interaction.RawRequest,
			RawResponse: "HTTP/1.1 200 OK\r\n\r\nchanged", Timestamp: at}, Where: []string{cb}},
		{Interaction: server.Interaction{UniqueID: nonce, Protocol: "http", RawRequest: original.Interaction.RawRequest,
			RawResponse: original.Interaction.RawResponse, Timestamp: at.Add(time.Nanosecond)}, Where: []string{cb}},
	} {
		res, err := Ingest(ctx, repo, "p", []Callback{changed})
		if err != nil || res.Duplicates != 0 {
			t.Fatalf("different response/capture instant was treated as a repeat: %+v %v", res, err)
		}
	}
	rows, err = repo.GetOASTInteractionsByScan(ctx, "s")
	if err != nil || len(rows) != 3 {
		t.Fatalf("independent collector observations disappeared: %+v %v", rows, err)
	}
}
