package oast

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

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
