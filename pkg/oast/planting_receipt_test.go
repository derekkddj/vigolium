package oast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
)

func TestPlantingObserverRequiresDeclaredSlotNotIncidentalReferer(t *testing.T) {
	for _, slot := range []string{"url", "X-OAST", "body", "request-line"} {
		t.Run(slot, func(t *testing.T) {
			s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
			label := "parameter"
			if slot == "X-OAST" {
				label = "header injection"
			}
			cb := s.GenerateURLFor(oastclass.SSRF, "https://victim.example/plant", slot, label, "ssrf", "h")
			nonce := s.NonceForCallback(cb)
			payload := cb + "/"
			s.RecordPayload(cb, payload)
			incidental := []byte("GET /final?url=benign HTTP/1.1\r\nHost: victim.example\r\nReferer: " + payload + "\r\nX-OAST: benign\r\n\r\nbenign")
			x := evidence.NewExchange("https://victim.example", "https://victim.example/final", incidental, []byte("HTTP/1.1 200 OK\r\n\r\nfinal answer"), evidence.ProvenanceCaptured)
			if !s.WantsPlantingReceipt(incidental, nil, "") {
				t.Fatal("intent selector should see the known nonce")
			}
			if err := s.ObservePlantingReceipt(x); err != nil {
				t.Fatal(err)
			}
			if s.plantingReceipt(nonce) != nil {
				t.Fatal("incidental Referer became planting proof for another slot")
			}
			if err := s.RegisterPlantingReceipt(nonce, x); err == nil {
				t.Fatal("explicit registration accepted incidental Referer instead of the declared slot")
			}
			if !bytes.Equal(x.Request, incidental) {
				t.Fatal("rejecting incidental context scrubbed genuine emitted bytes")
			}
			var planted []byte
			switch slot {
			case "url":
				planted = []byte("GET /plant?url=" + url.QueryEscape(payload) + " HTTP/1.1\r\nHost: victim.example\r\n\r\n")
			case "X-OAST":
				planted = []byte("GET /plant HTTP/1.1\r\nHost: victim.example\r\nX-OAST: " + payload + "\r\n\r\n")
			case "body":
				planted = []byte("POST /plant HTTP/1.1\r\nHost: victim.example\r\n\r\nentity=" + payload)
			case "request-line":
				planted = []byte("GET " + payload + " HTTP/1.1\r\nHost: victim.example\r\n\r\n")
			}
			x = evidence.NewExchange("https://victim.example", "https://victim.example/plant", planted, []byte("HTTP/1.1 202 Accepted\r\n\r\nplanting answer"), evidence.ProvenanceCaptured)
			if err := s.ObservePlantingReceipt(x); err != nil {
				t.Fatal(err)
			}
			if got := s.plantingReceipt(nonce); got == nil || got.ID != x.ID || !bytes.Equal(got.Request, planted) {
				t.Fatalf("declared planting slot did not bind actual receipt: %+v", got)
			}
		})
	}
}

func TestPlantingObserverEncodedParameterRetainsOriginalBytes(t *testing.T) {
	for _, surface := range []string{"query", "form", "json"} {
		t.Run(surface, func(t *testing.T) {
			s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
			cb := s.GenerateURLFor(oastclass.SSRF, "https://victim.example/", "url", "parameter", "ssrf", "h")
			nonce := s.NonceForCallback(cb)
			payload := cb + "/?x=a b&literal=%2F&plus=+&text=\"\\\x01\r\nX-Test: one"
			s.RecordPayload(cb, payload)
			rawFor := func(name, value string) []byte {
				switch surface {
				case "query":
					return []byte("GET /?" + name + "=" + url.QueryEscape(value) + " HTTP/1.1\r\nHost: victim.example\r\n\r\n")
				case "form":
					body := name + "=" + url.QueryEscape(value)
					return []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: victim.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
				default:
					// Go's %q is not a JSON encoder (e.g. it can emit \x escapes).
					body, err := json.Marshal(map[string]string{name: value})
					if err != nil {
						t.Fatal(err)
					}
					return []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: victim.example\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
				}
			}
			// Decoding may correlate only the declared slot, not another field
			// carrying the same genuine encoded payload.
			other := rawFor("other", payload)
			wrongSlot := evidence.NewExchange("https://victim.example", "https://victim.example/", other, []byte("HTTP/1.1 200 OK\r\n\r\nwrong slot"), evidence.ProvenanceCaptured)
			if !s.WantsPlantingReceipt(other, nil, "") {
				t.Fatal("literal nonce next to an encoded separator was not selected")
			}
			if err := s.ObservePlantingReceipt(wrongSlot); err != nil {
				t.Fatal(err)
			}
			if s.plantingReceipt(nonce) != nil || !bytes.Equal(wrongSlot.Request, other) {
				t.Fatal("encoded payload in another slot established planting or changed captured bytes")
			}
			raw := rawFor("url", payload)
			x := evidence.NewExchange("https://victim.example", "https://victim.example/", raw, []byte("HTTP/1.1 200 OK\r\n\r\nanswer"), evidence.ProvenanceCaptured)
			if err := s.ObservePlantingReceipt(x); err != nil {
				t.Fatal(err)
			}
			if got := s.plantingReceipt(nonce); got == nil || !bytes.Equal(got.Request, raw) {
				t.Fatalf("encoded planting was lost or decoded evidence replaced original bytes: %+v", got)
			}
		})
	}
}

func TestPlantingObserverURLMetadataAndUnknownSlotsCannotEstablishSend(t *testing.T) {
	s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example/", "", "unknown slot", "xxe", "h")
	nonce := s.NonceForCallback(cb)
	x := plantingTestExchange(nonce)
	if err := s.ObservePlantingReceipt(x); err != nil {
		t.Fatal(err)
	}
	if s.plantingReceipt(nonce) != nil {
		t.Fatal("unknown planting slot must fail closed")
	}
	x = evidence.NewExchange("https://victim.example", "https://victim.example/?url="+cb, []byte("GET / HTTP/1.1\r\nHost: victim.example\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n"), evidence.ProvenanceCaptured)
	if err := s.RegisterPlantingReceipt(nonce, x); err == nil {
		t.Fatal("URL metadata alone established a nonce-bearing send")
	}
	for _, raw := range [][]byte{[]byte("prefix" + nonce), []byte(nonce + "suffix"), []byte("prefix" + nonce + "suffix")} {
		if s.WantsPlantingReceipt(raw, nil, "") {
			t.Fatal("a nonce substring inside another token selected planting")
		}
	}
	if containsNonceToken([]byte("anything"), "") {
		t.Fatal("empty nonce cannot correlate a receipt")
	}
}

func TestPlantingReceiptCacheEvictionPreservesNonceSeal(t *testing.T) {
	s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
	var firstNonce string
	var first *evidence.Exchange
	for i := 0; i <= plantingReceiptCacheSize; i++ {
		cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example/", "body", "xxe", "xxe", "h")
		nonce := s.NonceForCallback(cb)
		x := plantingTestExchange(nonce)
		if i == 0 {
			firstNonce, first = nonce, x.Clone()
		}
		if err := s.ObservePlantingReceipt(x); err != nil {
			t.Fatal(err)
		}
	}
	if s.plantingCache.Len() != plantingReceiptCacheSize || s.plantingReceipt(firstNonce) != nil {
		t.Fatal("receipt-body retention is not bounded")
	}
	if err := s.RegisterPlantingReceipt(firstNonce, plantingTestExchange(firstNonce)); err == nil {
		t.Fatal("cache eviction allowed nonce reuse by another execution")
	}
	if err := s.RegisterPlantingReceipt(firstNonce, first); err != nil {
		t.Fatalf("the same original receipt should remain idempotent: %v", err)
	}
}

func TestPlantingObserverOversizedAndContendedHandoffFailClosed(t *testing.T) {
	s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example/", "body", "xxe", "xxe", "h")
	nonce := s.NonceForCallback(cb)
	x := plantingTestExchange(nonce)
	for _, lock := range []string{"receipt", "context"} {
		if lock == "receipt" {
			s.plantingMu.Lock()
		} else {
			s.contextMu.Lock()
		}
		err := s.ObservePlantingReceipt(x)
		if lock == "receipt" {
			s.plantingMu.Unlock()
		} else {
			s.contextMu.Unlock()
		}
		if err == nil || s.plantingReceipt(nonce) != nil {
			t.Fatal("contended observer must return immediately without retaining proof")
		}
	}
	oversized := x.Clone()
	oversized.Response = bytes.Repeat([]byte("x"), maxBufferedPlantingBytes+1)
	oversized.ContentHash = oversized.Hash()
	if err := s.ObservePlantingReceipt(oversized); err == nil || s.plantingReceipt(nonce) != nil {
		t.Fatal("oversized observation exceeded bounded retention")
	}
	if err := s.RegisterPlantingReceipt(nonce, oversized); err == nil {
		t.Fatal("oversized explicit receipt without database exceeded bounded retention")
	}
	if err := s.ObservePlantingReceipt(x); err != nil {
		t.Fatalf("rejected handoffs must not seal the nonce: %v", err)
	}
}

func TestPersistedLiveCompositeNonceRecoversThroughIngest(t *testing.T) {
	repo := newOASTTestRepo(t)
	s := &Service{repo: repo, projectUUID: "p", scanUUID: "s"}
	// Interactsh combines its correlation ID and nonce in one DNS label;
	// unlike fixed templates, the owned identifier is longer than an xid.
	const nonce = "livesession1234567890nonce1234567890"
	pctx := PayloadContext{TargetURL: "https://victim.example/", ParameterName: "body", Class: oastclass.XXE, ModuleID: "xxe", CallbackURL: nonce + ".cb.example"}
	s.trackPayload(nonce, pctx)
	x := plantingTestExchange(nonce)
	if err := s.RegisterPlantingReceipt(nonce, x); err != nil {
		t.Fatal(err)
	}
	s.Close()
	in := server.Interaction{Protocol: "http", UniqueID: nonce, RawRequest: "GET / HTTP/1.1\r\nHost: " + pctx.CallbackURL + "\r\n\r\n", RawResponse: "HTTP/1.1 204 No Content\r\n\r\n", Timestamp: x.CapturedAt}
	res, err := Ingest(context.Background(), repo, "p", []Callback{{Interaction: in, Where: []string{pctx.CallbackURL}}})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("live nonce recovery failed: %+v %v", res, err)
	}
	f, err := repo.GetFindingByHash(context.Background(), res.Findings[0].FindingHash, "p")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.HydrateFindingEvidenceForExport(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if got := primaryPlanting(t, f.Evidence); got.ID != x.ID || !bytes.Equal(got.Response, x.Response) {
		t.Fatalf("live nonce adopted a different exchange: %+v", got)
	}
}

func TestAsyncDurableConflictInvalidatesNewReceipt(t *testing.T) {
	repo := newOASTTestRepo(t)
	s := newFixedService(t, repo, "https://{nonce}.cb.example", "p", "s")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example/", "body", "xxe", "xxe", "h")
	nonce := s.NonceForCallback(cb)
	original := plantingTestExchange(nonce)
	if err := s.RegisterPlantingReceipt(nonce, original); err != nil {
		t.Fatal(err)
	}
	// Simulate a collision/recovered context trying to authorize a second send:
	// the durable project+nonce binding must remain immutable even if a hot
	// context is mistakenly reminted and its body cache was purged.
	pctx, _ := s.trackerCache().Peek(nonce)
	pctx.plantingID, pctx.plantingHash = "", ""
	s.trackPayload(nonce, pctx)
	s.plantingCache.Purge()
	other := plantingTestExchange(nonce)
	if err := s.ObservePlantingReceipt(other); err != nil {
		t.Fatal(err)
	}
	s.Flush()
	if s.plantingReceipt(nonce) != nil {
		t.Fatal("conflicting durable and in-memory bindings continued exposing proof")
	}
	s.Close()
}

func TestDurablePlantingEncodedQueryFormAndExplicitHeader(t *testing.T) {
	for _, surface := range []string{"query", "form", "header"} {
		t.Run(surface, func(t *testing.T) {
			repo := newOASTTestRepo(t)
			s := newFixedService(t, repo, "https://cb.example/{nonce}", "p", "s")
			t.Cleanup(s.Close)
			param, label := "url", "parameter"
			if surface == "header" {
				param, label = "X-OAST", "explicit header injection"
			}
			cb := s.GenerateURLFor(oastclass.SSRF, "https://victim.example/", param, label, "ssrf", "h")
			nonce := s.NonceForCallback(cb)
			payload := cb + "/"
			s.RecordPayload(cb, payload)
			var raw []byte
			switch surface {
			case "query":
				raw = []byte("GET /?url=" + url.QueryEscape(payload) + " HTTP/1.1\r\nHost: victim.example\r\n\r\n")
			case "form":
				body := "url=" + url.QueryEscape(payload)
				raw = []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: victim.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			case "header":
				raw = []byte("GET / HTTP/1.1\r\nHost: victim.example\r\nX-OAST: " + payload + "\r\n\r\n")
			}
			x := evidence.NewExchange("https://victim.example", "https://victim.example/", raw, []byte("HTTP/1.1 202 Accepted\r\n\r\n\x00\xff"), evidence.ProvenanceCaptured)
			if err := s.ObservePlantingReceipt(x); err != nil {
				t.Fatal(err)
			}
			s.Close()
			late := &Service{repo: repo, projectUUID: "p", scanUUID: "s"}
			got := late.plantingReceipt(nonce)
			if got == nil || got.ID != x.ID || !bytes.Equal(got.Request, raw) || !bytes.Equal(got.Response, x.Response) || !got.CapturedAt.Equal(x.CapturedAt) {
				t.Fatalf("durable encoded/header planting was not retained exactly: %+v", got)
			}
			pctx, ok := late.payloadContextForNonce(nonce)
			if !ok || pctx.InjectionType != label || pctx.plantingOwned {
				t.Fatalf("explicit slot context lost or authorized another send: %+v", pctx)
			}
		})
	}
}

func TestRestoredPayloadContextCannotAuthorizeNewPlanting(t *testing.T) {
	s := newFixedService(t, nil, "https://{nonce}.cb.example", "p", "s")
	cb := s.GenerateURLFor(oastclass.XXE, "https://victim.example/", "body", "xxe", "xxe", "h")
	nonce := s.NonceForCallback(cb)
	pctx, _ := s.trackerCache().Peek(nonce)
	pctx.plantingOwned = false // persistence recovery provides attribution only
	s.trackerCache().Add(nonce, pctx)
	x := plantingTestExchange(nonce)
	if s.WantsPlantingReceipt(x.Request, nil, "") {
		t.Fatal("restored attribution authorized a new sender handoff")
	}
	if err := s.RegisterPlantingReceipt(nonce, x); err == nil {
		t.Fatal("restored nonce silently adopted a new execution")
	}
}
