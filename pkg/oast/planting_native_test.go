package oast

import (
	"context"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/active/oast_probe"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// The real native OAST producer closes every chain and returns nil findings.
// Executor setup must still hand actual sender receipts to OAST without any
// changes to the producer, extra requests, or a synchronous result to inspect.
func TestNativeSilentOASTProbeRegistersActualPlanting(t *testing.T) {
	observed := make(chan string, 32)
	var sends atomic.Int64
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		sends.Add(1)
		if value := r.Header.Get("Referer"); value != "" {
			observed <- value
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(202)
		_, _ = w.Write([]byte("actual planted exchange\x00\xff"))
	}))
	defer srv.Close()
	repo := newOASTTestRepo(t)
	s := newFixedService(t, repo, "https://{nonce}.cb.example", "native-project", "native-scan")
	t.Cleanup(s.Close)
	requester := modtest.Requester(t)
	t.Cleanup(requester.CloseIdleConnections)
	rr := modtest.Request(t, srv.URL+"/plant")
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\noriginal crawl response")))
	var synchronous atomic.Int64
	m := oast_probe.New()
	executor := core.NewExecutor(core.ExecutorConfig{
		Workers: 1, HTTPRequester: requester, OASTProvider: s, OASTService: s,
		SkipBaseline: true, KeepBlocked: true, DisableFeedback: true,
		TechFilterDisabled: true, OnResult: func(*output.ResultEvent) { synchronous.Add(1) },
	}, source.NewSingleSource(rr, []string{m.ID()}), []modules.ActiveModule{m}, nil)
	if _, err := executor.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if synchronous.Load() != 0 {
		t.Fatal("silent planting unexpectedly produced synchronous findings")
	}
	var callback string
	select {
	case callback = <-observed:
	default:
		t.Fatal("native OAST header probe did not send")
	}
	nonce := s.NonceForCallback(callback)
	planting := s.plantingReceipt(nonce)
	if planting == nil || !strings.Contains(string(planting.Request), "Referer: "+callback) || !strings.Contains(string(planting.Response), "actual planted exchange") || strings.Contains(string(planting.Response), "original crawl response") {
		t.Fatalf("silent send lost or fabricated planting evidence: %+v", planting)
	}
	before := sends.Load()
	var emitted *output.ResultEvent
	s.emitResult = func(r *output.ResultEvent) { emitted = r }
	s.handleInteraction(&server.Interaction{Protocol: "http", UniqueID: nonce, RawRequest: "GET / HTTP/1.1\r\nHost: " + strings.TrimPrefix(callback, "http://") + "\r\n\r\n", RawResponse: "HTTP/1.1 204 No Content\r\n\r\n", Timestamp: time.Unix(30, 0).UTC()})
	if emitted == nil || emitted.EvidenceStatus != "selected" || primaryPlanting(t, emitted.Evidence).ID != planting.ID {
		t.Fatalf("native callback did not resolve exact silent sender receipt: %+v", emitted)
	}
	if sends.Load() != before {
		t.Fatal("callback/evidence collection added a target request")
	}
}
