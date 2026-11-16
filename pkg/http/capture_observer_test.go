package http

import (
	"bytes"
	"context"
	"errors"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

const observerTestNonce = "knownplantingnonce12345678"

type testPlantingObserver struct {
	mu            sync.Mutex
	receipts      []*evidence.Exchange
	calls         int
	panicSelector bool
	panicSink     bool
	failSink      bool
	mutate        bool
}

func (o *testPlantingObserver) WantsPlantingReceipt(input, raw []byte, target string) bool {
	if o.panicSelector {
		panic("selector failed")
	}
	return bytes.Contains(input, []byte(observerTestNonce)) || bytes.Contains(raw, []byte(observerTestNonce)) || strings.Contains(target, observerTestNonce)
}
func (o *testPlantingObserver) ObservePlantingReceipt(x *evidence.Exchange) error {
	if o.panicSink {
		panic("observer failed")
	}
	if o.failSink {
		return errors.New("receipt store unavailable")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	// Intent can preselect an execution, but only emitted bytes establish its
	// planting nonce. A redirect that drops it leaves planting unavailable.
	if bytes.Contains(x.Request, []byte(observerTestNonce)) {
		o.receipts = append(o.receipts, x.Clone())
	}
	if o.mutate {
		x.Request[0] = 'X'
		x.Response[0] = 'X'
	}
	return nil
}

func TestPlantingObserverSelectiveScopedOwnedAndCacheNeutral(t *testing.T) {
	var sends atomic.Int64
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		sends.Add(1)
		_, _ = w.Write([]byte("actual answer\x00\xff"))
	}))
	defer srv.Close()
	r := newTestRequester(t)
	t.Cleanup(r.CloseIdleConnections)
	r.clusterer = NewRequestClustererWithSize(16)
	observer := &testPlantingObserver{mutate: true}
	view := r.WithPlantingReceiptObserver(observer).WithContext(context.Background())
	credentials, err := view.WithAdditionalHeaders([]string{"Authorization: Bearer actual"})
	require.NoError(t, err)
	require.Same(t, view.plantingObserver, credentials.plantingObserver)
	for i := 0; i < 2; i++ {
		chain, _, err := view.Execute(makeTestRR(t, srv.URL+"/?nonce="+observerTestNonce), Options{})
		require.NoError(t, err)
		// The sink's mutation cannot rewrite the returned chain or its capture.
		x := CaptureEvidence(chain)
		require.True(t, bytes.HasPrefix(x.Request, []byte("GET ")))
		require.True(t, bytes.HasPrefix(x.Response, []byte("HTTP/")))
		chain.Close()
	}
	require.EqualValues(t, 1, sends.Load(), "observation must not disable clustering or add probes")
	require.Len(t, observer.receipts, 1, "cached observation must not create a planting execution")
	require.Equal(t, evidence.ProvenanceCaptured, observer.receipts[0].Provenance)
	require.NoError(t, observer.receipts[0].Validate())
	original := bytes.Clone(observer.receipts[0].Response)
	// Unselected ordinary traffic is never copied/delivered to the observer.
	chain, _, err := view.Execute(makeTestRR(t, srv.URL+"/ordinary"), Options{NoClustering: true})
	require.NoError(t, err)
	chain.Close()
	require.Equal(t, 1, observer.calls)
	// A different scan view cannot retarget the first view or the base requester.
	otherObserver := &testPlantingObserver{}
	other := r.WithPlantingReceiptObserver(otherObserver)
	chain, _, err = other.Execute(makeTestRR(t, srv.URL+"/other?nonce="+observerTestNonce), Options{NoClustering: true})
	require.NoError(t, err)
	chain.Close()
	require.Len(t, otherObserver.receipts, 1)
	require.Len(t, observer.receipts, 1)
	require.Nil(t, r.plantingObserver)
	require.Equal(t, original, observer.receipts[0].Response)
}

func TestPlantingObserverRedirectNeverCombinesEarlierRequestAndFinalAnswer(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/start" {
			stdhttp.Redirect(w, r, "/final", 302)
			return
		}
		_, _ = w.Write([]byte("final answer"))
	}))
	defer srv.Close()
	r := newTestRequester(t)
	t.Cleanup(r.CloseIdleConnections)
	observer := &testPlantingObserver{}
	view := r.WithPlantingReceiptObserver(observer)
	chain, _, err := view.Execute(makeTestRR(t, srv.URL+"/start?nonce="+observerTestNonce), Options{NoClustering: true})
	require.NoError(t, err)
	x := CaptureEvidence(chain)
	chain.Close()
	require.Equal(t, srv.URL+"/final", x.URL)
	requestLine, _, _ := bytes.Cut(x.Request, []byte("\r\n"))
	require.Equal(t, "GET /final HTTP/1.1", string(requestLine))
	// Referer legitimately includes the initial nonce. Do not scrub genuine
	// bytes to satisfy a test; it is incidental context, not the planting slot.
	require.Contains(t, string(x.Request), "Referer: "+srv.URL+"/start?nonce="+observerTestNonce)
	require.Len(t, observer.receipts, 0, "final answer cannot prove the earlier planting")
	require.Zero(t, observer.calls, "followed redirect must fail closed before sink handoff")
}

func TestPlantingObserverRejectsRawIntentWithoutCapturedEmittedRequest(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { _, _ = w.Write([]byte("answer")) }))
	defer srv.Close()
	r := newTestRequester(t)
	t.Cleanup(r.CloseIdleConnections)
	observer := &testPlantingObserver{}
	view := r.WithPlantingReceiptObserver(observer)
	rr := makeTestRR(t, srv.URL+"/?nonce="+observerTestNonce)
	chain, _, err := view.Execute(rr, Options{RawRequest: true, NoRedirects: true, NoClustering: true})
	require.NoError(t, err)
	chain.Close()
	require.Empty(t, observer.receipts)
	require.Zero(t, observer.calls)
	chain, _, err = view.Execute(rr, Options{RawBytes: rr.Request().Raw(), NoRedirects: true})
	require.NoError(t, err)
	chain.Close()
	require.Len(t, observer.receipts, 1)
	require.Equal(t, rr.Request().Raw(), observer.receipts[0].Request)
	require.Equal(t, srv.URL, observer.receipts[0].Service)
}

func TestPlantingObserverFailuresDoNotChangeTransportOutcome(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { _, _ = w.Write([]byte("answer")) }))
	defer srv.Close()
	r := newTestRequester(t)
	t.Cleanup(r.CloseIdleConnections)
	for _, observer := range []*testPlantingObserver{{panicSelector: true}, {panicSink: true}, {failSink: true}} {
		view := r.WithPlantingReceiptObserver(observer)
		chain, _, err := view.Execute(makeTestRR(t, srv.URL+"/?nonce="+observerTestNonce), Options{NoClustering: true})
		require.NoError(t, err)
		require.Contains(t, string(chain.BodyBytes()), "answer")
		chain.Close()
	}
}
