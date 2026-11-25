package http

import (
	"bytes"
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

type slotFailureObserver struct {
	testPlantingObserver
	mutateReceipt bool
}

func (o *slotFailureObserver) ObservePlantingReceipt(x *evidence.Exchange) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	line, _, _ := bytes.Cut(x.Request, []byte("\r\n"))
	parts := strings.SplitN(string(line), " ", 3)
	if len(parts) == 3 {
		if target, err := url.ParseRequestURI(parts[1]); err == nil && target.Query().Get("nonce") == observerTestNonce {
			o.receipts = append(o.receipts, x.Clone())
		}
	}
	if o.mutateReceipt {
		if len(x.Request) > 0 {
			x.Request[0] = 'X'
		}
		if len(x.Response) > 0 {
			x.Response[0] = 'X'
		}
	}
	return nil
}

func TestPlantingFailureObserverReceivesActualSentFailuresWithoutChangingError(t *testing.T) {
	for _, responseFails := range []bool{false, true} {
		name := "request-only"
		if responseFails {
			name = "partial-body"
		}
		t.Run(name, func(t *testing.T) {
			r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
				completeNativeCaptureWrite(req, nil)
				if !responseFails {
					return nil, io.EOF
				}
				return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
					Header: make(stdhttp.Header), Body: &failingCaptureBody{}, ContentLength: -1}, nil
			}))
			r.clusterer = NewRequestClustererWithSize(16)
			observer := &slotFailureObserver{mutateReceipt: true}
			view := r.WithPlantingReceiptObserver(observer).WithContext(context.Background())
			for i := 0; i < 2; i++ {
				chain, elapsed, err := view.Execute(makeTestRR(t, "http://fixture.invalid/fail?nonce="+observerTestNonce), Options{})
				if responseFails {
					require.ErrorIs(t, err, errCaptureRead)
				} else {
					require.ErrorIs(t, err, io.EOF)
				}
				require.Nil(t, chain)
				require.Zero(t, elapsed)
				x := CaptureFailureEvidence(err)
				require.NotNil(t, x)
				require.NoError(t, x.Validate(), "sink mutation cannot change the error-owned receipt")
				require.True(t, bytes.HasPrefix(x.Request, []byte("GET ")))
				require.Equal(t, x, observer.receipts[i])
			}
			require.Equal(t, 2, observer.calls)
			require.Len(t, observer.receipts, 2, "each real failure is a new send, never a cache observation")
			require.NotEqual(t, observer.receipts[0].ID, observer.receipts[1].ID)
			require.EqualValues(t, 2, r.RequestsSent())
			chain, _, err := view.Execute(makeTestRR(t, "http://fixture.invalid/ordinary"), Options{NoClustering: true})
			require.Error(t, err)
			require.Nil(t, chain)
			require.Equal(t, 2, observer.calls, "ordinary failed traffic remains unselected")
			require.Nil(t, r.plantingObserver)
		})
	}
}

func TestPlantingFailureObserverRejectsUnsentUntracedAndIncidentalTokens(t *testing.T) {
	for _, responseFails := range []bool{false, true} {
		r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
			if !responseFails {
				return nil, io.EOF
			}
			return &stdhttp.Response{Request: req, StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
				Header: make(stdhttp.Header), Body: &failingCaptureBody{}, ContentLength: -1}, nil
		}))
		observer := &slotFailureObserver{}
		chain, _, err := r.WithPlantingReceiptObserver(observer).Execute(makeTestRR(t, "http://fixture.invalid/?nonce="+observerTestNonce), Options{NoClustering: true})
		require.Error(t, err)
		require.Nil(t, chain)
		require.Empty(t, observer.receipts)
		require.Zero(t, observer.calls)
	}
	// Intent preselects this execution, but the emitted nonce moved to an
	// incidental header, not the registered query slot. The sink rechecks it.
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		req.URL.RawQuery = ""
		completeNativeCaptureWrite(req, stdhttp.Header{"Referer": {"http://earlier.invalid/?nonce=" + observerTestNonce}})
		return nil, io.EOF
	}))
	observer := &slotFailureObserver{}
	chain, _, err := r.WithPlantingReceiptObserver(observer).Execute(makeTestRR(t, "http://fixture.invalid/?nonce="+observerTestNonce), Options{NoClustering: true})
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, chain)
	require.Equal(t, 1, observer.calls)
	require.Empty(t, observer.receipts, "a token outside the exact planting slot cannot prove planting")
}

func TestPlantingFailureObserverRedirectNeverUsesEarlierNonce(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
		if req.URL.Path == "/start" {
			stdhttp.Redirect(w, req, "/final", 302)
			return
		}
		conn, _, err := w.(stdhttp.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	r := newTestRequester(t)
	r.retries = 0
	t.Cleanup(r.CloseIdleConnections)
	observer := &slotFailureObserver{}
	chain, _, err := r.WithPlantingReceiptObserver(observer).Execute(makeTestRR(t, srv.URL+"/start?nonce="+observerTestNonce), Options{NoClustering: true})
	require.Error(t, err)
	require.Nil(t, chain)
	x := CaptureFailureEvidence(err)
	require.NotNil(t, x)
	require.Equal(t, srv.URL+"/final", x.URL)
	require.True(t, bytes.HasPrefix(x.Request, []byte("GET /final HTTP/1.1\r\n")))
	require.Contains(t, string(x.Request), "Referer: "+srv.URL+"/start?nonce="+observerTestNonce)
	require.Empty(t, x.Response)
	require.Zero(t, observer.calls, "redirect failure is excluded before handoff, as on success")
	require.Empty(t, observer.receipts)
}

func TestPlantingFailureObserverPanicsAndStorageFailuresPreserveOutcome(t *testing.T) {
	r := nativeCaptureFixtureRequester(t, captureTestTransport(func(req *stdhttp.Request) (*stdhttp.Response, error) {
		completeNativeCaptureWrite(req, nil)
		return nil, io.EOF
	}))
	for _, observer := range []*testPlantingObserver{{panicSelector: true}, {panicSink: true}, {failSink: true}} {
		chain, _, err := r.WithPlantingReceiptObserver(observer).Execute(makeTestRR(t, "http://fixture.invalid/?nonce="+observerTestNonce), Options{NoClustering: true})
		require.ErrorIs(t, err, io.EOF)
		require.Nil(t, chain)
		x := CaptureFailureEvidence(err)
		require.NotNil(t, x)
		require.NoError(t, x.Validate())
	}
}

func TestObservedResponseLazyCaptureOwnsActualFinalExchange(t *testing.T) {
	body := append(bytes.Repeat([]byte("database error detail\n"), 1024), 0, 0xff)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
		if req.URL.Path == "/start" {
			stdhttp.Redirect(w, req, "/final", 302)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Actual-Response", "retained")
		w.WriteHeader(500)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	r := newTestRequester(t)
	t.Cleanup(r.CloseIdleConnections)
	var receipt *evidence.Exchange
	var observations int
	r.SetResponseObserver(func(observation ObservedResponse) {
		observations++
		require.Equal(t, srv.URL+"/final", observation.URL)
		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		require.Equal(t, u.Hostname(), observation.Host)
		require.Equal(t, 500, observation.Status)
		require.Equal(t, body, observation.Body)
		require.NotNil(t, observation.CaptureEvidence)
		receipt = observation.CaptureEvidence()
		require.NotNil(t, receipt)
		another := observation.CaptureEvidence()
		another.Request[0], another.Response[0] = 'X', 'X'
		require.NoError(t, receipt.Validate(), "each lazy call owns independent bytes")
	})
	chain, _, err := r.Execute(makeTestRR(t, srv.URL+"/start"), Options{NoClustering: true})
	require.NoError(t, err)
	require.Equal(t, 1, observations)
	require.Equal(t, CaptureEvidence(chain), receipt)
	chain.Close()
	require.NoError(t, receipt.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, receipt.Provenance)
	require.Equal(t, evidence.StateComplete, receipt.RequestState)
	require.Equal(t, evidence.StateComplete, receipt.ResponseState)
	require.True(t, bytes.HasPrefix(receipt.Request, []byte("GET /final HTTP/1.1\r\n")))
	require.True(t, bytes.HasSuffix(receipt.Response, body), "full proof bytes are separate from any 8KiB preview")
	require.Contains(t, string(receipt.Response), "X-Actual-Response: retained\r\n")
}
