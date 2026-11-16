package core

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
)

type baselineFailureReceived struct {
	raw []byte
	err error
}

// Read at the loopback peer so the test compares the receipt with emitted bytes,
// including transport-added headers, rather than with the submitted request.
func baselineFailurePeer(t *testing.T, response string, hold bool) (string, <-chan baselineFailureReceived, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	seen := make(chan baselineFailureReceived, 8)
	stop := make(chan struct{})
	var sends atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			sends.Add(1)
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var raw bytes.Buffer
				req, readErr := stdhttp.ReadRequest(bufio.NewReader(io.TeeReader(conn, &raw)))
				if readErr == nil {
					_, readErr = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
				}
				seen <- baselineFailureReceived{raw: bytes.Clone(raw.Bytes()), err: readErr}
				if hold {
					<-stop
					return
				}
				if response != "" {
					_, _ = io.WriteString(conn, response)
				}
			}(conn)
		}
	}()
	t.Cleanup(func() {
		close(stop)
		_ = ln.Close()
		wg.Wait()
	})
	return "http://" + ln.Addr().String(), seen, &sends
}

func baselineFailureRequester(t *testing.T) *http.Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Retries = 0
	opts.Timeout = 5 * time.Second
	opts.Headers = []string{"Authorization: Bearer actually-sent", "X-Sent: transport"}
	require.NoError(t, network.Init(opts))
	r, err := http.NewRequester(opts, &services.Services{Options: opts})
	require.NoError(t, err)
	t.Cleanup(r.CloseIdleConnections)
	return r
}

func baselineFailureInput(t *testing.T, target string) *httpmsg.HttpRequestResponse {
	t.Helper()
	payload := []byte{'s', 0, 0xff, 't'}
	rr, err := httpmsg.GetRawRequestFromURLWithMethod(target, stdhttp.MethodPost, map[string]string{"X-Input": "unchanged"}, payload)
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 201 Created\r\nX-Old: yes\r\n\r\nold response")))
	return rr.WithEvidence(evidence.NewExchange(evidenceService(rr), rr.Target(), rr.Request().Raw(), rr.Response().Raw(), evidence.ProvenanceCaptured))
}

func requireBaselineFailureInputUnchanged(t *testing.T, before, after *httpmsg.HttpRequestResponse) {
	t.Helper()
	require.Equal(t, before.Request().Raw(), after.Request().Raw())
	require.Equal(t, before.Response().Raw(), after.Response().Raw())
	require.Equal(t, before.Evidence(), after.Evidence())
	require.Empty(t, after.Request().Header("Authorization"))
	require.Empty(t, after.Request().Header("X-Sent"))
}

func receiveBaselineFailureRequest(t *testing.T, seen <-chan baselineFailureReceived) []byte {
	t.Helper()
	select {
	case got := <-seen:
		require.NoError(t, got.err)
		return got.raw
	case <-time.After(5 * time.Second):
		t.Fatal("loopback peer did not receive the baseline request")
		return nil
	}
}

func TestFetchBaselineFailureRestoresActualReceiptWithoutScanResponse(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		state    evidence.State
	}{
		{name: "connection-drop", state: evidence.StateMissing},
		{name: "partial-body", response: "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nX-Actual: yes\r\n\r\npartial\x00\xff", state: evidence.StateTruncated},
	} {
		t.Run(test.name, func(t *testing.T) {
			url, seen, sends := baselineFailurePeer(t, test.response, false)
			original := baselineFailureInput(t, url+"/attempt")
			before := original.Clone()
			e := &Executor{httpClient: baselineFailureRequester(t)}
			failed, ok := e.fetchBaseline(context.Background(), original)
			require.False(t, ok)
			require.Nil(t, failed.resp, "a partial answer is not a successful scan baseline")
			require.Nil(t, failed.pooledBuf, "Execute errors own no pooled buffers")
			require.Nil(t, failed.hops)
			require.Equal(t, DropFetchError, failed.drop)
			var captureErr *http.RequestCaptureError
			require.ErrorAs(t, failed.dropErr, &captureErr)
			require.NotNil(t, failed.req)
			x := failed.req.Evidence()
			require.NotNil(t, x)
			require.NoError(t, x.Validate())
			require.Equal(t, http.CaptureFailureEvidence(failed.dropErr), x)
			require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
			require.Equal(t, evidence.StateComplete, x.RequestState)
			require.Equal(t, test.state, x.ResponseState)
			require.NotEqual(t, before.Evidence().ID, x.ID)
			require.Equal(t, receiveBaselineFailureRequest(t, seen), x.Request)
			require.Equal(t, x.Request, failed.req.Request().Raw())
			require.Equal(t, "Bearer actually-sent", failed.req.Request().Header("Authorization"))
			require.Equal(t, "transport", failed.req.Request().Header("X-Sent"))
			require.Equal(t, []byte{'s', 0, 0xff, 't'}, failed.req.Request().Body())
			if test.response == "" {
				require.Equal(t, http.TransportErrReset, http.ClassifyTransportError(failed.dropErr))
				require.Nil(t, failed.req.Response())
				require.Empty(t, x.Response, "no status-zero response or old input response")
			} else {
				require.ErrorIs(t, failed.dropErr, io.ErrUnexpectedEOF)
				require.Equal(t, x.Response, failed.req.Response().Raw())
				require.Equal(t, "20", failed.req.Response().Header("Content-Length"))
				require.Equal(t, []byte("partial\x00\xff"), failed.req.Response().Body())
			}
			require.Len(t, e.BaselineFailures(), 1)
			require.Equal(t, http.ClassifyTransportError(failed.dropErr), e.BaselineFailures()[0].Class)
			require.Zero(t, e.Responded())
			require.EqualValues(t, 1, e.httpClient.RequestsSent())
			require.EqualValues(t, 1, sends.Load(), "receipt restoration must not send an extra request")
			requireBaselineFailureInputUnchanged(t, before, original)
			x.Request[0] = '!'
			require.NoError(t, failed.req.Evidence().Validate(), "returned receipt copies cannot rewrite owned evidence")
			require.NoError(t, http.CaptureFailureEvidence(failed.dropErr).Validate())
		})
	}
}

func TestFetchBaselineCancellationReturnsSentReceiptWithoutTargetFailure(t *testing.T) {
	url, seen, sends := baselineFailurePeer(t, "", true)
	original := baselineFailureInput(t, url+"/attempt")
	before := original.Clone()
	e := &Executor{httpClient: baselineFailureRequester(t)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		fetch baselineFetch
		ok    bool
	}
	done := make(chan outcome, 1)
	go func() {
		fetch, ok := e.fetchBaseline(ctx, original)
		done <- outcome{fetch: fetch, ok: ok}
	}()
	raw := receiveBaselineFailureRequest(t, seen)
	cancel()
	select {
	case got := <-done:
		require.False(t, got.ok)
		require.Nil(t, got.fetch.resp)
		require.Nil(t, got.fetch.pooledBuf)
		require.Nil(t, got.fetch.hops)
		require.Empty(t, got.fetch.drop)
		require.NoError(t, got.fetch.dropErr, "cancellation remains unclassified as a target drop")
		require.NotNil(t, got.fetch.req)
		x := got.fetch.req.Evidence()
		require.NotNil(t, x)
		require.NoError(t, x.Validate())
		require.Equal(t, raw, x.Request)
		require.Equal(t, evidence.StateMissing, x.ResponseState)
		require.Empty(t, x.Response)
		require.Nil(t, got.fetch.req.Response())
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled baseline fetch did not return")
	}
	require.Empty(t, e.BaselineFailures())
	require.Empty(t, e.DropReasons())
	require.Zero(t, e.Responded())
	require.EqualValues(t, 1, e.httpClient.RequestsSent())
	require.EqualValues(t, 1, sends.Load())
	requireBaselineFailureInputUnchanged(t, before, original)
}

func TestFetchBaselineDialFailureDoesNotAdoptOldExchange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	url := "http://" + ln.Addr().String()
	require.NoError(t, ln.Close())
	original := baselineFailureInput(t, url+"/attempt")
	before := original.Clone()
	e := &Executor{httpClient: baselineFailureRequester(t)}
	failed, ok := e.fetchBaseline(context.Background(), original)
	require.False(t, ok)
	require.Equal(t, DropFetchError, failed.drop)
	require.Error(t, failed.dropErr)
	require.Nil(t, http.CaptureFailureEvidence(failed.dropErr), "a dial failure cannot certify request intent")
	require.Nil(t, failed.req, "the old response and receipt cannot stand in for a failed send")
	require.Nil(t, failed.resp)
	require.Nil(t, failed.pooledBuf)
	require.Equal(t, http.TransportErrRefused, http.ClassifyTransportError(failed.dropErr))
	require.EqualValues(t, 1, e.httpClient.RequestsSent())
	requireBaselineFailureInputUnchanged(t, before, original)
}

func TestOnUnansweredCaptureFailureReceiptDoesNotStoreFailedBaseline(t *testing.T) {
	for _, response := range []string{"", "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial\x00\xff"} {
		name := "connection-drop"
		if response != "" {
			name = "partial-body"
		}
		t.Run(name, func(t *testing.T) {
			url, seen, sends := baselineFailurePeer(t, response, false)
			original := baselineFailureInput(t, url+"/attempt")
			before := original.Clone()
			e, db := newRepoExecutor(t)
			e.httpClient = baselineFailureRequester(t)
			passive := &trackingPassiveModule{id: "must-not-scan-failed-baseline"}
			e.perRequestPassive = []modules.PassiveModule{passive}
			var unanswered, answered, stored, traffic, results int
			var receipt *evidence.Exchange
			var callbackErr error
			e.cfg.OnUnanswered = func(item *work.WorkItem, reason string, err error) {
				unanswered++
				require.Same(t, original, item.Request, "callback item retains caller intent, not a fabricated baseline")
				require.Equal(t, DropFetchError, reason)
				var captureErr *http.RequestCaptureError
				require.True(t, errors.As(err, &captureErr))
				callbackErr = err
				// The typed error is the diagnostic API; it yields an owned exact
				// receipt even though this item produced no complete HTTP record.
				receipt = http.CaptureFailureEvidence(err)
			}
			e.cfg.OnResponse = func(*work.WorkItem, *httpmsg.HttpRequestResponse) { answered++ }
			e.cfg.OnRecordStored = func(string, *httpmsg.HttpRequestResponse) { stored++ }
			e.cfg.OnTraffic = func(string, string, int, string) { traffic++ }
			e.cfg.OnResult = func(*output.ResultEvent) { results++ }
			require.False(t, e.processItem(context.Background(), work.NewWithModules(original, nil)))
			require.Equal(t, 1, unanswered)
			require.Zero(t, answered)
			require.Zero(t, stored)
			require.Zero(t, traffic)
			require.Zero(t, results)
			require.Zero(t, passive.called.Load(), "partial diagnostics must never reach baseline modules")
			require.NotNil(t, receipt)
			require.NoError(t, receipt.Validate())
			require.Equal(t, receiveBaselineFailureRequest(t, seen), receipt.Request)
			require.Equal(t, http.CaptureFailureEvidence(callbackErr), receipt)
			require.Equal(t, map[string]int64{DropFetchError: 1}, e.DropReasons())
			require.Len(t, e.BaselineFailures(), 1)
			require.Zero(t, e.Responded())
			require.Zero(t, countRecords(t, db), "failed and partial exchanges are diagnostics, not complete HTTP records")
			require.Empty(t, loadFindings(t, db), "do not invent a finding to persist a failed baseline")
			require.EqualValues(t, 1, e.httpClient.RequestsSent())
			require.EqualValues(t, 1, sends.Load())
			requireBaselineFailureInputUnchanged(t, before, original)
		})
	}
}
