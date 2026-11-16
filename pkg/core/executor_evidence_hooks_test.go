package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/work"
)

type changingRequestHook struct{}

func (changingRequestHook) RunPreHooks(rr *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	raw, err := httpmsg.AddOrReplaceHeader(rr.Request().Raw(), "X-Probe", "changed")
	if err != nil {
		return nil, err
	}
	return httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(rr.Service(), raw), rr.Response()), nil
}
func (changingRequestHook) RunPostHooks(r *output.ResultEvent) (*output.ResultEvent, error) {
	return r, nil
}

func TestEvidenceRequestChangingHookRunsBeforeFetch(t *testing.T) {
	sentHeader := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentHeader <- r.Header.Get("X-Probe")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("fresh answer"))
	}))
	defer server.Close()
	rr, err := httpmsg.GetRawRequestFromURL(server.URL)
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nold answer")))
	var captured *evidence.Exchange
	e, _ := newTestExecutor(ExecutorConfig{KeepBlocked: true, OnResponse: func(_ *work.WorkItem, req *httpmsg.HttpRequestResponse) {
		captured = req.Evidence()
		require.Equal(t, http.StatusForbidden, req.Response().StatusCode())
		require.Contains(t, string(req.Response().Raw()), "fresh answer")
	}}, nil)
	e.hooks = changingRequestHook{}
	e.httpClient = modtest.Requester(t)
	require.False(t, e.processItem(context.Background(), work.NewWithModules(rr, nil)))
	require.NotNil(t, captured)
	require.Equal(t, "changed", <-sentHeader)
	require.Contains(t, string(captured.Request), "X-Probe: changed")
	require.Contains(t, string(captured.Response), "fresh answer")
	require.NotContains(t, string(captured.Response), "old answer")
}
