package jsext

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestHTTPAuthTestReturnsSelectableResponsesAndPreparesOnVMThread(t *testing.T) {
	const sessionCount = 8
	var prepared atomic.Int32
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if auth := r.Header.Get("Authorization"); auth != "" {
			// Session JS functions must all finish before concurrent network work
			// starts. Reading Go atomics here does not touch the Sobek runtime.
			if prepared.Load() != sessionCount {
				t.Errorf("session replay began before VM preparation completed: %d", prepared.Load())
			}
			if auth == "Bearer session_7" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "denied")
				return
			}
		}
		_, _ = io.WriteString(w, "same target content")
	}))
	defer srv.Close()
	vm := sobek.New()
	SetupAPI(vm, APIOptions{HTTPClient: modtest.Requester(t)})
	_ = vm.Set("preparedOnVM", func() { prepared.Add(1) })
	v, err := vm.RunString(fmt.Sprintf(`
		var headerCalls = [];
		var sessions = [];
		for (var i = 0; i < %d; i++) {
			sessions.push({label: 'session_' + i, getHeaders: function() {
				headerCalls.push(this.label);
				preparedOnVM();
				return {Authorization: 'Bearer ' + this.label};
			}});
		}
		var tested = vigolium.http.authTest({sessions: sessions, records: [{
			uuid: 'record-one', url: %q + '/resource',
			request: 'GET ' + %q + '/resource HTTP/1.1\r\nHost: ' + %q + '\r\n\r\n'
		}]} )[0];
		var unselected = vigolium.http.get(%q + '/last');
		[{url: tested.url, evidence: [
			{exchange: tested.results[2].response.exchange, role: 'attack', primary: true},
			{exchange: tested.original.exchange, role: 'baseline'},
			{exchange: tested.results[7].response.exchange, role: 'control'}
		]}];`, sessionCount, srv.URL, srv.URL, extractHost(srv.URL), srv.URL))
	require.NoError(t, err)
	require.Equal(t, int32(sessionCount+2), requests.Load()) // original, sessions, unrelated last call
	tested := vm.Get("tested").ToObject(vm)
	require.Equal(t, "idor", tested.Get("vulnerability").String())
	require.Equal(t, 7.0/8, tested.Get("confidence").ToFloat())
	require.Equal(t, "record-one", tested.Get("record_uuid").String())
	for i := range sessionCount {
		calls := vm.Get("headerCalls").ToObject(vm)
		require.Equal(t, fmt.Sprintf("session_%d", i), calls.Get(fmt.Sprint(i)).String())
		sr := tested.Get("results").ToObject(vm).Get(fmt.Sprint(i)).ToObject(vm)
		require.Equal(t, fmt.Sprintf("session_%d", i), sr.Get("session_label").String())
		require.Equal(t, i != 7, sr.Get("accessible").ToBoolean())
		require.NotNil(t, exchangeFromValue(vm, sr.Get("response").ToObject(vm).Get("exchange")))
	}
	results := parseJSResults(vm, v, nil)
	require.Len(t, results, 1)
	result := results[0]
	require.Len(t, result.Evidence, 3)
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Contains(t, result.Request, "Authorization: Bearer session_2")
	require.Contains(t, result.Request, "/resource HTTP/1.1")
	require.NotContains(t, result.Request, "/last")
	require.Contains(t, result.Response, "same target content")
	for _, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
	}
	require.NotContains(t, string(result.Evidence[1].Exchange.Request), "Authorization:")
	require.Contains(t, string(result.Evidence[2].Exchange.Request), "Authorization: Bearer session_7")
	require.Contains(t, string(result.Evidence[2].Exchange.Response), "403")

	resetReceipts(vm)
	v, err = vm.RunString(`[{evidence:[{exchange:tested.results[2].response.exchange,role:'attack',primary:true}]}]`)
	require.NoError(t, err)
	require.Empty(t, parseJSResults(vm, v, nil)[0].Evidence)
}
