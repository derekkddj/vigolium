package swagger_exposure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestSwaggerReceiptIsAnonymousProbeNotAuthenticatedInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Evidence-Receipt", "anonymous spec")
		_, _ = w.Write([]byte(`{"openapi":"3.1.0","info":{"title":"Public","version":"1"},"paths":{}}`))
	}))
	defer srv.Close()
	input := modtest.Request(t, srv.URL+"/authenticated-input")
	raw, err := httpmsg.AddOrReplaceHeader(input.Request().Raw(), "Authorization", "Bearer private")
	require.NoError(t, err)
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Cookie", "session=private")
	require.NoError(t, err)
	input = httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(input.Service(), raw), input.Response())
	results, err := New().ScanPerRequest(input, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.Len(t, result.Evidence, 1)
	x := result.Evidence[0].Exchange
	require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
	require.Equal(t, srv.URL+"/openapi.json", x.URL)
	require.Contains(t, string(x.Request), "GET /openapi.json HTTP/1.1")
	require.NotContains(t, string(x.Request), "Bearer private")
	require.NotContains(t, string(x.Request), "session=private")
	require.Contains(t, string(x.Response), "X-Evidence-Receipt: anonymous spec")
	require.Equal(t, string(x.Request), result.Request)
	require.Equal(t, string(x.Response), result.Response)
	require.NoError(t, x.Validate())
}
