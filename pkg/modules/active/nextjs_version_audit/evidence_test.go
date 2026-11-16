package nextjs_version_audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestVersionProbeDoesNotOptIntoInputEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_next/static/chunks/main.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`var NEXT_VERSION = "15.0.0";`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	body := `<html><script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script></html>`
	input := modtest.Response(modtest.Request(t, srv.URL+"/input"), "text/html", body)
	results, err := New().ScanPerHost(input, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, result := range results {
		require.False(t, result.BaselineEvidence)
		require.Len(t, result.Evidence, 1)
		entry := result.Evidence[0]
		require.True(t, entry.Primary)
		require.Equal(t, evidence.RoleObservation, entry.Role)
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.Contains(t, result.Request, "GET /_next/static/chunks/main.js HTTP/")
		require.Contains(t, result.Response, `var NEXT_VERSION = "15.0.0";`)
		require.NoError(t, entry.Exchange.Validate())
	}
}
