package salesforce_lightning_debug_mode

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestDebugModeSelectsRedirectedBootstrapNotGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/aura"):
			_, _ = w.Write([]byte(`{"event":{"descriptor":"markup://aura:invalidSession"}}`))
		case r.URL.Path == "/s/":
			http.Redirect(w, r, "/bootstrap", http.StatusFound)
		case r.URL.Path == "/bootstrap":
			_, _ = w.Write([]byte(`window.Aura={};auraConfig={"context":{"mode":"PRODDEBUG"}};`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.False(t, r.BaselineEvidence)
	require.Len(t, r.Evidence, 4)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleObservation, r.Evidence[0].Role)
	require.Contains(t, r.Request, "GET /bootstrap HTTP/1.1")
	require.Contains(t, r.Response, `"mode":"PRODDEBUG"`)
	require.NotContains(t, r.Response, "invalidSession")
	seen := map[string]bool{}
	confirmations := 0
	for _, entry := range r.Evidence {
		require.NotNil(t, entry.Exchange)
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, seen[entry.ExchangeID])
		seen[entry.ExchangeID] = true
		if entry.Primary || entry.Role == evidence.RoleConfirmation {
			require.Equal(t, srv.URL+"/bootstrap", entry.Exchange.URL)
		}
		if entry.Role == evidence.RoleConfirmation {
			confirmations++
		}
	}
	require.Equal(t, confirmRounds, confirmations)
}
