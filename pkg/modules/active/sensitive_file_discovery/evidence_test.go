package sensitive_file_discovery

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestGenericFileReceiptSelectsRedirectedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup.txt" {
			http.Redirect(w, r, "/actual.txt", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Receipt", "selected-file")
		_, _ = fmt.Fprint(w, "database configuration for recovered backup")
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/input")
	result := New().probeGenericFile(ctx, modtest.Requester(t), "/backup.txt", "Backup", "exposure", &notFoundFingerprint{})
	require.NotNil(t, result)
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 1)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.NoError(t, primary.Exchange.Validate())
	require.Equal(t, srv.URL+"/actual.txt", primary.Exchange.URL)
	require.Contains(t, result.Request, "GET /actual.txt HTTP/")
	require.NotContains(t, result.Request, "GET /input HTTP/")
	require.Contains(t, result.Response, "X-Receipt: selected-file")
	require.Contains(t, result.Response, "database configuration")
}
