package swagger_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestSwaggerUIGuardsRetainRootDirectoryAndSlugControls(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/redoc" {
			_, _ = fmt.Fprint(w, `<html><redoc spec-url="/openapi.json"></redoc></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "non-documentation control page")
	}))
	defer srv.Close()
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/plain", "input only")
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.Len(t, r.Evidence, 4, "one primary and all three deciding control operations")
	require.Equal(t, int32(13), hits.Load(), "ten original path candidates through redoc, random directory, root and slug; no evidence requests")
	primary := r.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleAttack, primary.Role)
	require.Contains(t, r.Request, "GET /redoc HTTP/1.1")
	require.Contains(t, r.Response, "X-Receipt: 10")
	require.Equal(t, string(primary.Exchange.Request), r.Request)
	require.Equal(t, string(primary.Exchange.Response), r.Response)
	for i, control := range r.Evidence[1:] {
		require.False(t, control.Primary)
		require.Equal(t, evidence.RoleControl, control.Role)
		require.NotEqual(t, primary.ExchangeID, control.ExchangeID)
		require.Contains(t, string(control.Exchange.Response), fmt.Sprintf("X-Receipt: %d", 11+i))
	}
	require.Contains(t, string(r.Evidence[2].Exchange.Request), "GET / HTTP/1.1")
	require.Equal(t, output.RecordKindObservation, r.RecordKind)
}
