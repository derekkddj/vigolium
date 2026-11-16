package js_devserver_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCustomEvidenceKeepsMissingPathFingerprint(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/__vite_ping" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing dev endpoint"))
	}))
	defer srv.Close()
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "<html>public page</html>")
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.EqualValues(t, 1+len(devProbes), hits.Load())
	f := results[0]
	assert.Equal(t, ModuleSeverity, f.Info.Severity)
	assert.Equal(t, ModuleConfidence, f.Info.Confidence)
	require.Len(t, f.Evidence, 2)
	primary, control := f.Evidence[0], f.Evidence[1]
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleObservation, primary.Role)
	assert.Contains(t, f.Request, "GET /__vite_ping ")
	assert.Contains(t, f.Response, "204 No Content")
	assert.Equal(t, string(primary.Exchange.Request), f.Request)
	assert.Equal(t, string(primary.Exchange.Response), f.Response)
	assert.False(t, control.Primary)
	assert.Equal(t, evidence.RoleControl, control.Role)
	assert.Equal(t, evidence.ProvenanceCaptured, control.Exchange.Provenance)
	assert.Equal(t, evidence.StateComplete, control.Exchange.ResponseState)
	assert.Contains(t, string(control.Exchange.Request), "/vigolium-nonexistent-path-404-check")
	assert.Contains(t, string(control.Exchange.Response), "404 Not Found")
	assert.Contains(t, string(control.Exchange.Response), "X-Receipt-Seq: 1")
	assert.NotEqual(t, primary.ExchangeID, control.ExchangeID)
}
