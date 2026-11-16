package proxy_header_trust

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestForwardedHostEvidenceKeepsInitialProbeAndFreshConfirmations(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Sequence", fmt.Sprint(calls.Add(1)))
		host := r.Header.Get("X-Forwarded-Host")
		if host != "" {
			w.Header().Set("Location", "https://"+host+"/dashboard")
			w.WriteHeader(http.StatusFound)
		}
		_, _ = fmt.Fprintf(w, "own response for %s", host)
	}))
	defer srv.Close()

	result := New().testForwardedHost(modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), srv.URL+"/seed", nil)
	require.NotNil(t, result)
	require.Len(t, result.Evidence, 3)
	primary := result.Evidence[0]
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	require.NotNil(t, primary.Exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	assert.Equal(t, string(primary.Exchange.Request), result.Request)
	assert.Equal(t, string(primary.Exchange.Response), result.Response)
	assert.Contains(t, result.Request, "GET / HTTP/1.1")
	assert.Contains(t, result.Request, injectedHost)
	assert.Contains(t, result.Response, "X-Receipt-Sequence: 1")
	assert.Contains(t, result.Response, "own response for "+injectedHost)
	assert.False(t, result.BaselineEvidence)
	seen := map[string]bool{primary.ExchangeID: true}
	for _, entry := range result.Evidence[1:] {
		assert.Equal(t, evidence.RoleConfirmation, entry.Role)
		assert.False(t, entry.Primary)
		assert.False(t, seen[entry.ExchangeID], "each execution must have its own identity")
		seen[entry.ExchangeID] = true
		require.NotNil(t, entry.Exchange)
		assert.False(t, strings.Contains(string(entry.Exchange.Request), injectedHost))
		assert.NoError(t, entry.Exchange.Validate())
	}
	assert.Equal(t, int64(3), calls.Load(), "receipt selection must not send additional proof requests")
}
