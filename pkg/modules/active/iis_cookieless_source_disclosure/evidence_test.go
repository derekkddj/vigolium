package iis_cookieless_source_disclosure

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

func TestCookielessFindingSelectsAttackNotDecoyOrRefetch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Operation", fmt.Sprint(calls.Add(1)))
		if r.URL.Path != "/web.config" && strings.HasSuffix(r.URL.Path, "/web.config") {
			_, _ = fmt.Fprint(w, `<configuration><connectionStrings><add name="db" connectionString="secret" /></connectionStrings></configuration>`)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	budget := 0
	result := New().probeTarget(modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), &budget, srv.URL, targets[0])
	require.NotNil(t, result)
	require.NotEmpty(t, result.Evidence)
	primary := result.Evidence[0]
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	require.NotNil(t, primary.Exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	assert.Contains(t, result.Request, "(S(")
	assert.Contains(t, result.Request, "/web.config HTTP/1.1")
	assert.Contains(t, result.Response, "X-Operation: 2")
	assert.Contains(t, result.Response, "connectionString")
	assert.Equal(t, string(primary.Exchange.Request), result.Request)
	assert.Equal(t, string(primary.Exchange.Response), result.Response)
	assert.False(t, result.BaselineEvidence)
	for _, entry := range result.Evidence[1:] {
		assert.NotEqual(t, primary.ExchangeID, entry.ExchangeID)
		assert.False(t, entry.Primary)
	}
	assert.Equal(t, int64(4), calls.Load())
}
