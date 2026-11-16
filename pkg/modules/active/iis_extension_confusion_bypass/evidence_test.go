package iis_extension_confusion_bypass

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestExtensionFindingKeepsOwnRawExecutionReceipt(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Operation", fmt.Sprint(calls.Add(1)))
		_, _ = fmt.Fprintf(w, "response for %s", r.URL.Path)
	}))
	defer srv.Close()
	seed, client, m := modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), New()
	var attack, control *evidence.Exchange
	status, body, ok := m.probe(seed, client, "/protected.aspx::$DATA", &attack)
	require.True(t, ok)
	assert.Equal(t, 200, status)
	_, _, ok = m.probe(seed, client, "/decoy.aspx::$DATA", &control)
	require.True(t, ok)
	u, err := seed.URL()
	require.NoError(t, err)
	result := m.buildFinding(u, "/protected.aspx::$DATA", "test", "test", body, nil, attack)
	require.Len(t, result.Evidence, 1)
	assert.Equal(t, attack.ID, result.Evidence[0].ExchangeID)
	assert.NotEqual(t, control.ID, result.Evidence[0].ExchangeID)
	assert.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	assert.Contains(t, result.Request, "GET /protected.aspx::$DATA HTTP/1.1")
	assert.Contains(t, result.Response, "X-Operation: 1")
	assert.Contains(t, result.Response, "response for /protected.aspx::$DATA")
	assert.False(t, result.BaselineEvidence)
	assert.Equal(t, int64(2), calls.Load())
}
