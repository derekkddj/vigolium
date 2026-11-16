package iis_shortname_discovery

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
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestShortnameResultSelectsPositiveOracleOperation(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Operation", fmt.Sprint(calls.Add(1)))
		if !strings.Contains(r.URL.Path, "*~1*") {
			w.WriteHeader(404)
		}
		_, _ = fmt.Fprint(w, "oracle response")
	}))
	defer srv.Close()
	budget := newRequestBudget(100)
	o := testMethodSuffix(modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), "OPTIONS", "/", "/", budget)
	require.NotNil(t, o)
	require.NotNil(t, o.primary)
	results := New().buildResult(&modkit.ScanContext{}, "test", srv.URL, o, []resolvedName{{shortName: "WEB~1.CON"}}, budget)
	require.Len(t, results, 1)
	r := results[0]
	require.Len(t, r.Evidence, 5)
	assert.Equal(t, o.primary.ID, r.Evidence[0].ExchangeID)
	assert.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	assert.Contains(t, r.Response, "X-Operation: 5")
	assert.Contains(t, r.Response, "oracle response")
	assert.Contains(t, r.Request, "OPTIONS ")
	for _, entry := range r.Evidence[1:] {
		assert.Equal(t, evidence.RoleControl, entry.Role)
		assert.NotEqual(t, o.primary.ID, entry.ExchangeID)
		assert.Contains(t, string(entry.Exchange.Response), "404")
	}
	assert.False(t, r.BaselineEvidence)
	assert.Equal(t, int64(8), calls.Load())
}
