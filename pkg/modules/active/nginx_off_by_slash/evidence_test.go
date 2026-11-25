package nginx_off_by_slash

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

func TestOffBySlashSelectsInitialAttackBeforeControls(t *testing.T) {
	t.Parallel()
	var attacks atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/assets../secret" {
			w.Header().Set("X-Attack-Operation", fmt.Sprint(attacks.Add(1)))
			_, _ = fmt.Fprint(w, strings.Repeat("private outside alias content ", 10))
		} else {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	m := New()
	m.injections, m.suffixes = []string{".."}, []string{"secret"}
	results, err := m.ScanPerRequest(modtest.Request(t, srv.URL+"/assets/start"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.NotEmpty(t, r.Evidence)
	assert.True(t, r.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	assert.Contains(t, r.Request, "GET /assets../secret HTTP/1.1")
	assert.Contains(t, r.Response, "X-Attack-Operation: 1")
	confirmations := 0
	for _, entry := range r.Evidence[1:] {
		assert.NotEqual(t, r.Evidence[0].ExchangeID, entry.ExchangeID)
		if entry.Role == evidence.RoleConfirmation {
			confirmations++
		}
	}
	assert.Equal(t, 2, confirmations)
	assert.Equal(t, int64(3), attacks.Load())
	assert.False(t, r.BaselineEvidence)
}
