package path_normalization

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestBuildFindingSelectsBackedProbeReceiptNotControl(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Probe-Path", r.URL.Path)
		_, _ = fmt.Fprintf(w, "body for %s", r.URL.Path)
	}))
	defer srv.Close()
	m := New()
	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/seed")
	probe := func(path string) pathProbe { return m.probePath(rr.Request().Raw(), path, rr.Service(), client, true) }
	baseline, rejected, backed, confirmation := probe("/clean"), probe("/over"), probe("/backed"), probe("/backed")
	urlx, err := rr.URL()
	require.NoError(t, err)
	result := m.buildFinding(urlx, "../", "/over", "/backed", baseline, rejected, backed, confirmation, false)
	require.Len(t, result.Evidence, 4)
	primary := result.Evidence[0]
	assert.Equal(t, backed.exchange.ID, primary.ExchangeID)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	assert.True(t, primary.Primary)
	assert.NotEqual(t, confirmation.exchange.ID, primary.ExchangeID, "same URL is not same execution")
	assert.Contains(t, result.Response, "X-Probe-Path: /backed")
	assert.True(t, strings.HasSuffix(result.Response, "body for /backed"))
	assert.Equal(t, string(backed.exchange.Request), result.Request)
	assert.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
	assert.Equal(t, evidence.RoleControl, result.Evidence[2].Role)
	assert.Equal(t, evidence.RoleConfirmation, result.Evidence[3].Role)
	assert.Equal(t, confirmation.exchange.ID, result.Evidence[3].ExchangeID)
}
