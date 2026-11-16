package spring_actuator_misconfig

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestActuatorCandidatesKeepWildcardAndOwnNon200SiblingReceipts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/actuator/health" || r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status":"UP"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "not an actuator report")
	}))
	defer srv.Close()
	m := New()
	m.testCases = []*testCase{{Name: "health", Payloads: []string{"actuator/health", "health"}, confirm: func(s string) bool { return strings.Contains(s, `"status":"UP"`) }}}
	results, err := m.ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, int32(5), hits.Load(), "two candidates, two existing sibling operations, one cached wildcard")
	for i, r := range results {
		require.Len(t, r.Evidence, 3)
		primary, wildcard, sibling := r.Evidence[0], r.Evidence[1], r.Evidence[2]
		require.True(t, primary.Primary)
		require.Equal(t, evidence.RoleObservation, primary.Role)
		require.Equal(t, string(primary.Exchange.Request), r.Request)
		require.Equal(t, string(primary.Exchange.Response), r.Response)
		primaryNumber, siblingNumber := 1, 3
		if i == 1 {
			primaryNumber, siblingNumber = 4, 5
		}
		require.Contains(t, r.Response, fmt.Sprintf("X-Receipt: %d", primaryNumber))
		require.Equal(t, evidence.RoleControl, wildcard.Role)
		require.Contains(t, string(wildcard.Exchange.Response), "X-Receipt: 2")
		require.Equal(t, evidence.RoleControl, sibling.Role)
		require.Contains(t, string(sibling.Exchange.Response), "404 Not Found")
		require.Contains(t, string(sibling.Exchange.Response), fmt.Sprintf("X-Receipt: %d", siblingNumber))
	}
	require.Equal(t, results[0].Evidence[1].ExchangeID, results[1].Evidence[1].ExchangeID)
	require.NotEqual(t, results[0].Evidence[2].ExchangeID, results[1].Evidence[2].ExchangeID)
}

func TestActuatorBypassKeepsOwnPrimaryBeforeAppendingSoft404Control(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/actuator/health" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/actuator/health") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status":"UP"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	m := New()
	m.testCases = []*testCase{{Name: "health", Payloads: []string{"actuator/health"}, confirm: func(s string) bool { return strings.Contains(s, `"status":"UP"`) }}}
	results, err := m.ScanPerRequest(modtest.Request(t, srv.URL+"/"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.Len(t, r.Evidence, 2)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	require.Equal(t, string(r.Evidence[0].Exchange.Request), r.Request)
	require.Equal(t, string(r.Evidence[0].Exchange.Response), r.Response)
	require.Contains(t, r.Response, "X-Receipt: 2")
	require.Equal(t, evidence.RoleControl, r.Evidence[1].Role)
	require.Contains(t, string(r.Evidence[1].Exchange.Response), "X-Receipt: 3")
	require.Equal(t, int32(3), hits.Load(), "blocked direct path, first existing bypass and wildcard only")
}
