package spring_boot_admin_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestSiblingGuardRetainsCandidatePrimaryAndLocalControl(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/admin/instances" || r.URL.Path == "/admin/applications" {
			_, _ = fmt.Fprint(w, "framework-specific-anchor with registration details")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "unrelated nonexistent sibling")
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL+"/input"), modtest.Requester(t)
	m := New()
	var previousControl string
	for i, path := range []string{"/admin/instances", "/admin/applications"} {
		p := probe{name: "guard receipt", path: path, markers: [][]string{{"framework-specific-anchor"}}}
		r, status := m.probeEndpoint(ctx, client, p, path, nil)
		require.Equal(t, http.StatusOK, status)
		require.NotNil(t, r)
		require.Len(t, r.Evidence, 2)
		primary, control := r.Evidence[0], r.Evidence[1]
		require.True(t, primary.Primary)
		require.Equal(t, evidence.RoleObservation, primary.Role)
		require.Contains(t, r.Request, "GET "+path+" HTTP/1.1")
		require.Equal(t, string(primary.Exchange.Request), r.Request)
		require.Equal(t, string(primary.Exchange.Response), r.Response)
		require.Contains(t, r.Response, fmt.Sprintf("X-Receipt: %d", 2*i+1))
		require.False(t, control.Primary)
		require.Equal(t, evidence.RoleControl, control.Role)
		require.Contains(t, string(control.Exchange.Response), fmt.Sprintf("X-Receipt: %d", 2*i+2))
		require.True(t, strings.Contains(string(control.Exchange.Request), "/admin/"))
		require.NotEqual(t, primary.ExchangeID, control.ExchangeID)
		require.NotEqual(t, previousControl, control.ExchangeID, "uncached siblings must not leak from the preceding candidate")
		previousControl = control.ExchangeID
		require.Equal(t, int32(2*(i+1)), hits.Load(), "one candidate and its original deciding sibling only")
	}
}
