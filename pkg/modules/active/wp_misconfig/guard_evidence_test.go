package wp_misconfig

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
)

func TestWordPressGuardsKeepAllControlsAndCachedIdentities(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/wp-admin/setup.php" || r.URL.Path == "/wp-admin/upgrade.php" {
			_, _ = fmt.Fprint(w, "WordPress-specific configuration installer document")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "ordinary not found response")
	}))
	defer srv.Close()
	ctx, client, sc := modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), &modkit.ScanContext{}
	m := New()
	var controlIDs []string
	for i, path := range []string{"/wp-admin/setup.php", "/wp-admin/upgrade.php"} {
		p := wpProbe{path: path, name: "receipt", markers: []string{"WordPress-specific"}}
		r := m.probeFile(ctx, client, sc, p, path, nil)
		require.NotNil(t, r)
		require.Len(t, r.Evidence, modkit.MaxEvidencePairs+1)
		primary := r.Evidence[0]
		require.True(t, primary.Primary)
		require.Equal(t, evidence.RoleObservation, primary.Role)
		require.Equal(t, string(primary.Exchange.Request), r.Request)
		require.Equal(t, string(primary.Exchange.Response), r.Response)
		require.Contains(t, r.Request, "GET "+path+" HTTP/1.1")
		for index, control := range r.Evidence[1:] {
			require.False(t, control.Primary)
			require.Equal(t, evidence.RoleControl, control.Role)
			require.NotEqual(t, primary.ExchangeID, control.ExchangeID)
			if i == 0 {
				controlIDs = append(controlIDs, control.ExchangeID)
				require.Contains(t, string(control.Exchange.Response), fmt.Sprintf("X-Receipt: %d", index+2))
			} else {
				require.Equal(t, controlIDs[index], control.ExchangeID, "wildcard, sibling and stability controls retain original cache execution identity")
			}
		}
		require.Equal(t, int32(11+i), hits.Load(), "one candidate; controls send once and are reused without evidence-only traffic")
	}
}

func TestWordPressCronKeepsEmptyPrimaryAndActualPHPDecoy(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path != "/wp-cron.php" {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/input")
	r := New().probeFile(ctx, modtest.Requester(t), &modkit.ScanContext{}, wpProbe{path: "/wp-cron.php"}, "/wp-cron.php", nil)
	require.NotNil(t, r)
	require.Len(t, r.Evidence, 2)
	require.True(t, r.Evidence[0].Primary)
	require.Contains(t, r.Request, "GET /wp-cron.php HTTP/1.1")
	require.Contains(t, r.Response, "X-Receipt: 1")
	require.Equal(t, evidence.RoleControl, r.Evidence[1].Role)
	require.Contains(t, string(r.Evidence[1].Exchange.Response), "X-Receipt: 2")
	require.Equal(t, int32(2), hits.Load(), "existing empty candidate and its PHP control only")
}
