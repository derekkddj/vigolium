package wp_ajax_exposure

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

func TestAJAXFindingKeepsSharedWildcardAndNoopOperationReceipts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, "wildcard control")
			return
		}
		if readAction(r) == "revslider_show_image" {
			_, _ = fmt.Fprint(w, "admin-ajax: missing image id parameter for revslider handler")
			return
		}
		_, _ = fmt.Fprint(w, "0")
	}))
	defer srv.Close()
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", "original input")
	results, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	require.Equal(t, int32(2+len(vulnerableActions)), hits.Load(), "noop, wildcard and one request per existing action; no evidence-only sends")
	for _, r := range results {
		require.Len(t, r.Evidence, 3)
		primary, noop, wildcard := r.Evidence[0], r.Evidence[1], r.Evidence[2]
		require.True(t, primary.Primary)
		require.Equal(t, evidence.RoleObservation, primary.Role)
		require.Equal(t, string(primary.Exchange.Request), r.Request)
		require.Equal(t, string(primary.Exchange.Response), r.Response)
		require.Contains(t, r.Request, "action=revslider_show_image")
		for _, entry := range []evidence.Entry{noop, wildcard} {
			require.False(t, entry.Primary)
			require.Equal(t, evidence.RoleControl, entry.Role)
			require.NotEqual(t, primary.ExchangeID, entry.ExchangeID)
		}
		require.Contains(t, string(noop.Exchange.Request), "action=vigolium_noop_")
		require.Contains(t, string(noop.Exchange.Response), "X-Receipt: 1")
		require.True(t, strings.HasSuffix(string(noop.Exchange.Response), "0"))
		require.Contains(t, string(wildcard.Exchange.Response), "X-Receipt: 2")
	}
}
