package modkit_test

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

func TestFetchedBaselineOwnsFinalReceiptAcrossCacheReuse(t *testing.T) {
	var hits atomic.Int64
	body := strings.Repeat("source-bearing body ", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "baseline_sid", Value: "final", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("X-Baseline-Receipt", "complete")
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/start")
	client, sc := modtest.Requester(t), &modkit.ScanContext{}
	first, err := sc.GetOrFetchBaseline(ctx, client)
	require.NoError(t, err)
	x := first.Receipt
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
	require.Equal(t, srv.URL+"/final", x.URL)
	require.Contains(t, string(x.Request), "GET /final HTTP/")
	require.Contains(t, string(x.Request), "baseline_sid=final")
	require.Contains(t, string(x.Response), "X-Baseline-Receipt: complete")
	require.True(t, strings.HasSuffix(string(x.Response), body))
	require.Equal(t, x.Response, first.Response.Raw())
	id, hash, stamp := x.ID, x.ContentHash, x.CapturedAt
	x.Request[0] = 'X' // consumer copy must not corrupt the cached receipt
	second, err := sc.GetOrFetchBaseline(ctx, client)
	require.NoError(t, err)
	require.Equal(t, int64(2), hits.Load(), "cache reuse must not send proof-only traffic")
	require.Equal(t, id, second.Receipt.ID)
	require.Equal(t, hash, second.Receipt.ContentHash)
	require.Equal(t, stamp, second.Receipt.CapturedAt)
	require.NoError(t, second.Receipt.Validate())
	require.Contains(t, string(second.Receipt.Request), "GET /final HTTP/")
}
