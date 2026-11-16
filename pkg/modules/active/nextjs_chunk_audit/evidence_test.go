package nextjs_chunk_audit

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

func TestChunkAndMapFindingsKeepTheirOwnAnonymousReceipts(t *testing.T) {
	t.Parallel()
	const chunkPath = "/_next/static/chunks/main-receipt.js"
	const body = `const privateToken="ghp_1234567890abcdefghijklmnopqrstuvwxyz"; const publicID="AKIA1234ABCD5678EFGH"; fetch("/api/receipt");`
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-Receipt-Path", r.URL.Path)
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	rr := modtest.Response(modtest.Request(t, srv.URL+"/seed"), "text/html", nextShellReferencing(chunkPath))
	results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 6, "private credential, public identifier and summary for both fetched bodies")
	ids := make(map[bool]string)
	for _, result := range results {
		require.Len(t, result.Evidence, 1)
		primary := result.Evidence[0]
		assert.True(t, primary.Primary)
		assert.Equal(t, evidence.RoleObservation, primary.Role)
		require.NotNil(t, primary.Exchange)
		assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
		assert.NoError(t, primary.Exchange.Validate())
		fromMap, ok := result.Metadata["from_map"].(bool)
		require.True(t, ok)
		path := chunkPath
		if fromMap {
			path += ".map"
		}
		assert.Contains(t, result.Request, "GET "+path+" HTTP/1.1")
		assert.Contains(t, result.Response, "X-Receipt-Path: "+path)
		assert.True(t, strings.HasSuffix(result.Response, body))
		assert.Equal(t, string(primary.Exchange.Request), result.Request)
		assert.Equal(t, string(primary.Exchange.Response), result.Response)
		assert.False(t, result.BaselineEvidence, "the HTML seed does not prove fetched-asset findings")
		if id, seen := ids[fromMap]; seen {
			assert.Equal(t, id, primary.ExchangeID, "builders analysing one body reuse its actual execution")
		} else {
			ids[fromMap] = primary.ExchangeID
		}
	}
	assert.NotEqual(t, ids[false], ids[true], "the later map fetch is a separate exchange")
	assert.Equal(t, int64(2), calls.Load(), "no proof-manufacturing refetch")
}
