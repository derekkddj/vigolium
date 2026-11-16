package iisgate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCachedIISGateRetainsOriginalOperationIdentities(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Operation", fmt.Sprint(calls.Add(1)))
		if r.URL.Path != "/" && !strings.Contains(r.URL.Path, "(S(") {
			w.WriteHeader(404)
			return
		}
		_, _ = fmt.Fprint(w, strings.Repeat("IIS root content ", 10))
	}))
	defer srv.Close()
	seed, client := modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t)
	first, reused := modkit.NewEvidenceCollector(), modkit.NewEvidenceCollector()
	require.True(t, ConfirmIISBehaviorWithEvidence(srv.URL, seed, client, first))
	require.True(t, ConfirmIISBehaviorWithEvidence(srv.URL, seed, client, reused))
	require.Len(t, first.Evidence(), 3)
	require.Len(t, reused.Evidence(), 3)
	for i, entry := range first.Evidence() {
		assert.Equal(t, entry.ExchangeID, reused.Evidence()[i].ExchangeID)
		assert.False(t, entry.Primary)
		assert.NoError(t, entry.Exchange.Validate())
	}
	assert.Equal(t, int64(3), calls.Load(), "cache reuse is not a new execution")
}
