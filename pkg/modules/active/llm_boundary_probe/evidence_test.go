package llm_boundary_probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestLLMPrimaryOwnsFullHTTPResponseAndCrossFormReceipt(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Operation", fmt.Sprint(calls.Add(1)))
		_, _ = fmt.Fprint(w, jsonReply("secret: "+testSecret))
	}))
	defer srv.Close()
	results, err := New().ScanPerRequest(modtest.RequestJSON(t, srv.URL, seedBody), modtest.Requester(t), markedCtx(t, srv.URL))
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.Len(t, r.Evidence, 2)
	assert.True(t, r.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	assert.Equal(t, evidence.RoleConfirmation, r.Evidence[1].Role)
	assert.NotEqual(t, r.Evidence[0].ExchangeID, r.Evidence[1].ExchangeID)
	assert.Contains(t, r.Request, promptForms[0])
	assert.Contains(t, r.Response, "HTTP/1.1 200")
	assert.Contains(t, r.Response, "X-Operation: 1")
	assert.Contains(t, r.Response, jsonReply("secret: "+testSecret))
	assert.Contains(t, string(r.Evidence[1].Exchange.Request), promptForms[1])
	assert.Contains(t, string(r.Evidence[1].Exchange.Response), "X-Operation: 2")
	assert.False(t, r.BaselineEvidence)
	assert.Equal(t, int64(2), calls.Load())
}
