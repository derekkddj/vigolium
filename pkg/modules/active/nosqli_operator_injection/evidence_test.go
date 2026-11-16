package nosqli_operator_injection

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestBooleanEvidenceCarriesFullActualPrimaryAndControlResponses(t *testing.T) {
	t.Parallel()
	trueBody := strings.Repeat("alpha bravo charlie delta echo foxtrot ", 20)
	falseBody := strings.Repeat("zulu yankee xray whiskey victor uniform ", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if injectedConditionIsFalse(r.URL.Query().Get("q")) {
			w.Header().Set("X-Condition", "false")
			_, _ = w.Write([]byte(falseBody))
			return
		}
		w.Header().Set("X-Condition", "true")
		_, _ = w.Write([]byte(trueBody))
	}))
	defer srv.Close()
	rr := modtest.Response(modtest.Request(t, srv.URL+"/search?q=seed"), "text/plain", trueBody)
	result, err := New().testBooleanDiff(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), trueBody)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Evidence)
	primary := result.Evidence[0]
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	require.NotNil(t, primary.Exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	assert.Contains(t, result.Response, "HTTP/1.1 200 OK")
	assert.Contains(t, result.Response, "X-Condition: true")
	assert.True(t, strings.HasSuffix(result.Response, trueBody))
	assert.Equal(t, string(primary.Exchange.Request), result.Request)
	var falseControl, confirmation bool
	seen := map[string]bool{primary.ExchangeID: true}
	for _, entry := range result.Evidence[1:] {
		assert.False(t, seen[entry.ExchangeID])
		seen[entry.ExchangeID] = true
		require.NotNil(t, entry.Exchange)
		assert.NoError(t, entry.Exchange.Validate())
		if entry.Role == evidence.RoleControl && strings.Contains(string(entry.Exchange.Response), "X-Condition: false") {
			falseControl = true
		}
		if entry.Role == evidence.RoleConfirmation {
			confirmation = true
		}
	}
	assert.True(t, falseControl)
	assert.True(t, confirmation)
}
