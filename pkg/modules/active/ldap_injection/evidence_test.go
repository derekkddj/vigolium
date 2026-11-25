package ldap_injection

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

func TestNegationOracleEvidenceKeepsPrimaryAndControlExecutions(t *testing.T) {
	t.Parallel()
	short, expanded := strings.Repeat("no match ", 30), strings.Repeat("directory entry ", 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Query().Get("username") == negationTruePayload {
			w.Header().Set("X-Ldap-Condition", "true")
			_, _ = w.Write([]byte(expanded))
			return
		}
		w.Header().Set("X-Ldap-Condition", "false")
		_, _ = w.Write([]byte(short))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/search?username=seed")
	result := New().detectNegationOracle(rr, modtest.InsertionPoint(t, rr, "username"), modtest.Requester(t), srv.URL+"/search", newResponseSignature(200, short))
	require.NotNil(t, result)
	require.NotEmpty(t, result.Evidence)
	primary := result.Evidence[0]
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	require.NotNil(t, primary.Exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	assert.Contains(t, result.Response, "X-Ldap-Condition: true")
	assert.True(t, strings.HasSuffix(result.Response, expanded))
	assert.Equal(t, string(primary.Exchange.Request), result.Request)
	var controls, confirmations int
	for _, entry := range result.Evidence[1:] {
		assert.NotEqual(t, primary.ExchangeID, entry.ExchangeID)
		require.NotNil(t, entry.Exchange)
		assert.NoError(t, entry.Exchange.Validate())
		switch entry.Role {
		case evidence.RoleControl:
			controls++
			assert.Contains(t, string(entry.Exchange.Response), "X-Ldap-Condition: false")
		case evidence.RoleConfirmation:
			confirmations++
		}
	}
	assert.Equal(t, 3, controls)
	assert.Equal(t, 2, confirmations)
}
