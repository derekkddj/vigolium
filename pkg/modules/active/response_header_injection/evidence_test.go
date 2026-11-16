package response_header_injection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestHeaderInjectionEvidenceIncludesBodyAndFreshConfirmations(t *testing.T) {
	t.Parallel()
	srv := headerSplitServer()
	defer srv.Close()
	m := New()
	rr := modtest.Request(t, srv.URL+"/search?q=seed")
	results, err := m.ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.Len(t, result.Evidence, 3)
	primary := result.Evidence[0]
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	require.NotNil(t, primary.Exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	assert.Equal(t, string(primary.Exchange.Response), result.Response)
	assert.Contains(t, result.Response, "HTTP/1.1 200 OK")
	assert.Contains(t, result.Response, "X-Injected: "+m.canary)
	assert.Contains(t, result.Response, "\r\n\r\nok")
	for _, entry := range result.Evidence[1:] {
		assert.Equal(t, evidence.RoleConfirmation, entry.Role)
		assert.NotEqual(t, primary.ExchangeID, entry.ExchangeID)
		require.NotNil(t, entry.Exchange)
		assert.NotContains(t, string(entry.Exchange.Request), m.canary)
		assert.NoError(t, entry.Exchange.Validate())
	}
}
