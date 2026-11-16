package redos_probe

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestTimeoutProofDoesNotPromoteIntendedRequestOrBaseline(t *testing.T) {
	t.Parallel()
	rr := modtest.Response(modtest.Request(t, "http://example.test/?email=seed"), "text/plain", "baseline only")
	p := prober{m: New(), ctx: rr, ip: modtest.InsertionPoint(t, rr, "email")}
	missing := evidence.NewExchange("", "", nil, nil, evidence.ProvenanceSupplied)
	proof := timed{elapsed: time.Second, request: "intended-but-not-captured", exchange: missing}
	result := p.result([]round{{control: time.Millisecond, low: 10 * time.Millisecond, high: time.Second}}, proof, 8, 16, time.Millisecond)
	require.NotEmpty(t, result.Evidence)
	primary := result.Evidence[0]
	assert.Equal(t, missing.ID, primary.ExchangeID)
	assert.True(t, primary.Primary)
	assert.Equal(t, evidence.RoleAttack, primary.Role)
	require.NotNil(t, primary.Exchange)
	assert.Equal(t, evidence.StateMissing, primary.Exchange.RequestState)
	assert.Equal(t, evidence.StateMissing, primary.Exchange.ResponseState)
	assert.Equal(t, "missing", result.EvidenceStatus)
	assert.Empty(t, result.Request)
	assert.Empty(t, result.Response)
	assert.False(t, result.BaselineEvidence)
}
