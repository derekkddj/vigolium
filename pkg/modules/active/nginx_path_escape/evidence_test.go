package nginx_path_escape

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
)

func TestPathEscapeBuilderDoesNotReconstructProbeBase(t *testing.T) {
	// Supplied fixtures deliberately stay supplied/unknown; the builder must
	// preserve their identity and fidelity, not certify bytes from Probe.Base.
	attack := evidence.NewExchange("", "", []byte("GET /actual/escaped HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nactual proof"), evidence.ProvenanceSupplied)
	control := evidence.NewExchange("", "", []byte("GET /control HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 404 Not Found\r\n\r\ncontrol"), evidence.ProvenanceSupplied)
	context := modkit.NewEvidenceCollector()
	context.AddExchange(control, evidence.RoleControl, "negative")
	probe := diffscan.NewProbe("test", 0, "wrong-intended-base")
	probe.Base = "/never-executed"
	r := buildEvidenceResult("http://test/seed", "test", "report", []*finding{{Primary: attack, Context: context, ProbeInfo: &ProbeInfo{Probe: probe}}})
	require.NotNil(t, r)
	require.Len(t, r.Evidence, 2)
	assert.Equal(t, attack.ID, r.Evidence[0].ExchangeID)
	assert.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	assert.Equal(t, evidence.ProvenanceSupplied, r.Evidence[0].Exchange.Provenance)
	assert.Equal(t, string(attack.Request), r.Request)
	assert.Equal(t, string(attack.Response), r.Response)
	assert.NotContains(t, r.Request, "never-executed")
	assert.Equal(t, control.ID, r.Evidence[1].ExchangeID)
	assert.False(t, r.Evidence[1].Primary)
	assert.False(t, r.BaselineEvidence)
}
