package node2shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	node2shellinfra "github.com/vigolium/vigolium/pkg/modules/infra/node2shell"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestBuildResultSelectsKnownProbeNotLaterTwin(t *testing.T) {
	t.Parallel()
	rr := modtest.Request(t, "http://example.test/upload")
	probe := evidence.NewExchange("http://example.test", "http://example.test/upload", []byte("POST /upload HTTP/1.1\r\n\r\nactual probe"), []byte("HTTP/1.1 422 Unprocessable Entity\r\n\r\nown probe response"), evidence.ProvenanceCaptured)
	twin := evidence.NewExchange("http://example.test", "http://example.test/upload", []byte("POST /upload HTTP/1.1\r\n\r\nactual twin"), []byte("HTTP/1.1 400 Bad Request\r\n\r\nown twin response"), evidence.ProvenanceCaptured)
	result := buildResult(verdict{
		probe: node2shellinfra.Exchange{Receipt: probe, Request: "elided probe display", Response: "truncated probe display"},
		twin:  node2shellinfra.Exchange{Receipt: twin, Request: "elided twin display", Response: "truncated twin display"},
	}, node2shellinfra.Gate{}, modtest.ScanCtxWithTech("http://example.test"), rr, "http://example.test/upload", node2shellinfra.LaneRoute)
	require.Len(t, result.Evidence, 2)
	assert.Equal(t, probe.ID, result.Evidence[0].ExchangeID)
	assert.True(t, result.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	assert.Equal(t, twin.ID, result.Evidence[1].ExchangeID)
	assert.Equal(t, evidence.RoleControl, result.Evidence[1].Role)
	assert.Equal(t, string(probe.Request), result.Request)
	assert.Equal(t, string(probe.Response), result.Response)
	assert.False(t, result.BaselineEvidence)
}
