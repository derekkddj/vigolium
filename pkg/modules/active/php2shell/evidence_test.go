package php2shell

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

func TestBuildResultKeepsReceiptSeparateFromElidedRequestDisplay(t *testing.T) {
	t.Parallel()
	body := []byte(strings.Repeat("multipart bytes ", 1024))
	raw := append([]byte("POST /index.php HTTP/1.1\r\nHost: example.test\r\n\r\n"), body...)
	display := modkit.ElideRequestBody(raw, len(body), maxEvidenceBytes)
	require.Contains(t, display, "more bytes of the probe body elided")
	response := []byte("HTTP/1.1 500 Internal Server Error\r\n\r\ndecisive response")
	for _, state := range []evidence.State{evidence.StateComplete, evidence.StateMissing, evidence.StateTruncated} {
		t.Run(string(state), func(t *testing.T) {
			// Supplied constructor fixtures test selection, not transport capture.
			request := raw
			if state == evidence.StateMissing {
				request = nil
			} else if state == evidence.StateTruncated {
				request = raw[:128]
			}
			primary := evidence.NewExchange("http://example.test", "http://example.test/index.php", request, response, evidence.ProvenanceSupplied)
			primary.RequestState = state
			primary.ContentHash = primary.Hash()
			control := evidence.NewExchange("http://example.test", "http://example.test/index.php", []byte("control request"), []byte("control response"), evidence.ProvenanceSupplied)
			r := buildResult("example.test", "http://example.test", defaultPath, 1, probes[0], "PHP-FPM", "test signal", "",
				exchange{receipt: control, request: "control display", response: "control display"},
				exchange{receipt: primary, request: display, response: "truncated response display"})
			require.Len(t, r.Evidence, 2)
			assert.Equal(t, primary, r.Evidence[0].Exchange)
			assert.Equal(t, control, r.Evidence[1].Exchange)
			assert.True(t, r.Evidence[0].Primary)
			assert.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
			assert.Equal(t, evidence.ProvenanceSupplied, r.Evidence[0].Exchange.Provenance)
			assert.NoError(t, r.Evidence[0].Exchange.Validate())
			assert.Equal(t, string(request), r.Request)
			assert.Equal(t, string(response), r.Response)
			assert.NotContains(t, r.Request, "more bytes of the probe body elided")
			if state == evidence.StateMissing {
				assert.Empty(t, r.Request, "neither the intended display nor control can repair missing request bytes")
				assert.Equal(t, "missing", r.EvidenceStatus)
			} else {
				assert.Equal(t, "selected", r.EvidenceStatus)
			}
		})
	}
}
