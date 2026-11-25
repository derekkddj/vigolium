package react_rsc_rce

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// sendActionProbe is the comparison-only compatibility API. Finding producers
// retain the explicit receipt returned by sendActionProbeEvidence.
func (m *Module) sendActionProbe(ctx *httpmsg.HttpRequestResponse, client *http.Requester, ref string) (int, string, []byte, string, bool) {
	status, body, raw, full, _, ok := m.sendActionProbeEvidence(ctx, client, ref)
	return status, body, raw, full, ok
}
