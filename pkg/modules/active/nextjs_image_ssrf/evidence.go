package nextjs_image_ssrf

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// optimizerProbe keeps the comparison-only API; finding producers use the
// receipt-returning variant, so body projections never certify a capture.
func (m *Module) optimizerProbe(ctx *httpmsg.HttpRequestResponse, client *http.Requester, target string) (string, int, string, string, bool) {
	raw, status, body, full, _, ok := m.optimizerProbeEvidence(ctx, client, target)
	return raw, status, body, full, ok
}
