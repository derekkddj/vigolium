package infra

import (
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ExecuteRawCapture preserves the raw-execution comparison projections while
// returning an owned receipt of this operation, captured before the chain closes.
// The prepared request is never used to certify transport bytes.
func ExecuteRawCapture(client *http.Requester, service *httpmsg.Service, raw []byte, opts http.Options) (status int, body, full string, receipt *evidence.Exchange, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return
	}
	if service != nil {
		req = req.WithService(service)
	}
	chain, _, err := client.Execute(req, opts)
	if chain != nil {
		defer chain.Close()
	}
	if err != nil || chain == nil || chain.Response() == nil {
		return
	}
	status, body, full = chain.Response().StatusCode, chain.Body().String(), chain.FullResponseString()
	receipt = http.CaptureEvidence(chain)
	ok = true
	return
}
