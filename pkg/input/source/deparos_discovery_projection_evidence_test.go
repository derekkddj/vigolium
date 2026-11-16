package source

import (
	"bytes"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/discovery"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func assertDiscoveryProjection(t *testing.T, rr *httpmsg.HttpRequestResponse, destination string, responseState evidence.State) *evidence.Exchange {
	t.Helper()
	x := rr.Evidence()
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
	require.Equal(t, evidence.StateUnknown, x.RequestState)
	require.Equal(t, responseState, x.ResponseState)
	require.Equal(t, destination, x.Service)
	require.Equal(t, rr.Target(), x.URL)
	require.Equal(t, rr.Request().Raw(), x.Request)
	if rr.HasResponse() {
		require.Equal(t, rr.Response().Raw(), x.Response)
	} else {
		require.Empty(t, x.Response)
	}
	return x
}

func TestReadDiscoveredNodeSuppliedUnknownProjection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		request  *deparosstorage.RequestData
		response *deparosstorage.ResponseData
	}{
		{
			name: "binary-post-and-reflected-response",
			request: &deparosstorage.RequestData{Method: "POST", Headers: map[string]string{
				"Content-Type": "application/octet-stream", "X-Token": "reflected-token",
			}, Body: []byte{'x', 0, 255}},
			response: &deparosstorage.ResponseData{StatusCode: 200, Headers: map[string]string{
				"Content-Type": "application/octet-stream", "X-Echo": "reflected-token", "Content-Length": "1",
			}, MIMEType: "application/octet-stream", Body: []byte{'x', 0, 255, 'y'}, DurationMs: 17},
		},
		{name: "request-only", request: &deparosstorage.RequestData{Method: "POST", Body: []byte("planned body")}},
		{name: "legacy-url-seed"},
		{name: "absent-status-is-not-a-response", response: &deparosstorage.ResponseData{Body: []byte("no HTTP status")}},
		{name: "empty-response-body-still-has-projected-headers", response: &deparosstorage.ResponseData{StatusCode: 204}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse("https://app.example:8443/submit?q=reflected-token")
			require.NoError(t, err)
			node := deparosstorage.NewDiscoveredNode(u)
			node.SetData(tc.request, tc.response, &deparosstorage.DiscoveryMetadata{FoundBy: "form", Timestamp: time.Now()})
			node.SetID(123)
			rec, nodeURL, body, ok := readDiscoveredNode(node)
			require.True(t, ok)
			require.Equal(t, u.String(), nodeURL)
			require.Equal(t, formRecordSource, rec.source)
			responseState := evidence.StateMissing
			if tc.response != nil && tc.response.StatusCode > 0 {
				responseState = evidence.StateUnknown
				require.True(t, rec.rr.HasResponse())
				require.Equal(t, tc.response.StatusCode, rec.status)
				require.Equal(t, tc.response.Body, body)
				require.Equal(t, tc.response.Body, rec.rr.Response().Body())
				require.Equal(t, time.Duration(tc.response.DurationMs)*time.Millisecond, rec.rr.Response().Duration())
			} else {
				require.False(t, rec.rr.HasResponse(), "preserve request-only planning")
				require.Zero(t, rec.status)
				require.Nil(t, body)
			}
			if tc.request == nil {
				require.Equal(t, "GET", rec.rr.Request().Method(), "legacy URL seeds retain the planning GET")
			} else {
				require.Equal(t, tc.request.Body, rec.rr.Request().Body())
			}
			x := assertDiscoveryProjection(t, rec.rr, "https://app.example:8443", responseState)
			require.NotEqual(t, "123", x.ID, "a discovery node ID cannot become a captured identity")
			again, _, _, ok := readDiscoveredNode(node)
			require.True(t, ok)
			require.NotEqual(t, x.ID, again.rr.Evidence().ID)
			snapshot := x.Clone()
			rec.rr.Request().Raw()[0] = 'X'
			if rec.rr.HasResponse() {
				rec.rr.Response().Raw()[0] = 'Y'
			}
			require.Equal(t, snapshot, rec.rr.Evidence(), "live projections cannot change owned receipt bytes")
		})
	}
}

func TestJSTemplateStubSuppliedUnknownProjection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		stub     discovery.TemplateStub
		outcome  string
		response *deparosstorage.ResponseData
	}{
		{
			name:    "replayed-template-with-reflected-response",
			stub:    discovery.TemplateStub{Method: "POST", Body: "template-token=abc\x00\xff", ContentType: "text/plain"},
			outcome: discovery.TemplateReplayedNotFound,
			response: &deparosstorage.ResponseData{StatusCode: 405, Headers: map[string]string{
				"Content-Type": "text/plain", "X-Reflected": "abc",
			}, Body: []byte("template-token=abc\x00\xff"), DurationMs: 23},
		},
		{
			name:    "withheld-template-is-request-only",
			stub:    discovery.TemplateStub{Method: "POST", Body: "planned-not-sent", ContentType: "text/plain"},
			outcome: discovery.TemplateWithheldPolicy,
		},
		{
			name:    "get-safe-headers-survive",
			stub:    discovery.TemplateStub{Method: "GET", Headers: []string{"X-Requested-With: fetch"}},
			outcome: discovery.TemplateWithheldConfidence,
		},
		{
			name:    "legacy-unresolved-method-seed",
			stub:    discovery.TemplateStub{Method: "GET", MethodUnresolved: true},
			outcome: discovery.TemplateWithheldFlushCap,
		},
		{
			name: "response-with-no-status-is-absent",
			stub: discovery.TemplateStub{Method: "GET"}, outcome: discovery.TemplateReplayedNotFound,
			response: &deparosstorage.ResponseData{Body: []byte("unusable response")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.stub.URL = "https://app.example:8443/api?q=abc"
			o := discovery.TemplateOutcome{ReplayNote: discovery.ReplayNote{Outcome: tc.outcome, Response: tc.response}}
			rr, err := jsTemplateStubRecord(tc.stub, o)
			require.NoError(t, err)
			require.True(t, bytes.Equal([]byte(tc.stub.Body), rr.Request().Body()), "preserve template body bytes, including an absent/empty body")
			if len(tc.stub.Headers) > 0 {
				require.Equal(t, "fetch", rr.Request().Header("X-Requested-With"))
			}
			responseState := evidence.StateMissing
			if tc.response != nil && tc.response.StatusCode > 0 {
				responseState = evidence.StateUnknown
				require.True(t, rr.HasResponse(), "keep normalized replay observations even though pairing is not captured")
				require.Equal(t, tc.response.Body, rr.Response().Body())
				require.Equal(t, time.Duration(tc.response.DurationMs)*time.Millisecond, rr.Response().Duration())
			} else {
				require.False(t, rr.HasResponse())
			}
			x := assertDiscoveryProjection(t, rr, "https://app.example:8443", responseState)
			again, err := jsTemplateStubRecord(tc.stub, o)
			require.NoError(t, err)
			require.NotEqual(t, x.ID, again.Evidence().ID, "a replay label or template is not a captured execution")
		})
	}
}

func TestDiscoveryProjectionMatchingOwnedCaptureUnchanged(t *testing.T) {
	for _, responseState := range []evidence.State{evidence.StateComplete, evidence.StateTruncated, evidence.StateUnknown, evidence.StateMissing} {
		t.Run(string(responseState), func(t *testing.T) {
			request := []byte("POST /probe HTTP/1.1\r\nHost: vhost.example\r\nX-Duplicate: a\r\nX-Duplicate: b\r\nContent-Length: 1\r\n\r\nx\x00\xff")
			response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\ny\x00\xff")
			if responseState == evidence.StateMissing {
				response = nil
			}
			x := evidence.NewExchange("https://app.example:8443", "https://finding.example/proof", request, response, evidence.ProvenanceCaptured)
			x.ResponseState = responseState
			x.ContentHash = x.Hash()
			original := x.Clone()
			rr, err := httpmsg.FromEvidenceExchange(x)
			require.NoError(t, err)
			got := withDiscoveryProjectionEvidence(rr)
			require.Same(t, rr, got, "do not recapture an exactly matching owned receipt")
			require.True(t, reflect.DeepEqual(original, got.Evidence()), "retain capture ID, bytes, states, timestamp, provenance and attribution")
			require.Equal(t, original, x, "the original receipt remains immutable")
		})
	}
}

func TestDiscoveryProjectionAbsentRequestRemainsMissing(t *testing.T) {
	for _, rawResponse := range [][]byte{nil, []byte("HTTP/1.1 200 OK\r\n\r\nresponse-only")} {
		req := httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("app.example", 8443, true), nil)
		var resp *httpmsg.HttpResponse
		responseState := evidence.StateMissing
		if len(rawResponse) > 0 {
			resp = httpmsg.NewHttpResponse(rawResponse)
			responseState = evidence.StateUnknown
		}
		rr := withDiscoveryProjectionEvidence(httpmsg.NewHttpRequestResponse(req, resp))
		x := rr.Evidence()
		require.NoError(t, x.Validate())
		require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
		require.Equal(t, evidence.StateMissing, x.RequestState)
		require.Empty(t, x.Request, "never fabricate a request for an absent message")
		require.Equal(t, responseState, x.ResponseState)
		require.Equal(t, rawResponse, x.Response)
		require.Equal(t, "https://app.example:8443", x.Service)
	}
}

func TestDiscoveryProjectionInvalidReceiptGetsFreshSuppliedIdentity(t *testing.T) {
	x := evidence.NewExchange("https://app.example:8443", "https://app.example:8443/probe",
		[]byte("GET /probe HTTP/1.1\r\nHost: app.example\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nresponse"), evidence.ProvenanceCaptured)
	rr, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	x.ContentHash = "invalid"
	original := x.Clone()
	projected := rr.WithEvidence(x)
	got := withDiscoveryProjectionEvidence(projected)
	supplied := assertDiscoveryProjection(t, got, "https://app.example:8443", evidence.StateUnknown)
	require.NotEqual(t, original.ID, supplied.ID)
	require.Equal(t, original, projected.Evidence(), "do not repair invalid historical metadata in place")
	require.Equal(t, original, x)
}

func TestDiscoveryProjectionChangedMessagesDoNotInheritCapture(t *testing.T) {
	for _, change := range []string{"request", "response", "destination"} {
		t.Run(change, func(t *testing.T) {
			x := evidence.NewExchange("https://app.example:8443", "https://app.example:8443/probe",
				[]byte("POST /probe HTTP/1.1\r\nHost: app.example\r\n\r\nactual-sent-body"),
				[]byte("HTTP/1.1 200 OK\r\n\r\nactual-response"), evidence.ProvenanceCaptured)
			original := x.Clone()
			rr, err := httpmsg.FromEvidenceExchange(x)
			require.NoError(t, err)
			req, resp, destination := rr.Request(), rr.Response(), "https://app.example:8443"
			switch change {
			case "request":
				req = req.WithBody([]byte("template-body-is-not-the-actual-request"))
			case "response":
				resp = resp.WithBody([]byte("normalized-reflected-response"))
			case "destination":
				req = httpmsg.NewHttpRequestWithService(httpmsg.NewServiceSecure("other.example", 9443, true), bytes.Clone(req.Raw()))
				destination = "https://other.example:9443"
			}
			projected := httpmsg.NewHttpRequestResponse(req, resp).WithEvidence(x)
			got := withDiscoveryProjectionEvidence(projected)
			supplied := assertDiscoveryProjection(t, got, destination, evidence.StateUnknown)
			require.NotEqual(t, original.ID, supplied.ID)
			require.Equal(t, original, x)
			require.Equal(t, original, projected.Evidence(), "rejecting inheritance must not mutate the original capture")
			require.NotEqual(t, original, supplied, "a changed template/observation cannot masquerade as the actual captured pair")
		})
	}
}
