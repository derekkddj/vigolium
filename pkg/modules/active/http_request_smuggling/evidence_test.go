package http_request_smuggling

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestTimingTimeoutEvidenceRemainsMissingNotBaseline(t *testing.T) {
	t.Parallel()
	rr := modtest.Response(modtest.Request(t, "http://example.test/"), "text/plain", "baseline only")
	missing := evidence.NewExchange("", "", nil, nil, evidence.ProvenanceSupplied)
	control := evidence.NewExchange("http://example.test", "http://example.test/", []byte("POST / HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\ncontrol"), evidence.ProvenanceSupplied)
	result := buildResult(rr, []byte("intended raw framing"), probes[0], controlReading{median: time.Millisecond}, time.Second, true,
		desyncEvidence{probeExchange: missing, controlExchange: control, reElapsed: time.Second, ctrlElapsed: time.Millisecond})
	require.Len(t, result.Evidence, 2)
	assert.Equal(t, missing.ID, result.Evidence[0].ExchangeID)
	assert.Equal(t, evidence.RoleConfirmation, result.Evidence[0].Role)
	assert.Equal(t, evidence.RoleControl, result.Evidence[1].Role)
	assert.Equal(t, "missing", result.EvidenceStatus)
	assert.Empty(t, result.Request)
	assert.Empty(t, result.Response)
	assert.False(t, result.BaselineEvidence)
}

func TestTimingRawUnknownConfirmationDoesNotCertifyIntendedFraming(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Receipt-Path", r.URL.Path)
		_, _ = w.Write([]byte("actual response"))
	}))
	defer srv.Close()
	client := modtest.Requester(t)
	probe, _, err := client.Execute(modtest.Request(t, srv.URL+"/probe"), httpRequester.Options{RawRequest: true, NoRedirects: true, NoClustering: true})
	require.NoError(t, err)
	primary := httpRequester.CaptureEvidence(probe)
	probe.Close()
	control, _, err := client.Execute(modtest.Request(t, srv.URL+"/control"), httpRequester.Options{NoRedirects: true, NoClustering: true})
	require.NoError(t, err)
	comparison := httpRequester.CaptureEvidence(control)
	control.Close()
	require.NotNil(t, primary)
	require.NotNil(t, comparison)
	assert.Equal(t, int32(2), hits.Load())
	assert.Equal(t, int64(2), client.RequestsSent())
	assert.Equal(t, evidence.ProvenanceCaptured, primary.Provenance)
	assert.Equal(t, evidence.StateMissing, primary.RequestState, "rawhttp without RawBytes cannot certify its rebuilt request")
	assert.Equal(t, evidence.StateComplete, primary.ResponseState)
	assert.Empty(t, primary.Request)
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/plain", "supplied baseline only")
	result := buildResult(rr, []byte("intended smuggling framing"), probes[0], controlReading{median: time.Millisecond}, time.Second, false,
		desyncEvidence{probeExchange: primary, controlExchange: comparison, reElapsed: time.Second, ctrlElapsed: time.Millisecond})
	require.Len(t, result.Evidence, 2)
	assert.Equal(t, primary, result.Evidence[0].Exchange)
	assert.Equal(t, comparison, result.Evidence[1].Exchange)
	assert.True(t, result.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleConfirmation, result.Evidence[0].Role)
	assert.Equal(t, evidence.RoleControl, result.Evidence[1].Role)
	assert.Equal(t, "missing", result.EvidenceStatus)
	assert.Empty(t, result.Request)
	assert.Equal(t, string(primary.Response), result.Response)
	assert.Contains(t, result.Response, "X-Receipt-Path: /probe")
	assert.False(t, result.BaselineEvidence)
}

func TestCL0RenderedResponseMarksEvidenceTruncation(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("x", cl0EvidenceBody+10)
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Receipt: own\r\n\r\n%s", len(body), body)
	response, err := readWireResponse(bufio.NewReader(strings.NewReader(raw)), "POST")
	require.NoError(t, err)
	assert.True(t, response.truncated)
	assert.Equal(t, body, response.body, "the comparison body stays unchanged")
	assert.Contains(t, response.raw, "X-Receipt: own")
	assert.True(t, strings.HasSuffix(response.raw, body[:cl0EvidenceBody]))
}
