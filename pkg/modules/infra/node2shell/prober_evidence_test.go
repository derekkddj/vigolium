package node2shell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestProberOwnsPerProbeFullReceiptSeparateFromLegacyProjection(t *testing.T) {
	var hits atomic.Int64
	written := make(chan struct{}, 2)
	received := make(chan []byte, 2)
	body := strings.Repeat("complete response ", 400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body) // also permits the stream's 100-continue write
		if err != nil {
			t.Errorf("read probe body: %v", err)
			return
		}
		received <- requestBody
		// A final answer without reading an Expect: 100-continue body can
		// legitimately leave request evidence missing. This full-capture fixture
		// instead waits for the actual write trace before returning its answer.
		select {
		case <-written:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("X-Probe-Sequence", fmt.Sprint(hits.Add(1)))
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				written <- struct{}{}
			}
		},
	})
	client := modtest.Requester(t).WithContext(ctx)
	p, ok := NewProber(modtest.Request(t, srv.URL+"/input"), client, "POST", "/probe", "application/json")
	require.True(t, ok)
	first, ok := p.Send(ContentEncoding, "br", []byte("small first probe"))
	require.True(t, ok)
	x := first.Receipt
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
	require.Equal(t, evidence.StateComplete, x.RequestState)
	require.Equal(t, evidence.StateComplete, x.ResponseState)
	require.Contains(t, string(x.Request), "POST /probe HTTP/")
	require.Contains(t, string(x.Request), "small first probe")
	require.Contains(t, string(x.Response), "X-Probe-Sequence: 1")
	require.True(t, strings.HasSuffix(string(x.Response), body))
	require.LessOrEqual(t, len(first.Response), maxEvidenceBytes+100)
	require.Greater(t, len(x.Response), len(first.Response))
	require.Equal(t, []byte("small first probe"), <-received)
	streamBody := []byte(strings.Repeat("full stream body \x00\xff ", 400))
	second, ok := p.SendStream("br", streamBody)
	require.True(t, ok)
	require.NotNil(t, second.Receipt)
	require.NotEqual(t, x.ID, second.Receipt.ID)
	require.Equal(t, evidence.ProvenanceCaptured, second.Receipt.Provenance)
	require.Equal(t, evidence.StateComplete, second.Receipt.RequestState)
	require.Equal(t, evidence.StateComplete, second.Receipt.ResponseState)
	require.Equal(t, streamBody, <-received, "the server must receive the original binary body")
	require.True(t, bytes.HasSuffix(second.Receipt.Request, streamBody), "receipt retains actual binary bytes, not replay intent")
	require.Less(t, len(second.Request), len(second.Receipt.Request), "elision is only a legacy projection")
	require.Contains(t, string(second.Receipt.Response), "X-Probe-Sequence: 2")
	require.NoError(t, second.Receipt.Validate())
	require.NoError(t, x.Validate(), "later execution/pool reuse must not overwrite the first receipt")
	require.Contains(t, string(x.Response), "X-Probe-Sequence: 1")
	require.Equal(t, int64(2), hits.Load(), "capture must not send report-only traffic")
}
