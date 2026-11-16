package reflected_ssti

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCustomEvidenceKeepsBothFreshOperandConfirmations(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(hits.Add(1)))
		_, _ = w.Write([]byte("<html>result: " + evalSSTI(r.URL.Query().Get("q")) + "</html>"))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	results, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.EqualValues(t, 3, hits.Load())
	f := results[0]
	require.Len(t, f.Evidence, 3)
	ids := map[string]bool{}
	for i, entry := range f.Evidence {
		assert.Equal(t, i == 0, entry.Primary)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		assert.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Receipt-Seq: %d", i+1))
		assert.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
		if i > 0 {
			assert.Equal(t, evidence.RoleConfirmation, entry.Role)
			assert.NotEqual(t, string(f.Evidence[0].Exchange.Request), string(entry.Exchange.Request))
		}
	}
	assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
	assert.Contains(t, f.Response, "X-Receipt-Seq: 1")
	assert.Contains(t, f.Response, New().result)
	assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
	assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
}

func TestCustomEvidenceKeepsCompletedFreshOperandMiss(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(n))
		body := "not an evaluation"
		if n == 1 {
			body = evalSSTI(r.URL.Query().Get("q"))
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	proof := modkit.NewEvidenceCollector()
	m := New()
	confirmed, err := m.confirmEvaluation(rr, modtest.InsertionPoint(t, rr, "q"), modtest.Requester(t), m.payloads[0], proof)
	require.NoError(t, err)
	assert.False(t, confirmed)
	assert.EqualValues(t, 2, hits.Load())
	require.Len(t, proof.Evidence(), 2)
	for i, entry := range proof.Evidence() {
		assert.False(t, entry.Primary)
		assert.Equal(t, evidence.RoleConfirmation, entry.Role)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Receipt-Seq: %d", i+1))
	}
	assert.Contains(t, string(proof.Evidence()[1].Exchange.Response), "not an evaluation")
}

func TestCustomEvidenceFreshOperandTransportFailureStillKeepsInitialPrimary(t *testing.T) {
	var hits atomic.Int32
	requests := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.RequestURI
		n := hits.Add(1)
		if n >= 3 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		// A reused connection closed without a response allows net/http to
		// transparently replay this GET before the Requester's configured retry.
		// Fresh sockets isolate the existing retry schedule in this fixture.
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(n))
		_, _ = w.Write([]byte(evalSSTI(r.URL.Query().Get("q"))))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/?q=hello")
	client := modtest.Requester(t)
	results, err := New().ScanPerInsertionPoint(rr, modtest.InsertionPoint(t, rr, "q"), client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1, "fresh-operand transport ambiguity still fails open")
	assert.Equal(t, int32(4), hits.Load(), "initial, first confirmation, second confirmation plus its existing retry")
	assert.Equal(t, int64(4), client.RequestsSent(), "gate attempts equal wire sends with fresh sockets")
	close(requests)
	var targets []string
	for target := range requests {
		targets = append(targets, target)
	}
	require.Len(t, targets, 4)
	assert.NotEqual(t, targets[0], targets[1], "first fresh operands differ from the initial payload")
	assert.NotEqual(t, targets[1], targets[2], "second fresh operands differ from the first confirmation")
	assert.Equal(t, targets[2], targets[3], "only the failed second confirmation is retried")
	f := results[0]
	require.Len(t, f.Evidence, 3)
	assert.True(t, f.Evidence[0].Primary)
	assert.Contains(t, f.Response, "X-Receipt-Seq: 1")
	assert.Equal(t, evidence.RoleConfirmation, f.Evidence[1].Role)
	assert.Contains(t, string(f.Evidence[1].Exchange.Response), "X-Receipt-Seq: 2")
	assert.Equal(t, evidence.RoleConfirmation, f.Evidence[2].Role)
	assert.False(t, f.Evidence[2].Primary)
	require.NotNil(t, f.Evidence[2].Exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, f.Evidence[2].Exchange.Provenance)
	assert.Equal(t, evidence.StateComplete, f.Evidence[2].Exchange.RequestState)
	assert.Contains(t, string(f.Evidence[2].Exchange.Request), "GET "+targets[3]+" HTTP/1.1\r\n")
	assert.NoError(t, f.Evidence[2].Exchange.Validate())
	assert.Equal(t, evidence.StateMissing, f.Evidence[2].Exchange.ResponseState)
	assert.Empty(t, f.Evidence[2].Exchange.Response)
	assert.NotEqual(t, f.Evidence[0].ExchangeID, f.Evidence[1].ExchangeID)
	assert.NotEqual(t, f.Evidence[1].ExchangeID, f.Evidence[2].ExchangeID)
}
