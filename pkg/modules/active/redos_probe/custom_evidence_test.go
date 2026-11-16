package redos_probe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCustomEvidenceKeepsRepresentativeTimingOperations(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(hits.Add(1)))
		if match := attackRe.FindStringSubmatch(r.URL.Query().Get("email")); len(match) == 2 {
			switch len(match[1]) {
			case 32:
				time.Sleep(100 * time.Millisecond)
			case 64:
				time.Sleep(800 * time.Millisecond)
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	seed := modtest.Response(modtest.Request(t, srv.URL+"/?email=a%40b.com"), "text/plain", "ok")
	m := New()
	m.minFloor = testFloor
	results, err := m.ScanPerInsertionPoint(seed, modtest.InsertionPoint(t, seed, "email"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	// Four floor requests, three two-request escalation steps, two triples.
	wantSends := baselineSamples + 2*len(lengths) + 3*confirmRounds
	assert.EqualValues(t, wantSends, hits.Load())
	f := results[0]
	assert.Equal(t, ModuleSeverity, f.Info.Severity)
	assert.Equal(t, ModuleConfidence, f.Info.Confidence)
	require.True(t, f.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
	assert.Contains(t, f.Response, fmt.Sprintf("X-Receipt-Seq: %d", wantSends))
	assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
	assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
	floorCount, escalationCount, confirmationCount, contextCount := 0, 0, 0, 0
	ids := map[string]bool{}
	for _, entry := range f.Evidence {
		if !entry.Primary {
			contextCount++
		}
		if entry.Exchange.Provenance != evidence.ProvenanceCaptured {
			continue // The supplied original baseline remains supplied.
		}
		assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		assert.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
		switch {
		case strings.HasPrefix(entry.Label, "timing floor sample"):
			floorCount++
			assert.Equal(t, evidence.RoleControl, entry.Role)
			assert.Contains(t, string(entry.Exchange.Response), "X-Receipt-Seq: "+strconv.Itoa(floorCount))
		case entry.Label == "decisive escalation control":
			escalationCount++
			assert.Equal(t, evidence.RoleControl, entry.Role)
			assert.Contains(t, string(entry.Exchange.Response), "X-Receipt-Seq: 9")
		case entry.Label == "decisive escalation attack":
			escalationCount++
			assert.Equal(t, evidence.RoleAttack, entry.Role)
			assert.Contains(t, string(entry.Exchange.Response), "X-Receipt-Seq: 10")
		case strings.HasPrefix(entry.Label, "timing round"):
			confirmationCount++
			if strings.HasSuffix(entry.Label, "control") {
				assert.Equal(t, evidence.RoleControl, entry.Role)
			} else if strings.HasSuffix(entry.Label, "high replay") {
				assert.Equal(t, evidence.RoleConfirmation, entry.Role)
				assert.Contains(t, string(entry.Exchange.Response), "X-Receipt-Seq: 13")
			} else {
				assert.Equal(t, evidence.RoleAttack, entry.Role)
			}
		}
	}
	assert.Equal(t, 2, floorCount, "remaining capacity keeps the first two actual floor samples")
	assert.Equal(t, 2, escalationCount)
	assert.Equal(t, 5, confirmationCount, "the last high is already the primary")
	assert.Equal(t, modkit.MaxEvidencePairs, contextCount)
	assert.LessOrEqual(t, len(f.AdditionalEvidence), modkit.MaxEvidencePairs)
}

func TestCustomEvidenceAttackFailureUsesAvailableNativeReceipt(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	rr := modtest.Response(modtest.Request(t, srv.URL+"/?email=seed"), "text/plain", "supplied baseline only")
	client := modtest.Requester(t)
	p := prober{m: New(), ctx: rr, ip: modtest.InsertionPoint(t, rr, "email"), client: client}
	proof, err := p.timed(attack(16), true)
	require.NoError(t, err, "an attack failure still contributes its existing timing observation")
	// A timing probe is sent once (modkit.SendTimed forbids retries); retaining
	// evidence must not add another execution.
	assert.EqualValues(t, 1, hits.Load())
	assert.EqualValues(t, 1, client.RequestsSent())
	require.NotNil(t, proof.exchange)
	assert.Equal(t, evidence.ProvenanceCaptured, proof.exchange.Provenance)
	assert.Equal(t, evidence.StateComplete, proof.exchange.RequestState)
	assert.Equal(t, evidence.StateMissing, proof.exchange.ResponseState)
	assert.Contains(t, string(proof.exchange.Request), strings.Repeat("a", 16))
	assert.Empty(t, proof.exchange.Response)
	result := p.result([]round{{control: time.Millisecond, low: 10 * time.Millisecond, high: time.Second}}, proof, 8, 16, time.Millisecond)
	require.NotEmpty(t, result.Evidence)
	assert.True(t, result.Evidence[0].Primary)
	assert.Equal(t, proof.exchange.ID, result.Evidence[0].ExchangeID)
	assert.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	assert.Equal(t, string(proof.exchange.Request), result.Request)
	assert.Empty(t, result.Response)
	assert.Equal(t, "missing", result.EvidenceStatus)
	assert.False(t, result.BaselineEvidence)
}
