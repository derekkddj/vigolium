package nosqli_operator_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestCustomEvidenceKeepsNonAnalyzableInertnessPrecheck(t *testing.T) {
	var hits atomic.Int32
	trueBody := strings.Repeat("alpha bravo charlie delta echo foxtrot ", 20)
	falseBody := strings.Repeat("zulu yankee xray whiskey victor uniform ", 20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(n))
		if n == 1 {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("non-analyzable precheck"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if injectedConditionIsFalse(r.Header.Get("X-Query")) {
			_, _ = w.Write([]byte(falseBody))
			return
		}
		_, _ = w.Write([]byte(trueBody))
	}))
	defer srv.Close()
	seed := modtest.Request(t, srv.URL+"/search")
	raw, err := httpmsg.AddOrReplaceHeader(seed.Request().Raw(), "X-Query", "seed")
	require.NoError(t, err)
	rr := modtest.Response(httpmsg.NewRequestResponseRaw(raw, seed.Service()), "text/plain", trueBody)
	ip := modtest.InsertionPoint(t, rr, "X-Query")
	require.Equal(t, httpmsg.INS_HEADER, ip.Type())
	f, err := New().testBooleanDiff(rr, ip, modtest.Requester(t), trueBody)
	require.NoError(t, err)
	require.NotNil(t, f, "a non-analyzable precheck still fails open")
	assert.EqualValues(t, 1+2*(boolTrueSamples+boolFalseSamples+boolNeutralSamples), hits.Load())
	assert.True(t, f.Evidence[0].Primary)
	assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
	assert.Contains(t, f.Response, "X-Receipt-Seq: 2")
	assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
	assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
	found := false
	for _, entry := range f.Evidence {
		if entry.Label != "benign insertion-point relevance precheck" {
			continue
		}
		found = true
		assert.False(t, entry.Primary)
		assert.Equal(t, evidence.RoleControl, entry.Role)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		assert.Contains(t, string(entry.Exchange.Response), "X-Receipt-Seq: 1")
		assert.Contains(t, string(entry.Exchange.Response), "application/octet-stream")
		assert.Contains(t, string(entry.Exchange.Request), benignProbeSuffix)
		assert.NotEqual(t, f.Evidence[0].ExchangeID, entry.ExchangeID)
	}
	assert.True(t, found)
}
