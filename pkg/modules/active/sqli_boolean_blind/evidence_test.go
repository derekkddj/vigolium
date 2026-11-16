package sqli_boolean_blind

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestBooleanReceiptsKeepActualTripletAndBoundedBattery(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		_, _ = fmt.Fprint(w, evalBool(r.URL.Query().Get("id")))
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/item?id=1")
	ip := modtest.InsertionPoint(t, ctx, "id")
	client := modtest.Requester(t)
	m := New()
	baseFull, baseSig, blocked, baseline, err := m.sendPayloadReceipt(ctx, client, ip, "1")
	require.NoError(t, err)
	require.False(t, blocked)
	// Evidence is full HTTP while every comparison remains body-only.
	require.Equal(t, newResponseSignature(http.StatusOK, truePage, "1"), baseSig)
	require.Contains(t, baseFull, "X-Receipt: 1")
	pair := buildMatrixPayloads(true)[0]
	result, err := m.testPayloadPair(ctx, client, ip, "1", pair, baseSig, baseFull, baseline)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 9)
	require.LessOrEqual(t, len(result.AdditionalEvidence), modkit.MaxEvidencePairs)
	roles := []evidence.Role{evidence.RoleAttack, evidence.RoleBaseline, evidence.RoleControl, evidence.RoleConfirmation, evidence.RoleControl}
	values := []string{"1" + pair.trueVal, "1", "1" + pair.falseVal, "1" + pair.trueVal, "1" + pair.falseVal}
	ids := map[string]bool{}
	for i, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, ids[entry.ExchangeID], "fresh replays must keep distinct identities")
		ids[entry.ExchangeID] = true
		require.Contains(t, string(entry.Exchange.Response), "X-Receipt:")
		if i < len(roles) {
			require.Equal(t, roles[i], entry.Role)
			u, err := url.Parse(entry.Exchange.URL)
			require.NoError(t, err)
			require.Equal(t, values[i], u.Query().Get("id"))
		}
	}
	require.True(t, result.Evidence[0].Primary)
	require.Contains(t, result.Response, "X-Receipt: 2", "primary is the first TRUE, not the last call")
	require.Contains(t, result.Response, truePage)
	require.Equal(t, evidence.RoleControl, result.Evidence[len(result.Evidence)-1].Role)
	require.Contains(t, result.Evidence[len(result.Evidence)-1].Label, "invalid SQL syntax")
	// One baseline, the triplet/retries, baseline drift, logic selection, three
	// full battery rounds and invalid syntax still run; retaining fewer receipts
	// must never reduce the detection battery.
	require.Equal(t, int32(15), hits.Load())
}

func TestStatusOracleCompatibilityReservesSuppliedTripletSlots(t *testing.T) {
	srv := httptest.NewServer(statusOracleHandler())
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/item?id=1")
	ip := modtest.InsertionPoint(t, ctx, "id")
	pair := getPayloadsForValue("1")[0]
	const baseFull = "HTTP/1.1 200 OK\r\nX-Supplied: baseline\r\n\r\n" + truePage
	const trueFull = "HTTP/1.1 200 OK\r\nX-Supplied: true\r\n\r\n" + truePage
	const falseFull = "HTTP/1.1 404 Not Found\r\nX-Supplied: false\r\n\r\n" + falsePage
	result, err := New().confirmStatusOracle(ctx, modtest.Requester(t), ip, "1", pair,
		newResponseSignature(200, truePage, "1"), baseFull, trueFull, falseFull,
		newResponseSignature(404, falsePage, "1"+pair.falseVal))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 10)
	require.LessOrEqual(t, len(result.AdditionalEvidence), modkit.MaxEvidencePairs)
	for _, entry := range result.Evidence[:3] {
		require.Equal(t, evidence.ProvenanceSupplied, entry.Exchange.Provenance)
	}
	require.Equal(t, trueFull, result.Response, "actual replay must not slide into the original TRUE slot")
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	require.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
	require.Equal(t, evidence.RoleControl, result.Evidence[2].Role)
	for _, entry := range result.Evidence[3:] {
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.NoError(t, entry.Exchange.Validate())
	}
	require.Equal(t, evidence.RoleControl, result.Evidence[4].Role)
	require.Contains(t, strings.Join(result.AdditionalEvidence, "\n"), "syntax-break control")
}
