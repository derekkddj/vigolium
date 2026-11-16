package sqli_error_based

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestErrorBaselineHelperKeepsActualReceiptWithoutUpgradingInput(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Receipt", "baseline")
		_, _ = fmt.Fprint(w, "original body")
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/item?id=1")
	client := modtest.Requester(t)
	var receipt *evidence.Exchange
	body := getResponseBodyIfNotResponsive(ctx, client, &receipt)
	require.Equal(t, "original body", body)
	require.NotNil(t, receipt)
	require.NoError(t, receipt.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, receipt.Provenance)
	require.Contains(t, string(receipt.Response), "X-Receipt: baseline")
	ctx = modtest.Response(ctx, "text/plain", "supplied baseline")
	body = getResponseBodyIfNotResponsive(ctx, client, &receipt)
	require.Equal(t, "supplied baseline", body)
	require.Nil(t, receipt, "input comparison data is not a newly captured baseline send")
	require.Equal(t, int32(1), hits.Load())
}

func TestErrorFindingKeepsExplicitConfirmationSinkReceipts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if strings.ContainsAny(r.URL.Query().Get("id"), `'")\`) {
			_, _ = fmt.Fprint(w, mysqlSyntaxError)
			return
		}
		_, _ = fmt.Fprint(w, "clean original value")
	}))
	defer srv.Close()
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/?id=1"), "text/plain", "supplied comparison input")
	results, err := New().ScanPerInsertionPoint(ctx, modtest.InsertionPoint(t, ctx, "id"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	require.Equal(t, int32(3*len(results)), hits.Load(), "initial payload, signature replay and fresh original control only")
	for i, result := range results {
		require.Len(t, result.Evidence, 4)
		require.True(t, result.Evidence[0].Primary)
		require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
		require.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
		require.Equal(t, evidence.ProvenanceSupplied, result.Evidence[1].Exchange.Provenance)
		require.Equal(t, evidence.RoleConfirmation, result.Evidence[2].Role)
		require.Equal(t, evidence.RoleControl, result.Evidence[3].Role)
		for _, index := range []int{0, 2, 3} {
			x := result.Evidence[index].Exchange
			require.NotNil(t, x)
			require.NoError(t, x.Validate())
			require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
			require.Contains(t, string(x.Response), "X-Receipt:")
		}
		require.NotEqual(t, result.Evidence[0].ExchangeID, result.Evidence[2].ExchangeID)
		require.Equal(t, string(result.Evidence[0].Exchange.Request), result.Request)
		require.Equal(t, string(result.Evidence[0].Exchange.Response), result.Response)
		require.Contains(t, result.Response, fmt.Sprintf("X-Receipt: %d", 3*i+1))
		require.Contains(t, string(result.Evidence[2].Exchange.Response), fmt.Sprintf("X-Receipt: %d", 3*i+2))
		require.Contains(t, string(result.Evidence[3].Exchange.Response), fmt.Sprintf("X-Receipt: %d", 3*i+3))
	}
}
