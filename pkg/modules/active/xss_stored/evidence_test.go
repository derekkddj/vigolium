package xss_stored

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

func TestStoredReceiptsSeparateWriteRetrievalAndBrowser(t *testing.T) {
	gb := &guestbook{persistOnGet: true}
	var hits atomic.Int32
	handler := gb.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		handler(w, r)
	}))
	defer srv.Close()
	ctx := modtest.RequestMethod(t, "POST", srv.URL+"/comment", "c=hello")
	ip := modtest.InsertionPoint(t, ctx, "c")
	results, err := newTestModule().ScanPerInsertionPoint(ctx, ip, modtest.Requester(t), scanCtx())
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 2, "the browser fetch does not supply an HTTP receipt")
	require.Len(t, result.AdditionalEvidence, 1)
	write, retrieval := result.Evidence[0], result.Evidence[1]
	require.True(t, write.Primary)
	require.Equal(t, evidence.RoleAttack, write.Role)
	require.Equal(t, evidence.RoleConfirmation, retrieval.Role)
	require.Contains(t, result.Request, "POST /comment HTTP/")
	require.Contains(t, result.Response, "X-Receipt: 1")
	require.Contains(t, string(retrieval.Exchange.Request), "GET /comment HTTP/")
	require.NotContains(t, string(retrieval.Exchange.Request), "c=hello")
	require.Contains(t, string(retrieval.Exchange.Response), "X-Receipt: 2")
	require.Contains(t, retrieval.Label, "not browser navigation")
	require.NotEqual(t, write.ExchangeID, retrieval.ExchangeID)
	for _, entry := range result.Evidence {
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.NoError(t, entry.Exchange.Validate())
	}
	require.Equal(t, int32(3), hits.Load())
}

func TestStoredAttemptClearsEarlierReceiptWhenNoDialogFires(t *testing.T) {
	gb := &guestbook{persistOnGet: true}
	srv := httptest.NewServer(gb.handler())
	defer srv.Close()
	ctx := modtest.RequestMethod(t, "POST", srv.URL+"/comment", "c=hello")
	ip := modtest.InsertionPoint(t, ctx, "c")
	m := New()
	m.Probe = func(context.Context, spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		return &spitolas.ProbeResult{}, nil
	}
	receipts := storedReceipts{
		write:     evidence.NewExchange("", "", []byte("earlier write"), []byte("earlier response"), evidence.ProvenanceSupplied),
		retrieval: evidence.NewExchange("", "", []byte("earlier retrieval"), []byte("earlier response"), evidence.ProvenanceSupplied),
	}
	dialog, _, stored := m.injectAndConfirm(ctx, ip, modtest.Requester(t), "vigstored-canary", "vigstored-canary", []string{srv.URL + "/comment"}, &receipts)
	require.True(t, stored)
	require.Nil(t, dialog)
	require.Nil(t, receipts.write)
	require.Nil(t, receipts.retrieval)
}
