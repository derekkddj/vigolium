package salesforce

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestInvokeActionReceiptOwnsOperationBeforeClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"actions":[{"state":"SUCCESS","returnValue":"` + r.FormValue("aura.context") + `"}]}`))
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL), modtest.Requester(t)
	first := InvokeAction(ctx, client, "/aura", BuildGetConfigData(), "first-context")
	require.True(t, first.OK)
	require.NotNil(t, first.Exchange)
	require.Equal(t, evidence.ProvenanceCaptured, first.Exchange.Provenance)
	require.NoError(t, first.Exchange.Validate())
	owned := first.Exchange.Clone()
	second := InvokeAction(ctx, client, "/aura", BuildGetConfigData(), "second-context")
	require.True(t, second.OK)
	require.NotNil(t, second.Exchange)
	require.NotEqual(t, first.Exchange.ID, second.Exchange.ID)
	require.Equal(t, owned, first.Exchange)
	require.Contains(t, string(first.Exchange.Request), "aura.context=first-context")
	require.Contains(t, string(first.Exchange.Response), "first-context")
	require.Contains(t, string(second.Exchange.Response), "second-context")
}

func TestGatewayReceiptOutputDoesNotReuseEarlierSuccess(t *testing.T) {
	var live atomic.Bool
	live.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if live.Load() {
			_, _ = w.Write([]byte("aura:invalidSession"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	ctx, client := modtest.Request(t, srv.URL), modtest.Requester(t)
	var receipt *evidence.Exchange
	_, ok := FindLiveAuraGateway(ctx, client, &receipt)
	require.True(t, ok)
	require.NotNil(t, receipt)
	live.Store(false)
	_, ok = FindLiveAuraGateway(ctx, client, &receipt)
	require.False(t, ok)
	require.Nil(t, receipt, "a failed new gate has no selected operation")
}
