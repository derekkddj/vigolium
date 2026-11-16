package xss_dom_confirm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

func TestDOMReceiptIsHTTPPrefilterNotFragmentNavigation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Receipt", "prefilter")
		_, _ = fmt.Fprint(w, "<html><body>"+r.URL.Query().Get("q")+"</body></html>")
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/echo?q=hello")
	ip := modtest.InsertionPoint(t, ctx, "q")
	payload, err := NewPayload()
	require.NoError(t, err)
	var navigation string
	m := New()
	m.Probe = func(_ context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error) {
		navigation = cfg.URL
		return &spitolas.ProbeResult{Dialogs: []spitolas.DialogEvent{{Type: "alert", Message: payload.Canary}}}, nil
	}
	result, captured := m.attempt(ctx, ip, modtest.Requester(t), ctx.Service().Host(), payload, payload.Body, payload.Hash)
	require.NotNil(t, result)
	require.NotNil(t, captured)
	require.False(t, result.BaselineEvidence)
	require.Contains(t, navigation, "#")
	require.Len(t, result.Evidence, 1, "a dialog is not a browser-navigation HTTP receipt")
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleAttack, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.NoError(t, primary.Exchange.Validate())
	require.Equal(t, captured.receipt.ID, primary.ExchangeID)
	require.Contains(t, primary.Label, "not browser navigation")
	require.NotContains(t, primary.Exchange.URL, "#")
	require.False(t, strings.Contains(result.Request, "#"))
	require.Contains(t, result.Response, "X-Receipt: prefilter")
}
