package xss_light_scanner

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
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestEncodedReceiptSelectsActualExecutableRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/input" {
			http.Redirect(w, r, "/actual?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		value, _ := url.QueryUnescape(r.URL.Query().Get("q"))
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(value, "alert(") {
			w.Header().Set("X-Receipt", "executable")
		} else {
			w.Header().Set("X-Receipt", "canary")
		}
		_, _ = fmt.Fprint(w, "<html><body>"+value+"</body></html>")
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/input?q=hello")
	ip := modtest.InsertionPoint(t, ctx, "q")
	m := NewEncodedScanner()
	m.base.Probe = nil
	result, err := m.scanInsertionPointEncoded(ctx, ip, modtest.Requester(t))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.BaselineEvidence)
	require.Equal(t, severity.Low, result.Info.Severity)
	require.Len(t, result.Evidence, 3)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleConfirmation, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.Contains(t, primary.Exchange.URL, "/actual?")
	require.Contains(t, result.Request, "GET /actual?")
	require.NotContains(t, result.Request, "GET /input?")
	require.Contains(t, result.Request, "%253C", "the actual encoded send, not a rebuilt raw canary")
	require.Contains(t, result.Response, "X-Receipt: executable")
	require.Contains(t, result.Response, "<svg onload=alert(")
	canary := result.Evidence[1]
	require.False(t, canary.Primary)
	require.Equal(t, evidence.RoleAttack, canary.Role)
	require.Contains(t, string(canary.Exchange.Response), "X-Receipt: canary")
	require.NotEqual(t, primary.ExchangeID, canary.ExchangeID)
}

func TestSecondaryCanaryAndExecutableReceiptsKeepSeparateSends(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		_, _ = fmt.Fprint(w, "<html><body>"+r.URL.Query().Get("q")+"</body></html>")
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/echo?q=hello")
	ip := modtest.InsertionPoint(t, ctx, "q")
	client := modtest.Requester(t)
	scan := NewXSSScanResult()
	scan.PrimaryPayload = GeneratePrimary()
	var err error
	scan.PrimaryResponse, err = sendAndValidatePayload(ctx, ip, scan.PrimaryPayload, client, &scan.PrimaryReceipt)
	require.NoError(t, err)
	scan.SecondaryPayload = GeneratePrimary()
	scan.SecondaryResponse, err = sendAndValidatePayload(ctx, ip, scan.SecondaryPayload, client, &scan.SecondaryReceipt)
	require.NoError(t, err)
	base := buildResultEvent(ctx, ip, scan)
	require.Equal(t, scan.SecondaryReceipt.ID, base.Evidence[0].ExchangeID)
	require.Contains(t, base.Response, "X-Receipt: 2")
	require.Contains(t, base.Response, scan.SecondaryPayload.FullPayload)
	require.Equal(t, scan.PrimaryReceipt.ID, base.Evidence[2].ExchangeID)
	out := sendExec(ctx, ip, execContextCandidates(HTMLGeneric, "vigx123abc")[0], BypassPrefixes[0], "vigx123abc", client, nil)
	require.True(t, out.httpBreakout)
	browserConfirm(executingProbe, &out, out.fuzzedReq)
	require.True(t, out.browserConfirmed)
	result := gradeConfirmedEvent(base, out)
	require.NotNil(t, result)
	require.Equal(t, severity.High, result.Info.Severity)
	require.Len(t, result.Evidence, 4, "dialogs must not manufacture another HTTP receipt")
	require.Equal(t, out.receipt.ID, result.Evidence[0].ExchangeID)
	require.Equal(t, evidence.RoleConfirmation, result.Evidence[0].Role)
	require.Contains(t, result.Response, "X-Receipt: 3")
	require.NotContains(t, result.Response, scan.PrimaryPayload.FullPayload)
	for i, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		if i > 0 {
			require.False(t, entry.Primary)
		}
		require.NotContains(t, entry.Label, "browser-confirm")
	}
	require.Equal(t, int32(3), hits.Load())
}

func TestRejectedCanaryClearsOptionalReceipt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ignored":true}`)
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/echo?q=hello")
	ip := modtest.InsertionPoint(t, ctx, "q")
	receipt := evidence.NewExchange("", "", []byte("earlier request"), []byte("earlier response"), evidence.ProvenanceSupplied)
	body, err := sendAndValidateRawPayload(ctx, ip, "ignored", modtest.Requester(t), &receipt)
	require.NoError(t, err)
	require.Nil(t, body)
	require.Nil(t, receipt, "an earlier successful send must not survive a rejected attempt")
}
