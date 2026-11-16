package jsext

import (
	"encoding/base64"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestJSEvidenceSelectsOneCallNotLastAndRejectsForgedOrReplayedHandle(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	defer srv.Close()
	vm := sobek.New()
	SetupAPI(vm, APIOptions{HTTPClient: modtest.Requester(t), ProjectUUID: "project-a"})
	val, err := vm.RunString(fmt.Sprintf(`
		var attack = vigolium.http.get(%q + '/attack');
		var unselected = vigolium.http.get(%q + '/last');
		var saved = attack.exchange;
		attack.exchange.request_base64 = 'forged';
		[{url: 'https://finding.example/', payload: 'payload', record_kind:'candidate', evidence_grade:'E2',
		 evidence: [{exchange:attack.exchange, role:'attack', primary:true}], additional_evidence:['context']}];`, srv.URL, srv.URL))
	require.NoError(t, err)
	results := parseJSResults(vm, val, nil)
	require.Len(t, results, 1)
	result := results[0]
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Len(t, result.Evidence, 1)
	require.Contains(t, result.Request, "GET /attack HTTP/1.1")
	require.NotContains(t, result.Request, "/last")
	require.Equal(t, "https://finding.example/", result.URL)
	require.Equal(t, "payload", result.Payload)
	require.Equal(t, "candidate", string(result.RecordKind))
	require.Equal(t, "E2", string(result.EvidenceGrade))
	require.Equal(t, []string{"context"}, result.AdditionalEvidence)
	require.NoError(t, result.Evidence[0].Exchange.Validate())
	for _, script := range []string{
		`[{evidence:[{exchange: JSON.parse(JSON.stringify(saved)), role:'attack',primary:true}]}]`,
		`[{evidence:[{exchange: {id:saved.id}, role:'attack',primary:true}]}]`,
		`[{evidence:[{exchange: saved, role:'invented',primary:true}]}]`,
	} {
		v, err := vm.RunString(script)
		require.NoError(t, err)
		r := parseJSResults(vm, v, nil)[0]
		require.Empty(t, r.Evidence)
		require.Equal(t, "missing", r.EvidenceStatus)
		require.NotEmpty(t, r.Metadata["evidence_error"])
	}
	v, err := vm.RunString(`[{evidence:[{exchange:saved,role:'attack',primary:true},{exchange:unselected.exchange,role:'confirmation',primary:true}]}]`)
	require.NoError(t, err)
	multiple := parseJSResults(vm, v, nil)[0]
	require.Len(t, multiple.Evidence, 1)
	require.Contains(t, multiple.Request, "GET /attack HTTP/1.1")
	require.Equal(t, "multiple primary evidence selections", multiple.Metadata["evidence_error"])
	resetReceipts(vm) // same pooled VM, different invocation/project boundary
	v, err = vm.RunString(`[{evidence:[{exchange:saved,role:'attack',primary:true}]}]`)
	require.NoError(t, err)
	require.Empty(t, parseJSResults(vm, v, nil)[0].Evidence)
}

func TestJSSessionReceiptAfterInterceptorAndRedirect(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/start" {
			stdhttp.Redirect(w, r, "/final", 307)
			return
		}
		require.Equal(t, "Bearer interceptor", r.Header.Get("Authorization"))
		require.Contains(t, r.Header.Get("Cookie"), "session=owned")
		_, _ = w.Write([]byte{'r', 0, 0xff})
	}))
	defer srv.Close()
	vm := sobek.New()
	SetupAPI(vm, APIOptions{HTTPClient: modtest.Requester(t)})
	v, err := vm.RunString(fmt.Sprintf(`
		var s = vigolium.http.session({cookies:{session:'owned'}});
		s.onRequest(function(req) { req.headers.Authorization = 'Bearer interceptor'; req.body = 'changed'; return req; });
		var resp = s.post(%q + '/start', 'before');
		[{evidence:[{exchange:resp.exchange,role:'attack',primary:true}]}];`, srv.URL))
	require.NoError(t, err)
	r := parseJSResults(vm, v, nil)[0]
	require.Len(t, r.Evidence, 1)
	x := r.Evidence[0].Exchange
	require.Equal(t, srv.URL+"/final", x.URL)
	require.Contains(t, string(x.Request), "POST /final HTTP/1.1")
	require.Contains(t, string(x.Request), "Authorization: Bearer interceptor")
	require.Contains(t, string(x.Request), "session=owned")
	require.Contains(t, string(x.Request), "\r\n\r\nchanged")
	encoded := vm.Get("resp").ToObject(vm).Get("exchange").ToObject(vm).Get("response_base64").String()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.Equal(t, x.Response, decoded)
}

func TestJSEvidenceScopeAndBoundedRegistry(t *testing.T) {
	vm := sobek.New()
	scope := config.DefaultScopeConfig()
	scope.Host.Exclude = []string{"outside.example"}
	matcher := config.NewScopeMatcher(*scope)
	SetupAPI(vm, APIOptions{ScopeMatcher: matcher})
	x := evidence.NewExchange("https://outside.example", "https://outside.example/probe", []byte("GET /probe HTTP/1.1\r\nHost: outside.example\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nbody"), evidence.ProvenanceCaptured)
	_ = vm.Set("handle", registerExchange(vm, x))
	v, err := vm.RunString(`[{evidence:[{exchange:handle,role:'attack',primary:true}]}]`)
	require.NoError(t, err)
	r := parseJSResults(vm, v, nil)[0]
	require.Empty(t, r.Evidence)
	require.Equal(t, "exchange outside invocation scope", r.Metadata["evidence_error"])
	for i := 0; i < maxInvocationReceipts+10; i++ {
		registerExchange(vm, x)
	}
	require.Len(t, receipts(vm).entries, maxInvocationReceipts)
	require.Nil(t, exchangeFromValue(vm, vm.Get("handle")))
	resetReceipts(vm)
	require.Empty(t, receipts(vm).entries)
}

func TestJSBaselineContextCannotPretendToBeNewAttack(t *testing.T) {
	vm := sobek.New()
	ctx := modtest.Response(modtest.Request(t, "https://baseline.example/image.png"), "image/png", "binary")
	_ = vm.Set("ctx", buildRequestContext(vm, ctx))
	v, err := vm.RunString(`[{evidence:[{exchange:ctx.exchange,role:'attack',primary:true}]}]`)
	require.NoError(t, err)
	r := parseJSResults(vm, v, ctx)[0]
	require.Empty(t, r.Evidence)
	v, err = vm.RunString(`[{baseline_evidence:true,evidence:[{exchange:ctx.exchange,role:'observation',primary:true}]}]`)
	require.NoError(t, err)
	r = parseJSResults(vm, v, ctx)[0]
	require.Len(t, r.Evidence, 1)
	require.True(t, r.BaselineEvidence)
	require.Equal(t, evidence.StateUnknown, r.Evidence[0].Exchange.RequestState)
	require.Equal(t, evidence.ProvenanceLegacy, r.Evidence[0].Exchange.Provenance)
}

func TestJSLegacyEvidenceIsNotPromotedOrAutomaticallySelected(t *testing.T) {
	vm := sobek.New()
	v, err := vm.RunString(`[{request:'GET / HTTP/1.1',response:'HTTP/1.1 200 OK',evidence:['note',{request:'old',response:'old',note:'historical'}],additional_evidence:['more']}]`)
	require.NoError(t, err)
	r := parseJSResults(vm, v, nil)[0]
	require.Empty(t, r.Evidence)
	require.Len(t, r.AdditionalEvidence, 3)
	require.Equal(t, "missing", r.EvidenceStatus)
}
