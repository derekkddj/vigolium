package yamlext

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestYAMLActivePayloadSelectsOwnedProbeBeforeClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Query().Get("id") == "selected" {
			_, _ = w.Write([]byte("probe marker"))
			return
		}
		_, _ = w.Write([]byte("no match"))
	}))
	defer srv.Close()
	client := modtest.Requester(t)
	def := &ExtensionDef{
		ID: "probe-evidence", Name: "Probe evidence", Type: "active",
		ScanTypes: []string{"per_insertion_point"},
		Payloads:  []string{"negative", "selected", "never-sent"},
		Matchers:  []MatcherDef{{Type: "body", Contains: "probe marker"}},
		Finding:   &FindingDef{Name: "Probe matched"},
	}
	m, err := NewYAMLActiveModule(def, nil, client)
	require.NoError(t, err)
	ctx := modtest.Response(modtest.Request(t, srv.URL+"/start?id=baseline"), "text/plain", "probe marker in baseline")
	results, err := m.ScanPerInsertionPoint(ctx, modtest.InsertionPoint(t, ctx, "id"), client, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.Evidence, 1)
	entry := result.Evidence[0]
	require.True(t, entry.Primary)
	require.Equal(t, evidence.RoleAttack, entry.Role)
	require.NotNil(t, entry.Exchange)
	require.NoError(t, entry.Exchange.Validate())
	require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
	require.Equal(t, srv.URL+"/final?id=selected", entry.Exchange.URL)
	require.Contains(t, result.Request, "GET /final?id=selected HTTP/1.1")
	require.NotContains(t, result.Request, "negative")
	require.NotContains(t, result.Request, "baseline")
	require.Contains(t, result.Response, "probe marker")
	require.Equal(t, string(entry.Exchange.Request), result.Request)
	require.Equal(t, string(entry.Exchange.Response), result.Response)
}

func TestYAMLActiveReadOnlyBranchesDeclareInputEvidence(t *testing.T) {
	for _, mode := range []string{"flat", "rules", "host"} {
		t.Run(mode, func(t *testing.T) {
			def := &ExtensionDef{
				ID: "input-evidence", Name: "Input evidence", Type: "active",
				ScanTypes: []string{"per_request"},
				Matchers:  []MatcherDef{{Type: "body", Contains: "marker"}},
				Finding:   &FindingDef{Name: "Input matched"},
			}
			if mode == "rules" {
				def.Rules = []RuleDef{{Match: RuleMatchDef{BodyRegex: "marker"}, Finding: FindingDef{Name: "Rule matched"}}}
			}
			m, err := NewYAMLActiveModule(def, nil, nil)
			require.NoError(t, err)
			ctx := makeRequestResponse("GET", "/input", 200, nil, "marker")
			input := evidence.NewExchange("http://example.com", ctx.Target(), ctx.Request().Raw(), []byte("HTTP/1.1 200 OK\r\n\r\nmarker plus unmodified original"), evidence.ProvenanceSupplied)
			ctx = ctx.WithEvidence(input)
			results, err := m.ScanPerRequest(ctx, nil, nil)
			if mode == "host" {
				results, err = m.ScanPerHost(ctx, nil, nil)
			}
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.True(t, results[0].BaselineEvidence)
			require.Len(t, results[0].Evidence, 1)
			require.Equal(t, evidence.RoleObservation, results[0].Evidence[0].Role)
			require.True(t, results[0].Evidence[0].Primary)
			require.Equal(t, input.ID, results[0].Evidence[0].ExchangeID)
			require.Equal(t, string(input.Response), results[0].Response)
			input.Response[0] = 'X'
			require.NoError(t, results[0].Evidence[0].Exchange.Validate())

			// A caller without an input snapshot gets only the positive input
			// analysis declaration; no transport receipt is fabricated here.
			plain := httpmsg.NewHttpRequestResponse(ctx.Request(), ctx.Response())
			results, err = m.ScanPerRequest(plain, nil, nil)
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.True(t, results[0].BaselineEvidence)
			require.Empty(t, results[0].Evidence)
		})
	}
}
