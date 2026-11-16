package jsext

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestGraphQLSchemaPreservesShapeAndExposesSameReceipt(t *testing.T) {
	const schemaBody = `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT"}]}}}`
	for _, withSession := range []bool{false, true} {
		t.Run(fmt.Sprintf("session_%v", withSession), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/graphql", http.StatusTemporaryRedirect)
					return
				}
				if r.URL.Path == "/last" {
					_, _ = io.WriteString(w, "unselected last call")
					return
				}
				if withSession && r.Header.Get("Authorization") != "Bearer selected-session" {
					t.Errorf("GraphQL request lost session headers: %v", r.Header)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, schemaBody)
			}))
			defer srv.Close()
			vm := sobek.New()
			SetupAPI(vm, APIOptions{HTTPClient: modtest.Requester(t)})
			sessionSetup := "var opts = {};"
			if withSession {
				sessionSetup = `var session = vigolium.http.session({headers:{Authorization:'Bearer selected-session'}}); var opts = {session:session};`
			}
			v, err := vm.RunString(fmt.Sprintf(`
				%s
				var schema = vigolium.http.graphqlSchema(%q + '/start', opts);
				var schemaJSON = JSON.stringify(schema);
				var sameHandle = schema.exchange === schema.raw.exchange;
				var rawString = typeof schema.raw.raw;
				var regular = vigolium.http.graphql(%q + '/graphql', {
					query:'{__typename}', session:opts.session
				});
				var unselected = vigolium.http.get(%q + '/last');
				[{url: schema.raw.url, evidence:[{exchange:schema.exchange,role:'observation',primary:true}]}];`, sessionSetup, srv.URL, srv.URL, srv.URL))
			require.NoError(t, err)
			require.True(t, vm.Get("sameHandle").ToBoolean())
			require.Equal(t, "string", vm.Get("rawString").String())
			require.JSONEq(t, `{"queryType":{"name":"Query"},"types":[{"name":"Query","kind":"OBJECT"}]}`, vm.Get("schemaJSON").String())
			keys := vm.Get("schema").ToObject(vm).Keys()
			require.ElementsMatch(t, []string{"queryType", "types"}, keys)
			regularRaw := vm.Get("regular").ToObject(vm).Get("raw").ToObject(vm)
			require.NotNil(t, exchangeFromValue(vm, regularRaw.Get("exchange")))
			require.Contains(t, regularRaw.Get("raw").String(), "HTTP/1.1 200")
			result := parseJSResults(vm, v, nil)[0]
			require.Len(t, result.Evidence, 1)
			x := result.Evidence[0].Exchange
			require.NoError(t, x.Validate())
			require.Equal(t, evidence.ProvenanceCaptured, x.Provenance)
			require.Equal(t, srv.URL+"/graphql", x.URL)
			require.Contains(t, result.Request, "POST /graphql HTTP/1.1")
			require.Contains(t, result.Request, "IntrospectionQuery")
			require.NotContains(t, result.Request, "/last")
			require.Contains(t, result.Response, schemaBody)
			if withSession {
				require.Contains(t, result.Request, "Authorization: Bearer selected-session")
			}
		})
	}
}

func TestGraphQLSchemaWithoutReceiptDoesNotMintOne(t *testing.T) {
	vm := sobek.New()
	resp := vm.NewObject()
	_ = resp.Set("body", `{"data":{"__schema":{"types":[]}}}`)
	_ = resp.Set("raw", "historical raw response")
	value := parseGraphQLSchemaResponse(vm, resp)
	require.False(t, sobek.IsNull(value))
	obj := value.ToObject(vm)
	require.Same(t, resp, obj.Get("raw"))
	require.False(t, isSet(obj.Get("exchange")))
	require.Empty(t, receipts(vm).entries)
	for _, body := range []string{"not JSON", `{"data":null}`, `{"data":{}}`, `{"data":{"__schema":null}}`} {
		_ = resp.Set("body", body)
		require.True(t, sobek.IsNull(parseGraphQLSchemaResponse(vm, resp)), body)
	}
}
