package graphql_scan

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/graphqlx"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestGraphQLSendEvidenceOwnsExactOperation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Observed", r.URL.RawQuery)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	seed := modtest.Request(t, srv.URL+"/input-only")
	client, m := modtest.Requester(t), New()
	payload := `{"query":"{ first }"}`
	first, err := m.send(seed, client, "POST", "/graphql?round=1", "application/json", payload)
	require.NoError(t, err)
	require.NotNil(t, first.Exchange)
	original := first.Exchange.Clone()
	_, err = m.send(seed, client, "POST", "/graphql?round=2", "application/json", `{"query":"{ second }"}`)
	require.NoError(t, err)
	require.Equal(t, original, first.Exchange)
	parsed, err := httpmsg.FromEvidenceExchange(first.Exchange)
	require.NoError(t, err)
	require.Equal(t, "/graphql?round=1", parsed.Request().Path())
	require.Equal(t, []byte(payload), parsed.Request().Body())
	require.Equal(t, seed.Service().Port(), parsed.Service().Port())
	require.Contains(t, string(first.Exchange.Response), "X-Observed: round=1")
	proof := &gqlProof{}
	proof.attack(first, payload)
	result := proof.finding(&output.ResultEvent{Request: "seed", Response: "projection"})
	require.Equal(t, string(original.Request), result.Request)
	require.Equal(t, string(original.Response), result.Response)
	require.Equal(t, payload, result.Payload)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
}

// This fixture accepts only its declared byId(id: <string>) operation. Decode
// both the JSON envelope and the GraphQL string literal: QuoteString JSON-escapes
// angle brackets before QueryBody escapes the surrounding GraphQL document.
var xssErrorFixtureArgument = regexp.MustCompile(`^\s*query\s*\{\s*byId\s*\(\s*id\s*:\s*("(?:\\.|[^"\\])*")\s*\)\s*\}\s*$`)

func decodeXSSErrorFixtureMarker(body []byte) (string, error) {
	var envelope struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", err
	}
	argument := xssErrorFixtureArgument.FindStringSubmatch(envelope.Query)
	if len(argument) != 2 {
		return "", fmt.Errorf("unexpected fixture operation: %q", envelope.Query)
	}
	var marker string
	if err := json.Unmarshal([]byte(argument[1]), &marker); err != nil {
		return "", err
	}
	return marker, nil
}

type xssErrorFixtureResponse struct {
	contentType string
	escaped     bool
	absent      bool
}

type xssErrorFixtureOperation struct {
	body   string
	marker string
}

func xssErrorFixture(t *testing.T, responses [2]xssErrorFixtureResponse) (*httptest.Server, <-chan xssErrorFixtureOperation) {
	t.Helper()
	operations := make(chan xssErrorFixtureOperation, len(xssMarkers))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unexpected fixture request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		marker, err := decodeXSSErrorFixtureMarker(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for i, expected := range xssMarkers {
			if marker != expected {
				continue
			}
			operations <- xssErrorFixtureOperation{body: string(body), marker: marker}
			response := responses[i]
			w.Header().Set("Content-Type", response.contentType)
			if response.absent {
				marker = "argument rejected without reflection"
			}
			if response.contentType == "text/html" {
				if response.escaped {
					marker = html.EscapeString(marker)
				}
				_, _ = fmt.Fprintf(w, "<html><body>Argument error: %s</body></html>", marker)
			} else {
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(response.escaped)
				_ = encoder.Encode(map[string]any{"errors": []map[string]string{{"message": "Argument error: " + marker}}})
			}
			return
		}
		http.Error(w, "unexpected fixture marker", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	return srv, operations
}

func xssErrorFixtureSchema(t *testing.T) *graphqlx.Schema {
	t.Helper()
	schema, ok := graphqlx.ParseSchema([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"byId","args":[{"name":"id","type":{"kind":"SCALAR","name":"Int","ofType":null}}],"type":{"kind":"SCALAR","name":"String","ofType":null}}]}]}}}`))
	require.True(t, ok)
	require.Len(t, collectXSSCandidates(schema), 1)
	return schema
}

func TestXSSErrorSelectsReceiptEstablishingHTMLContext(t *testing.T) {
	schema := xssErrorFixtureSchema(t)
	srv, operations := xssErrorFixture(t, [2]xssErrorFixtureResponse{{contentType: "application/json"}, {contentType: "text/html"}})
	result := New().phaseXSSError(modtest.Request(t, srv.URL), modtest.Requester(t), "/graphql", schema, srv.URL)
	require.Len(t, operations, len(xssMarkers), "both semantic argument values must reach the loopback server")
	first, second := <-operations, <-operations
	require.Equal(t, xssMarkers[0], first.marker)
	require.Equal(t, xssMarkers[1], second.marker)
	require.Contains(t, second.body, `\\u003c`, "the HTTP body carries an escaped GraphQL string, not a raw HTML marker")
	require.NotNil(t, result)
	require.Equal(t, severity.Medium, result.Info.Severity)
	require.Equal(t, output.RecordKindCandidate, result.RecordKind)
	require.Equal(t, second.body, result.Payload)
	require.Contains(t, result.Response, "Content-Type: text/html")
	require.Contains(t, result.Response, xssMarkers[1])
	require.Len(t, result.Evidence, 2)
	require.True(t, result.Evidence[0].Primary)
	primary, err := httpmsg.FromEvidenceExchange(result.Evidence[0].Exchange)
	require.NoError(t, err)
	require.Equal(t, second.body, string(primary.Request().Body()))
	require.Equal(t, evidence.RoleConfirmation, result.Evidence[1].Role)
	confirmation, err := httpmsg.FromEvidenceExchange(result.Evidence[1].Exchange)
	require.NoError(t, err)
	require.Equal(t, first.body, string(confirmation.Request().Body()))
	require.Contains(t, string(result.Evidence[1].Exchange.Response), "Content-Type: application/json")
	require.Contains(t, string(result.Evidence[1].Exchange.Response), xssMarkers[0])
	require.NotEqual(t, result.Evidence[0].ExchangeID, result.Evidence[1].ExchangeID)
}

func TestXSSErrorRequiresBothVerbatimReflections(t *testing.T) {
	cases := []struct {
		name      string
		responses [2]xssErrorFixtureResponse
		want      bool
		requests  int
	}{
		{"raw JSON reflections", [2]xssErrorFixtureResponse{{contentType: "application/json"}, {contentType: "application/json"}}, true, 2},
		{"JSON unicode-escaped first marker", [2]xssErrorFixtureResponse{{contentType: "application/json", escaped: true}, {contentType: "text/html"}}, false, 1},
		{"HTML entity-escaped second marker", [2]xssErrorFixtureResponse{{contentType: "application/json"}, {contentType: "text/html", escaped: true}}, false, 2},
		{"missing second marker", [2]xssErrorFixtureResponse{{contentType: "application/json"}, {contentType: "text/html", absent: true}}, false, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, operations := xssErrorFixture(t, tc.responses)
			result := New().phaseXSSError(modtest.Request(t, srv.URL), modtest.Requester(t), "/graphql", xssErrorFixtureSchema(t), srv.URL)
			require.Len(t, operations, tc.requests)
			if !tc.want {
				require.Nil(t, result, "only raw angle brackets in both responses establish reflection")
				return
			}
			require.NotNil(t, result)
			require.Equal(t, severity.Low, result.Info.Severity)
			require.Equal(t, output.RecordKindObservation, result.RecordKind)
			require.Len(t, result.Evidence, len(xssMarkers))
			require.Contains(t, result.Response, xssMarkers[0])
			require.Contains(t, string(result.Evidence[1].Exchange.Response), xssMarkers[1])
		})
	}
}

func TestGraphQLProofDoesNotRepairMissingReceipts(t *testing.T) {
	missing := (&gqlProof{}).finding(&output.ResultEvent{Request: "input request", Response: "input response"})
	require.Equal(t, "missing", missing.EvidenceStatus)
	require.Empty(t, missing.Request)
	require.Empty(t, missing.Response)
	require.False(t, missing.BaselineEvidence)
	x := evidence.NewExchange("http://destination.example:8080", "", nil,
		[]byte("HTTP/1.1 200 OK\r\n\r\nactual-response"), evidence.ProvenanceCaptured)
	result := (&gqlProof{primary: x}).observation(&output.ResultEvent{Request: "input request"})
	require.Empty(t, result.Request)
	require.Equal(t, "missing", result.EvidenceStatus)
	require.Equal(t, string(x.Response), result.Response)
	require.Equal(t, evidence.StateMissing, result.Evidence[0].Exchange.RequestState)
}
