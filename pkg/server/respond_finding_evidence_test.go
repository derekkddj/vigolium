package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// Single selected receipts stay objects in both API versions. The request and
// response fields are base64 strings, not lossy text or a list envelope.
func TestFindingEvidenceObjectContractV1AndV2(t *testing.T) {
	fixture, err := os.ReadFile("testdata/finding_evidence.json")
	require.NoError(t, err)
	var exchange evidence.Exchange
	require.NoError(t, json.Unmarshal(fixture, &exchange))
	require.NoError(t, exchange.Validate())
	require.Equal(t, []byte("POST /proof HTTP/1.1\r\nHost: app.test\r\nContent-Length: 2\r\n\r\n\x00\xff"), exchange.Request)
	require.Equal(t, []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n\xff\x00proof"), exchange.Response)

	db, repo := newPinnedTestDB(t)
	finding := &database.Finding{
		ProjectUUID: database.DefaultProjectUUID, FindingHash: "object-contract-proof",
		ModuleID: "test", ModuleName: "Test", EvidenceStatus: "selected",
		Evidence: []evidence.Entry{evidence.Select(&exchange, evidence.RoleAttack, true, "proof")},
	}
	require.NoError(t, repo.SaveFindingDirect(context.Background(), finding))
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Use(apiVersionMiddleware(1))
	app.Use(ProjectUUIDMiddleware(repo))
	app.Get("/api/findings/:id/evidence/:exchange_id", h.findingsHandler().HandleGetFindingEvidence)
	path := fmt.Sprintf("/api/findings/%d/evidence/%s", finding.ID, exchange.ID)
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			resp, raw := doReq2(t, app, http.MethodGet, path, "", map[string]string{
				apicontract.RESTAPIVersionHeader: fmt.Sprint(version),
			})
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s", raw)
			require.Equal(t, fmt.Sprint(version), resp.Header.Get(apicontract.RESTAPIVersionHeader))
			require.Contains(t, resp.Header.Get("Content-Type"), "application/json")
			require.JSONEq(t, string(fixture), string(raw))
			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))
			require.Equal(t, base64.StdEncoding.EncodeToString(exchange.Request), body["request"])
			require.Equal(t, base64.StdEncoding.EncodeToString(exchange.Response), body["response"])
			for _, envelopeField := range []string{"items", "data", "schema_version", "kind"} {
				require.NotContains(t, body, envelopeField)
			}
			var got evidence.Exchange
			require.NoError(t, json.Unmarshal(raw, &got))
			require.Equal(t, exchange.Request, got.Request)
			require.Equal(t, exchange.Response, got.Response)
			require.NoError(t, got.Validate())
		})
	}
}

func TestSwaggerFindingEvidenceObjectAndByteContract(t *testing.T) {
	doc := loadSwaggerDoc(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	properties := func(name string) map[string]any {
		t.Helper()
		return schemas[name].(map[string]any)["properties"].(map[string]any)
	}
	exchange := properties("EvidenceExchange")
	for _, name := range []string{"request", "response"} {
		field := exchange[name].(map[string]any)
		require.Equal(t, "string", field["type"], name)
		require.Equal(t, "byte", field["format"], "%s must document base64 bytes", name)
	}
	manifest := properties("Finding")["evidence"].(map[string]any)
	require.Equal(t, "array", manifest["type"])
	require.Equal(t, "#/components/schemas/EvidenceEntry", manifest["items"].(map[string]any)["$ref"])
	require.Contains(t, properties("Finding"), "evidence_status")
	require.Contains(t, properties("VerifyFindingResult"), "unclassified_matched")
	paths := doc["paths"].(map[string]any)
	operation := paths["/api/findings/{id}/evidence/{exchange_id}"].(map[string]any)["get"].(map[string]any)
	response := operation["responses"].(map[string]any)["200"].(map[string]any)
	body := response["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	require.Equal(t, "#/components/schemas/EvidenceExchange", body["$ref"])
	require.NotContains(t, body, "items")
}
