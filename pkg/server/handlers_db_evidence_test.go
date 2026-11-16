package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func newGenericDBTestApp(t *testing.T, db *database.DB, repo *database.Repository) *fiber.App {
	t.Helper()
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(repo))
	app.Get("/api/db/tables", h.HandleListDBTables)
	app.Get("/api/db/tables/:table/columns", h.HandleListDBTableColumns)
	app.Get("/api/db/tables/:table/records", h.HandleListDBRecords)
	app.Get("/api/db/tables/:table/records/:id", h.HandleGetDBRecord)
	app.Post("/api/db/tables/:table/records", h.HandleCreateDBRecord)
	app.Put("/api/db/tables/:table/records/:id", h.HandleUpdateDBRecord)
	app.Delete("/api/db/tables/:table/records/:id", h.HandleDeleteDBRecord)
	return app
}

func TestGenericDBEvidenceAccessDeniedAcrossProjects(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	const foreignProject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const secret = "FOREIGN-RECEIPT-SECRET"
	require.NoError(t, repo.CreateProject(ctx, &database.Project{UUID: foreignProject, Name: "foreign", OwnerUUID: database.DefaultUserUUID}))
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte(secret+"\xff\x00"), evidence.ProvenanceCaptured)
	for _, project := range []string{database.DefaultProjectUUID, foreignProject} {
		f := &database.Finding{ProjectUUID: project, FindingHash: "generic-denial", ModuleID: "test", ModuleName: "Test", Severity: "low", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, secret)}}
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}
	var associationID int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT MIN(id) FROM finding_evidence").Scan(&associationID))
	app := newGenericDBTestApp(t, db, repo)
	for _, headers := range []map[string]string{nil, {"X-Project-UUID": foreignProject}} {
		for _, table := range []string{"evidence_exchanges", "finding_evidence"} {
			id := x.ID
			if table == "finding_evidence" {
				id = fmt.Sprint(associationID)
			}
			base := "/api/db/tables/" + table + "/records"
			for _, request := range []struct {
				method string
				path   string
				body   string
			}{
				{http.MethodGet, base, ""},
				{http.MethodGet, base + "?all_projects=true&columns=id&truncate=1", ""},
				{http.MethodGet, base + "/" + id, ""},
				{http.MethodPost, base, `{"label":"injected"}`},
				{http.MethodPut, base + "/" + id, `{"label":"changed"}`},
				{http.MethodDelete, base + "/" + id, ""},
			} {
				resp, body := doReq2(t, app, request.method, request.path, request.body, headers)
				require.Equal(t, http.StatusForbidden, resp.StatusCode, "%s %s: %s", request.method, request.path, body)
				require.NotContains(t, string(body), secret)
				require.NotContains(t, string(body), base64.StdEncoding.EncodeToString(x.Response))
			}
			resp, body := doReq2(t, app, http.MethodGet, "/api/db/tables/"+table+"/columns", "", headers)
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
			require.NotContains(t, string(body), secret)
		}
	}
	resp, body := doReq2(t, app, http.MethodGet, "/api/db/tables", "", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	require.Contains(t, string(body), "evidence_exchanges")
	require.Contains(t, string(body), "finding_evidence")
	require.NotContains(t, string(body), secret)
	for _, project := range []string{database.DefaultProjectUUID, foreignProject} {
		stored, err := repo.GetEvidenceExchange(ctx, x.ID, project)
		require.NoError(t, err)
		require.Equal(t, x.Response, stored.Response)
	}
}

func TestGenericDBHTTPRecordExchangeImmutableMetadataScoped(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	const foreignProject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	require.NoError(t, repo.CreateProject(ctx, &database.Project{UUID: foreignProject, Name: "foreign", OwnerUUID: database.DefaultUserUUID}))
	rr, err := httpmsg.ParseRawRequest("GET /original HTTP/1.1\r\nHost: app.test\r\n\r\n")
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\noriginal\x00\xff")))
	ownID, err := repo.SaveRecord(ctx, rr, "test", database.DefaultProjectUUID)
	require.NoError(t, err)
	foreignID, err := repo.SaveRecord(ctx, rr, "test", foreignProject)
	require.NoError(t, err)
	before, err := repo.GetRecordByUUID(ctx, ownID)
	require.NoError(t, err)
	app := newGenericDBTestApp(t, db, repo)
	base := "/api/db/tables/http_records/records"
	for _, column := range []string{
		"raw_request", "raw_response", "method", "hostname", "path", "url", "scheme", "port",
		"request_hash", "response_hash", "has_response", "http_version", "status_code", "status_phrase",
		"request_content_type", "response_content_type", "request_content_length", "response_content_length",
		"response_http_version", "response_location", "request_authorization", "sent_at", "received_at", "body_compaction", "project_uuid",
	} {
		t.Run(column, func(t *testing.T) {
			payload, err := json.Marshal(map[string]interface{}{column: "changed", "risk_score": 99})
			require.NoError(t, err)
			resp, body := doReq2(t, app, http.MethodPut, base+"/"+ownID, string(payload), nil)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "%s", body)
		})
	}
	after, err := repo.GetRecordByUUID(ctx, ownID)
	require.NoError(t, err)
	require.Equal(t, before, after, "denied mixed updates must be atomic")
	resp, body := doReq2(t, app, http.MethodPost, base, `{"raw_request":"supplied","url":"https://app.test"}`, nil)
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "%s", body)

	resp, body = doReq2(t, app, http.MethodPut, base+"/"+ownID, `{"risk_score":42,"parent_uuid":"parent","remarks":"[\"reviewed\"]"}`, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	after, err = repo.GetRecordByUUID(ctx, ownID)
	require.NoError(t, err)
	require.Equal(t, 42, after.RiskScore)
	require.Equal(t, "parent", after.ParentUUID)
	require.Equal(t, []string{"reviewed"}, after.Remarks)
	require.Equal(t, before.RawRequest, after.RawRequest)
	require.Equal(t, before.RawResponse, after.RawResponse)
	require.Equal(t, before.URL, after.URL)

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		payload := ""
		if method == http.MethodPut {
			payload = `{"risk_score":99}`
		}
		resp, body := doReq2(t, app, method, base+"/"+foreignID+"?all_projects=true", payload, nil)
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "%s %s", method, body)
	}
	foreign, err := repo.GetRecordByUUID(ctx, foreignID)
	require.NoError(t, err)
	require.Zero(t, foreign.RiskScore)
	resp, body = doReq2(t, app, http.MethodPut, base+"/"+foreignID, `{"risk_score":7}`, map[string]string{"X-Project-UUID": foreignProject})
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	foreign, err = repo.GetRecordByUUID(ctx, foreignID)
	require.NoError(t, err)
	require.Equal(t, 7, foreign.RiskScore)
}
