//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// The shared scenario checks the real listener, REST middleware, database
// association checks and binary JSON boundary, rather than a direct handler call.
func scenarioEvidenceAPI(t *testing.T, env *apiTestEnv) {
	t.Helper()
	ctx := context.Background()
	x := evidence.NewExchange("http://destination.test:8081", "http://destination.test/probe",
		[]byte("POST /probe HTTP/1.1\r\nHost: virtual.test\r\nContent-Length: 999\r\n\r\n\x00\xffrequest"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n\xff\x00response"), evidence.ProvenanceCaptured)
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 123456789, time.UTC)
	x.RequestState, x.ResponseState = evidence.StateTruncated, evidence.StateTruncated
	x.ContentHash = x.Hash()
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "api-binary-proof", ModuleID: "test", ModuleName: "Test", Severity: "low",
		URL: "https://attribution.test/assertion", Request: string(x.Request), Response: string(x.Response), EvidenceStatus: "selected",
		Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "actual selected receipt")}}
	unrelated := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "api-unrelated", ModuleID: "test", ModuleName: "Test", Severity: "low"}
	for _, finding := range []*database.Finding{f, unrelated} {
		require.NoError(t, env.repo.SaveFindingDirect(ctx, finding))
	}
	const foreignProject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	require.NoError(t, env.repo.CreateProject(ctx, &database.Project{UUID: foreignProject, Name: "foreign-evidence", OwnerUUID: database.DefaultUserUUID}))
	foreignExchange := x.Clone()
	foreignExchange.Response = []byte("HTTP/1.1 200 OK\r\n\r\n\x00\xffforeign-project-only")
	foreignExchange.ResponseState = evidence.StateComplete
	foreignExchange.ContentHash = foreignExchange.Hash()
	foreign := &database.Finding{ProjectUUID: foreignProject, FindingHash: "api-foreign", ModuleID: "test", ModuleName: "Test", Severity: "low",
		Evidence: []evidence.Entry{evidence.Select(foreignExchange, evidence.RoleObservation, true, "same ID, different bytes in another project")}}
	require.NoError(t, env.repo.SaveFindingDirect(ctx, foreign))
	traffic, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	trafficID, err := env.repo.SaveRecord(ctx, traffic, database.RecordSourceIngestCLI, database.DefaultProjectUUID)
	require.NoError(t, err)
	get := func(path, project string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.url+path, nil)
		require.NoError(t, err)
		if project != "" {
			req.Header.Set("X-Project-UUID", project)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		expectedVersion := "1"
		if req.URL.Query().Get(apicontract.RESTAPIVersionQuery) == "2" {
			expectedVersion = "2"
		}
		require.Equal(t, expectedVersion, resp.Header.Get(apicontract.RESTAPIVersionHeader), "both REST versions must actually be negotiated")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, body
	}
	for _, version := range []string{"", "?api_version=2"} {
		status, body := get("/api/http-records/"+trafficID+version, "")
		require.Equal(t, http.StatusOK, status)
		var storedTraffic database.HTTPRecord
		require.NoError(t, json.Unmarshal(body, &storedTraffic))
		require.Equal(t, x.RequestState, storedTraffic.CaptureRequestState)
		require.Equal(t, x.ResponseState, storedTraffic.CaptureResponseState)
		require.Equal(t, x.Request, storedTraffic.RawRequest)
		require.Equal(t, x.Response, storedTraffic.RawResponse)
		supplied, err := database.RecordToHttpRequestResponse(&storedTraffic)
		require.NoError(t, err)
		require.Equal(t, evidence.ProvenanceSupplied, supplied.Evidence().Provenance)
		require.NotEqual(t, x.ID, supplied.Evidence().ID)
		require.Equal(t, evidence.StateTruncated, supplied.Evidence().ResponseState)
		status, _ = get("/api/http-records/"+trafficID+version, foreignProject)
		require.Equal(t, http.StatusNotFound, status)
		status, body = get(fmt.Sprintf("/api/findings/%d%s", f.ID, version), "")
		require.Equal(t, http.StatusOK, status)
		var manifest database.Finding
		require.NoError(t, json.Unmarshal(body, &manifest))
		require.Len(t, manifest.Evidence, 1)
		require.Nil(t, manifest.Evidence[0].Exchange, "detail reads must not eagerly load binary messages")
		require.Equal(t, x.ID, manifest.Evidence[0].ExchangeID)
		require.Equal(t, evidence.RoleAttack, manifest.Evidence[0].Role)
		path := fmt.Sprintf("/api/findings/%d/evidence/%s", f.ID, x.ID)
		status, body = get(path+version, "")
		require.Equal(t, http.StatusOK, status)
		var got evidence.Exchange
		require.NoError(t, json.Unmarshal(body, &got))
		require.NoError(t, got.Validate())
		require.Equal(t, x, &got, "binary bytes, destination, framing and nanosecond capture instant must round-trip")
		for _, denied := range []string{
			fmt.Sprintf("/api/findings/%d/evidence/%s", unrelated.ID, x.ID),
			fmt.Sprintf("/api/findings/%d/evidence/%s", foreign.ID, x.ID),
			fmt.Sprintf("/api/findings/%d/evidence/ghost", f.ID),
		} {
			status, _ := get(denied+version, "")
			require.Equal(t, http.StatusNotFound, status, "visible receipt alone cannot authorize another finding")
		}
		status, _ = get(path+version, foreignProject)
		require.Equal(t, http.StatusNotFound, status)
		status, body = get(fmt.Sprintf("/api/findings/%d/evidence/%s%s", foreign.ID, x.ID, version), foreignProject)
		require.Equal(t, http.StatusOK, status)
		require.NoError(t, json.Unmarshal(body, &got))
		require.Equal(t, foreignExchange, &got, "receipt IDs must remain project scoped even for different bytes")
		status, _ = get("/api/db/tables/evidence_exchanges/records"+version, "")
		require.NotEqual(t, http.StatusOK, status, "generic APIs must not bypass finding association")
	}
	_, err = env.db.ExecContext(ctx, "DELETE FROM evidence_exchanges WHERE project_uuid = ? AND id = ?", database.DefaultProjectUUID, x.ID)
	require.NoError(t, err)
	for _, version := range []string{"", "?api_version=2"} {
		status, _ := get(fmt.Sprintf("/api/findings/%d/evidence/%s%s", f.ID, x.ID, version), "")
		require.Equal(t, http.StatusNotFound, status, "retention loss cannot borrow inline text or another project's receipt")
	}
}

func TestAPI_EvidenceBinaryAssociationScope(t *testing.T) {
	scenarioEvidenceAPI(t, newAPITestEnv(t, ""))
}

func TestPg_API_EvidenceBinaryAssociationScope(t *testing.T) {
	scenarioEvidenceAPI(t, newPgAPITestEnv(t, ""))
}
