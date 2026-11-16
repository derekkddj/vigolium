package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestFindingSelectedEvidenceAssociationScopeAndLazyBytes(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("POST /proof HTTP/1.1\r\n\r\n\x00\xff"), []byte("HTTP/1.1 200 OK\r\n\r\n\xff\x00proof"), evidence.ProvenanceCaptured)
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "selected-proof", ModuleID: "test", ModuleName: "Test", EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "proof")}}
	other := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "unrelated", ModuleID: "test", ModuleName: "Test"}
	for _, finding := range []*database.Finding{f, other} {
		if err := repo.SaveFindingDirect(ctx, finding); err != nil {
			t.Fatal(err)
		}
	}
	const foreignProject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if err := repo.CreateProject(ctx, &database.Project{UUID: foreignProject, Name: "foreign", OwnerUUID: database.DefaultUserUUID}); err != nil {
		t.Fatal(err)
	}
	foreign := &database.Finding{ProjectUUID: foreignProject, FindingHash: "foreign", ModuleID: "test", ModuleName: "Test", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "foreign")}}
	if err := repo.SaveFindingDirect(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(repo))
	app.Get("/api/findings/:id", h.findingsHandler().HandleGetFinding)
	app.Get("/api/findings/:id/evidence/:exchange_id", h.findingsHandler().HandleGetFindingEvidence)
	status, body := doGet(t, app, fmt.Sprintf("/api/findings/%d", f.ID), nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d %s", status, body)
	}
	var manifest database.Finding
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Evidence) != 1 || manifest.Evidence[0].Exchange != nil || manifest.Evidence[0].Role != evidence.RoleAttack {
		t.Fatalf("detail is not manifest-only: %s", body)
	}
	path := fmt.Sprintf("/api/findings/%d/evidence/%s", f.ID, x.ID)
	status, body = doGet(t, app, path, nil)
	var got evidence.Exchange
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || !bytes.Equal(got.Request, x.Request) || !bytes.Equal(got.Response, x.Response) {
		t.Fatalf("binary receipt changed: %d %s", status, body)
	}
	for _, path := range []string{fmt.Sprintf("/api/findings/%d/evidence/%s", other.ID, x.ID), fmt.Sprintf("/api/findings/%d/evidence/%s", foreign.ID, x.ID), fmt.Sprintf("/api/findings/%d/evidence/ghost", f.ID)} {
		status, body = doGet(t, app, path, nil)
		if status != http.StatusNotFound {
			t.Fatalf("unassociated/foreign/missing exchange exposed: %d %s", status, body)
		}
	}
	foreignHeaders := map[string]string{"X-Project-UUID": foreignProject}
	status, body = doGet(t, app, path, foreignHeaders)
	if status != http.StatusNotFound {
		t.Fatalf("default finding exposed under foreign header: %d %s", status, body)
	}
	foreignPath := fmt.Sprintf("/api/findings/%d/evidence/%s", foreign.ID, x.ID)
	status, body = doGet(t, app, foreignPath, foreignHeaders)
	if status != http.StatusOK {
		t.Fatalf("owning project cannot hydrate its associated receipt: %d %s", status, body)
	}
	// Receipt retention loss leaves manifest identity, never inline fallback.
	if _, err := db.ExecContext(ctx, "DELETE FROM evidence_exchanges WHERE id = ?", x.ID); err != nil {
		t.Fatal(err)
	}
	status, body = doGet(t, app, path, nil)
	if status != http.StatusNotFound {
		t.Fatalf("missing receipt fallback: %d %s", status, body)
	}
}
