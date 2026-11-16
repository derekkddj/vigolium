package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestHandleCreateProjectCanonicalizesClientUUID(t *testing.T) {
	canonical := "3af56732-9c75-4fc2-8ace-a2e5655b725c"
	forms := map[string]string{
		"uppercase": strings.ToUpper(canonical),
		"braces":    "{" + canonical + "}",
		"urn":       "urn:uuid:" + canonical,
		"compact":   strings.ReplaceAll(canonical, "-", ""),
	}

	for name, supplied := range forms {
		t.Run(name, func(t *testing.T) {
			db, repo := newProjectModelTestDB(t)
			h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
			app := fiber.New()
			app.Post("/api/projects", h.HandleCreateProject)

			body, err := json.Marshal(ProjectRequest{Name: "canonical project", UUID: supplied})
			require.NoError(t, err)
			status, responseBody := doReq(t, app, http.MethodPost, "/api/projects", string(body), nil)
			if status != http.StatusCreated {
				t.Fatalf("status = %d body = %s, want 201", status, responseBody)
			}
			var created database.Project
			require.NoError(t, json.Unmarshal(responseBody, &created))
			require.Equal(t, canonical, created.UUID, "REST must persist and return canonical UUID spelling")

			stored, err := repo.GetProjectByUUID(t.Context(), canonical)
			require.NoError(t, err)
			require.Equal(t, canonical, stored.UUID)

			body, err = json.Marshal(ProjectRequest{Name: "retry name", UUID: supplied})
			require.NoError(t, err)
			status, responseBody = doReq(t, app, http.MethodPost, "/api/projects", string(body), nil)
			require.Equal(t, http.StatusOK, status, string(responseBody))
			var retried database.Project
			require.NoError(t, json.Unmarshal(responseBody, &retried))
			require.Equal(t, canonical, retried.UUID, "equivalent create retries must return the canonical row")

			if supplied != canonical {
				if _, err := repo.GetProjectByUUID(t.Context(), supplied); err == nil {
					t.Fatalf("noncanonical UUID spelling %q was stored as an alias", supplied)
				}
			}
		})
	}
}
