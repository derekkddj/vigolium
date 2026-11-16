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
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestHandleBurpSiteMapSnapshotIsIdempotentAndVersionsResponse(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			db, repo := newPinnedTestDB(t)
			h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
			app := fiber.New()
			app.Use(apiVersionMiddleware(1))
			app.Post("/api/burp/sitemap/snapshot", h.HandleBurpSiteMapSnapshot)
			ctx := context.Background()

			rawRequest := []byte("GET /api HTTP/1.1\r\nHost: example.test\r\n\r\n")
			firstRaw := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nfirst\x00\xff")
			secondRaw := []byte("HTTP/1.1 403 Forbidden\r\nContent-Type: application/octet-stream\r\n\r\nchanged\xff\x00")

			post := func(response []byte, inserted, unchanged int) {
				t.Helper()
				body, err := json.Marshal(siteMapSnapshotRequest{Records: []siteMapSnapshotRecord{{
					URL:            "https://example.test/api",
					RequestBase64:  base64.StdEncoding.EncodeToString(rawRequest),
					ResponseBase64: base64.StdEncoding.EncodeToString(response),
				}}})
				require.NoError(t, err)
				resp, raw := doReq2(t, app, http.MethodPost, "/api/burp/sitemap/snapshot", string(body), map[string]string{
					apicontract.RESTAPIVersionHeader: fmt.Sprint(version),
				})
				require.Equal(t, http.StatusOK, resp.StatusCode, "%s", raw)
				require.Equal(t, fmt.Sprint(version), resp.Header.Get(apicontract.RESTAPIVersionHeader))
				// Keep the existing object and counter names in both versions. The
				// legacy updated counter remains present but immutable snapshots
				// count changed exchanges as inserted, never as updated.
				require.JSONEq(t, fmt.Sprintf(`{"received":1,"inserted":%d,"updated":0,"unchanged":%d,"skipped":0}`, inserted, unchanged), string(raw))
			}
			loadVersions := func() []*database.HTTPRecord {
				t.Helper()
				var records []*database.HTTPRecord
				require.NoError(t, db.NewSelect().Model(&records).
					Where("project_uuid = ?", database.DefaultProjectUUID).
					Where("source = ?", "burp-sitemap").Scan(ctx))
				return records
			}

			post(firstRaw, 1, 0)
			originals := loadVersions()
			require.Len(t, originals, 1)
			originalUUID := originals[0].UUID
			post(secondRaw, 1, 0)
			post(secondRaw, 0, 1)
			// Re-importing the earlier snapshot is also idempotent: it must not
			// rewrite the newer exchange or create another historical version.
			post(firstRaw, 0, 1)
			versions := loadVersions()
			require.Len(t, versions, 2)
			original, err := repo.GetRecordByUUID(ctx, originalUUID)
			require.NoError(t, err)
			require.Equal(t, 200, original.StatusCode)
			require.Equal(t, rawRequest, original.RawRequest)
			require.Equal(t, firstRaw, original.RawResponse, "original exchange bytes were rewritten")
			for _, record := range versions {
				require.Equal(t, rawRequest, record.RawRequest)
				if record.UUID == originalUUID {
					continue
				}
				require.Equal(t, 403, record.StatusCode)
				require.Equal(t, secondRaw, record.RawResponse, "new exchange bytes changed")
			}
		})
	}
}
