package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestFindingLinkageDetailScopedUnion(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	own := insertRecordReturning(t, db, database.DefaultProjectUUID)
	foreign := insertRecordReturning(t, db, "foreign-project")
	const secret = "FOREIGN-SECRET-BODY"
	if _, err := db.ExecContext(ctx, "UPDATE http_records SET raw_response = ? WHERE uuid = ?", []byte(secret), foreign); err != nil {
		t.Fatal(err)
	}
	id := insertFindingReturning(t, db, database.DefaultProjectUUID)
	refs, _ := json.Marshal([]string{foreign, "ghost-record"})
	if _, err := db.ExecContext(ctx, "UPDATE findings SET http_record_uuids = ? WHERE id = ?", string(refs), id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO finding_records (finding_id, record_uuid) VALUES (?, ?)", id, own); err != nil {
		t.Fatal(err)
	}
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/findings/:id", h.findingsHandler().HandleGetFinding)
	status, body := doGet(t, app, "/api/findings/"+strconv.FormatInt(id, 10), nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if strings.Contains(string(body), secret) || strings.Contains(string(body), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("cross-project body exposed")
	}
	var result struct {
		database.Finding
		RecordsTotal int      `json:"records_total"`
		Unavailable  []string `json:"records_unavailable"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if _, embedded := fields["records"]; embedded {
		t.Fatal("ordinary detail embeds linked traffic instead of lazy references")
	}
	if result.RecordsTotal != 3 || slices.Contains(result.Unavailable, own) || len(result.Unavailable) != 2 {
		t.Fatalf("wrong inventory: %+v", result)
	}
	if !slices.Contains(result.HTTPRecordUUIDs, own) || !slices.Contains(result.Unavailable, foreign) || !slices.Contains(result.Unavailable, "ghost-record") {
		t.Fatalf("lost legacy references: %+v", result)
	}
}
