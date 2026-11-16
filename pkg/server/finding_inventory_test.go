package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
)

type findingInventoryQueryHook struct {
	mu      sync.Mutex
	queries []string
}

func (h *findingInventoryQueryHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	if strings.Contains(event.Query, "http_records") {
		h.mu.Lock()
		h.queries = append(h.queries, event.Query)
		h.mu.Unlock()
	}
	return ctx
}

func (*findingInventoryQueryHook) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestFindingLinkageDetailNeverLoadsLinkedBodies(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()
	own := insertRecordReturning(t, db, database.DefaultProjectUUID)
	bodyBytes := []byte(strings.Repeat("LINKED-BODY-NOT-IN-DETAIL", 16384))
	if _, err := db.ExecContext(ctx, "UPDATE http_records SET raw_request = ?, raw_response = ? WHERE uuid = ?", bodyBytes, bodyBytes, own); err != nil {
		t.Fatal(err)
	}
	id := insertFindingReturning(t, db, database.DefaultProjectUUID)
	refs := []string{own}
	for i := 0; i < database.SQLChunkSize+3; i++ {
		refs = append(refs, fmt.Sprintf("ghost-%04d", i))
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE findings SET http_record_uuids = ? WHERE id = ?", string(refsJSON), id); err != nil {
		t.Fatal(err)
	}
	hook := &findingInventoryQueryHook{}
	db.AddQueryHook(hook)
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Get("/api/findings/:id", h.findingsHandler().HandleGetFinding)
	app.Get("/api/http-records/:uuid", h.HandleGetRecord)
	status, body := doGet(t, app, "/api/findings/"+strconv.FormatInt(id, 10), nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var result struct {
		database.Finding
		RecordsTotal int      `json:"records_total"`
		Unavailable  []string `json:"records_unavailable"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.HTTPRecordUUIDs) != len(refs) || result.RecordsTotal != len(refs) || len(result.Unavailable) != len(refs)-1 {
		t.Fatalf("inventory was capped: refs=%d total=%d unavailable=%d", len(result.HTTPRecordUUIDs), result.RecordsTotal, len(result.Unavailable))
	}
	if len(body) >= len(bodyBytes) || strings.Contains(string(body), "LINKED-BODY-NOT-IN-DETAIL") || strings.Contains(string(body), `"records":`) {
		t.Fatal("linked bodies embedded in ordinary detail")
	}
	hook.mu.Lock()
	queries := append([]string(nil), hook.queries...)
	hook.mu.Unlock()
	if len(queries) == 0 {
		t.Fatal("inventory did not check scoped record availability")
	}
	for _, query := range queries {
		if strings.Contains(query, "raw_request") || strings.Contains(query, "raw_response") || strings.Contains(query, "request_authorization") {
			t.Fatalf("inventory loaded HTTP content: %s", query)
		}
	}
	// The existing scoped drill-down still retrieves the complete stored bytes.
	status, body = doGet(t, app, "/api/http-records/"+own, nil)
	if status != http.StatusOK || !strings.Contains(string(body), base64.StdEncoding.EncodeToString(bodyBytes)) {
		t.Fatalf("lazy record lookup did not return stored bytes: status=%d", status)
	}
}
