package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

func requireAgentMetric(t *testing.T, raw map[string]json.RawMessage, key string, want int64) {
	t.Helper()
	value, present := raw[key]
	require.True(t, present, "known metric %s was omitted", key)
	var got int64
	require.NoError(t, json.Unmarshal(value, &got))
	require.Equal(t, want, got, key)
}

func TestAgentSessionKnownZeroMetricsAreNotUnknown(t *testing.T) {
	started := time.Date(2026, 11, 6, 13, 23, 35, 0, time.UTC)
	run := &database.AgenticScan{
		UUID: "early-failure", Mode: "swarm", Status: "failed",
		StartedAt: started, CompletedAt: started.Add(33 * time.Millisecond),
		ErrorMessage: "initialization rejected", DurationMs: 0,
	}
	detail := agenticScanToSessionDetail(run)
	detail.ChildRuns = []*AgentSessionDetail{agenticScanToSessionDetail(run)}
	for _, dto := range []any{agenticScanToSessionSummary(run), detail} {
		b, err := json.Marshal(dto)
		require.NoError(t, err)
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &raw))
		for _, key := range []string{"finding_count", "record_count", "saved_count", "duration_ms"} {
			requireAgentMetric(t, raw, key, 0)
		}
		if children := raw["child_runs"]; children != nil {
			var child []map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(children, &child))
			require.Len(t, child, 1)
			for _, key := range []string{"finding_count", "record_count", "saved_count", "duration_ms"} {
				requireAgentMetric(t, child[0], key, 0)
			}
		}
	}
	// Do not replace the stored measurement with elapsed time inferred from dates.
	require.Zero(t, detail.DurationMs)
}

func TestAgentSessionEndpointsPreserveKnownZeroMetrics(t *testing.T) {
	const project = "de9042c9-53c2-44e4-9e8e-7d2d6c6d224f"
	db, repo := newPinnedTestDB(t)
	started := time.Date(2026, 11, 6, 13, 23, 35, 0, time.UTC)
	parent := &database.AgenticScan{
		UUID: "early-failure", ProjectUUID: project, Mode: "swarm", Status: "failed",
		StartedAt: started, CompletedAt: started.Add(33 * time.Millisecond),
		ErrorMessage: "initialization rejected", DurationMs: 0,
	}
	child := &database.AgenticScan{
		UUID: "early-failure-child", ProjectUUID: project, Mode: "query", Status: "failed",
		ParentAgenticScanUUID: parent.UUID, StartedAt: started, CompletedAt: parent.CompletedAt,
	}
	for _, run := range []*database.AgenticScan{parent, child} {
		require.NoError(t, repo.CreateAgenticScan(context.Background(), run))
	}
	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Use(apiVersionMiddleware(1))
	app.Use(ProjectUUIDMiddleware(nil))
	app.Get("/api/agent/sessions", h.HandleAgentSessionList)
	app.Get("/api/agent/sessions/:id", h.HandleAgentSessionDetail)
	app.Get("/api/agent/status/list", h.HandleAgenticScanList)
	app.Get("/api/agent/status/:id", h.HandleAgenticScanStatus)

	for _, version := range []string{"1", "2"} {
		t.Run("v"+version, func(t *testing.T) {
			headers := map[string]string{"X-Project-UUID": project}
			// Use the public query negotiation so this test covers both list shapes.
			for _, path := range []string{"/api/agent/sessions/" + parent.UUID, "/api/agent/status/" + parent.UUID} {
				resp, body := doReq2(t, app, http.MethodGet, path+"?api_version="+version, "", headers)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var raw map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(body, &raw))
				for _, key := range []string{"finding_count", "record_count", "saved_count"} {
					requireAgentMetric(t, raw, key, 0)
				}
				if path == "/api/agent/sessions/"+parent.UUID {
					requireAgentMetric(t, raw, "duration_ms", 0)
					var children []map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(raw["child_runs"], &children))
					require.Len(t, children, 1)
					for _, key := range []string{"finding_count", "record_count", "saved_count", "duration_ms"} {
						requireAgentMetric(t, children[0], key, 0)
					}
				}
			}
			for _, path := range []string{"/api/agent/sessions", "/api/agent/status/list"} {
				resp, body := doReq2(t, app, http.MethodGet, path+"?api_version="+version, "", headers)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				var rows []map[string]json.RawMessage
				if version == "1" && path == "/api/agent/status/list" {
					require.NoError(t, json.Unmarshal(body, &rows))
				} else {
					var envelope map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(body, &envelope))
					key := "data"
					if version == "2" {
						key = "items"
					}
					require.NoError(t, json.Unmarshal(envelope[key], &rows))
				}
				// History/status lists intentionally omit child runs; children are
				// covered in the parent's detail object above, not separate rows.
				require.Len(t, rows, 1)
				identity := "uuid"
				if path == "/api/agent/status/list" {
					identity = "agentic_scan_uuid"
				}
				require.JSONEq(t, `"early-failure"`, string(rows[0][identity]))
				for _, row := range rows {
					for _, key := range []string{"finding_count", "record_count", "saved_count"} {
						requireAgentMetric(t, row, key, 0)
					}
					if path == "/api/agent/sessions" {
						requireAgentMetric(t, row, "duration_ms", 0)
					}
				}
			}
		})
	}
}

func TestAgentStatusPreservesZeroAndUnknownSentinelCounts(t *testing.T) {
	for _, count := range []int{0, -1, 7} {
		dto := AgenticScanStatusResponse{AgenticScanUUID: "status", Status: "failed",
			FindingCount: count, RecordCount: count, SavedCount: count}
		b, err := json.Marshal(dto)
		require.NoError(t, err)
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &raw))
		for _, key := range []string{"finding_count", "record_count", "saved_count"} {
			requireAgentMetric(t, raw, key, int64(count))
		}
	}
}
