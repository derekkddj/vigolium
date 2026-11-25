package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestSessionMaxTurnsPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.OliumConfig
		spec int
		want int
	}{
		{"unset", nil, 0, 0},
		{"config", &config.OliumConfig{MaxTurns: 47}, 0, 47},
		{"guardrail_override", &config.OliumConfig{MaxTurns: 47}, 1, 1},
		{"intent_override", &config.OliumConfig{MaxTurns: 47}, 30, 30},
		{"spec_without_config", nil, 8, 8},
		{"negative_config_is_bounded", &config.OliumConfig{MaxTurns: -1}, 0, 0},
		{"negative_spec_does_not_disable_config", &config.OliumConfig{MaxTurns: 47}, -1, 47},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionMaxTurns(tc.cfg, SessionSpec{MaxTurns: tc.spec}); got != tc.want {
				t.Fatalf("effective turns = %d, want %d", got, tc.want)
			}
		})
	}
}

// Exercise the real adapter/provider construction, not just the precedence
// helper. The synthetic local provider emits harmless unknown-tool calls then a
// final answer on turn 34, reproducing the old silent reset to 32. No target,
// shell, real credentials or external provider is used.
func TestOliumAdapterPassesConfiguredMaxTurnsToEngine(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int
		spec       int
		wantCalls  int32
		wantError  bool
	}{
		{"default_is_still_32", 0, 0, 32, true},
		{"configured_above_32", 35, 0, 34, false},
		{"configured_low_cap", 3, 0, 3, true},
		{"explicit_guardrail_cap_wins", 35, 1, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				if n < 34 {
					fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_%d\",\"type\":\"function\",\"function\":{\"name\":\"synthetic_unavailable\",\"arguments\":\"{}\"}}]}}]}\n\n", n)
					fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
				} else {
					fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"complete plan\"}}]}\n\n")
					fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
				}
				fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer srv.Close()
			cfg := &config.OliumConfig{
				Provider: "openai-compatible", Model: "synthetic", MaxTurns: tc.configured,
				MaxConcurrent:  -1,
				CustomProvider: config.CustomProviderConfig{BaseURL: srv.URL, APIKey: "synthetic"},
			}
			eng, err := buildOliumEngineWithSpec(cfg, SessionSpec{MaxTurns: tc.spec})
			if err != nil {
				t.Fatal(err)
			}
			defer eng.CloseRecorder()
			out, err := runOliumOnEngineWithThinking(context.Background(), cfg, eng, "synthetic plan", nil, nil, false)
			if tc.wantError {
				var budgetErr *RuntimeBudgetError
				if !errors.As(err, &budgetErr) || budgetErr.Kind != "turns" || isRetryableAgentError(context.Background(), err) {
					t.Fatalf("runtime budget stop lost its type or became retryable: %v", err)
				}
				if err == nil || !strings.Contains(err.Error(), "exceeded max turns") {
					t.Fatalf("expected bounded turn failure, got %v", err)
				}
			} else if err != nil || out.Text != "complete plan" {
				t.Fatalf("configured budget was lost: err=%v text=%q", err, out.Text)
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Fatalf("provider calls = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}
