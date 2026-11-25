package provider

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

type toolPolicyProvider string

func (p toolPolicyProvider) Name() string { return string(p) }
func (toolPolicyProvider) Stream(context.Context, Request) (<-chan stream.Event, error) {
	panic("classification must not start a provider")
}

func TestHasInternalToolLoop(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"claude-code", true},
		{"claude-sdk-bridge", true},
		{"codex", false},
		{"openai-compatible", false},
		{"anthropic", false},
		{"google-vertex", false},
		{"synthetic", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasInternalToolLoop(toolPolicyProvider(tc.name)); got != tc.want {
				t.Fatalf("internal tool loop = %t, want %t", got, tc.want)
			}
		})
	}
}
