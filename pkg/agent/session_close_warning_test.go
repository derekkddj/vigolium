package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/olium"
)

type warningCloseSession struct {
	err    error
	closes int
}

func (s *warningCloseSession) Fork() AgentSession { return s }
func (s *warningCloseSession) Close() error       { s.closes++; return s.err }

type warningCloseRuntime struct {
	fakeRuntime
	session *warningCloseSession
	runErr  error
}

func (r *warningCloseRuntime) NewSessionWithSpec(_ *config.OliumConfig, spec SessionSpec) (AgentSession, error) {
	r.sessionCalls.Add(1)
	r.lastSpec = spec
	return r.session, nil
}
func (r *warningCloseRuntime) RunOnSession(_ context.Context, _ *config.OliumConfig, _ AgentSession, _ string, _, _ io.Writer, _ bool) (oliumRunOutput, error) {
	r.runOnSessionCalls.Add(1)
	return oliumRunOutput{Text: "retained answer"}, r.runErr
}

func TestEngineEvidenceOwnedSessionCloseWarning(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	reg, err := olium.LoadSkillsFor(false)
	if err != nil || reg == nil || reg.Len() == 0 {
		t.Fatalf("skills fixture unavailable: %v", err)
	}
	for _, path := range []string{"skills", "bridge", "offline"} {
		for _, runFails := range []bool{false, true} {
			for _, closeFails := range []bool{false, true} {
				t.Run(path+"/"+map[bool]string{false: "run_ok", true: "run_failed"}[runFails]+"/"+map[bool]string{false: "close_ok", true: "close_failed"}[closeFails], func(t *testing.T) {
					session := &warningCloseSession{}
					if closeFails {
						session.err = errors.New("PRIVATE-CLOSE-ERROR")
					}
					rt := &warningCloseRuntime{session: session}
					if runFails {
						rt.runErr = context.Canceled
					}
					e := &Engine{runtime: rt}
					var sink bytes.Buffer
					opts := Options{PromptInline: "PRIVATE-PROMPT", StreamWriter: &sink, Retry: &RetryConfig{MaxRetries: -1}}
					var result *Result
					var runErr error
					switch path {
					case "skills":
						result, runErr = e.RunWithSkills(context.Background(), opts, reg)
					case "bridge":
						opts.EnableBurpBridgeTools = true
						result, runErr = e.Run(context.Background(), opts)
					case "offline":
						opts.OfflineTools = true
						result, runErr = e.Run(context.Background(), opts)
					}
					if runFails && !errors.Is(runErr, context.Canceled) || !runFails && runErr != nil {
						t.Fatalf("close failure replaced provider outcome: %v", runErr)
					}
					if result == nil || result.RawOutput != "retained answer" || session.closes != 1 || rt.runOnSessionCalls.Load() != 1 || rt.runPromptCalls.Load() != 0 {
						t.Fatal("close failure discarded output, leaked session, or retried successful work")
					}
					wantWarnings := 0
					if closeFails {
						wantWarnings = 1
					}
					if strings.Count(sink.String(), "Evidence degraded") != wantWarnings || strings.Contains(sink.String(), "PRIVATE") || strings.Contains(sink.String(), "retained answer") {
						t.Fatalf("close warning missing, duplicated, or leaked private data: %q", sink.String())
					}
				})
			}
		}
	}
}
