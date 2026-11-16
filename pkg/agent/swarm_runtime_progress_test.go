package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

func runtimeTestPipeline(writer io.Writer) *swarmPipelineState {
	return &swarmPipelineState{
		runner:       NewSwarmRunner(nil, nil),
		cfg:          SwarmConfig{StreamWriter: writer},
		agenticScan:  &database.AgenticScan{},
		result:       &SwarmResult{},
		phaseTimings: make(map[string]time.Duration),
	}
}

func TestSwarmRuntimeProgress_PhaseTransitions(t *testing.T) {
	var out bytes.Buffer
	ps := runtimeTestPipeline(NewSynchronizedWriter(&out))
	var callbacks []string
	ps.cfg.PhaseCallback = func(phase string) { callbacks = append(callbacks, phase) }
	for _, phase := range []string{SwarmPhaseNormalize, SwarmPhaseDiscover, SwarmPhaseScan} {
		started := ps.startPhase(context.Background(), phase, phase != SwarmPhaseNormalize)
		if ps.agenticScan.CurrentPhase != phase {
			t.Fatalf("phase transition missing: %q", ps.agenticScan.CurrentPhase)
		}
		ps.finishPhase(phase, started.Add(-37*time.Millisecond))
		wantFinish := fmt.Sprintf("[swarm] [%s] phase finished: duration=%s\n", phase, ps.phaseTimings[phase].Round(time.Millisecond))
		if strings.Count(out.String(), "[swarm] ["+phase+"] phase started: "+phase+"\n") != 1 || strings.Count(out.String(), wantFinish) != 1 {
			t.Fatalf("phase %q missing/duplicated start, finish or duration: %s", phase, out.String())
		}
		if ps.phaseTimings[phase] < 37*time.Millisecond {
			t.Fatalf("duration not retained for %s", phase)
		}
	}
	if len(callbacks) != 2 || callbacks[0] != SwarmPhaseDiscover || callbacks[1] != SwarmPhaseScan {
		t.Fatalf("silent phase changed callback behavior: %v", callbacks)
	}
	if len(ps.activePhases) != 0 || len(ps.completedPhases) != 3 {
		t.Fatalf("phase tracking: active=%v complete=%v", ps.activePhases, ps.completedPhases)
	}
}

func TestSwarmRuntimeProgress_ExtensionSingleStart(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(fmt.Sprint(populated), func(t *testing.T) {
			var out bytes.Buffer
			ps := runtimeTestPipeline(NewSynchronizedWriter(&out))
			ps.sessionDir = t.TempDir()
			callbacks := 0
			ps.cfg.PhaseCallback = func(string) { callbacks++ }
			if populated {
				ps.sourceExtensions = []GeneratedExtension{{Filename: "test.js", Code: "// valid JavaScript"}}
			}
			if err := (extensionSwarmStep{}).Run(context.Background(), ps); err != nil {
				t.Fatal(err)
			}
			if strings.Count(out.String(), "phase started:") != 1 || strings.Count(out.String(), "phase finished:") != 1 {
				t.Fatalf("extension phase start/end duplicated or missing: %s", out.String())
			}
			wantCallbacks := 0
			if populated {
				wantCallbacks = 1
			}
			if callbacks != wantCallbacks {
				t.Fatalf("console callback changed: got %d want %d", callbacks, wantCallbacks)
			}
		})
	}
}

func TestSwarmRuntimeProgress_RestoredPlan(t *testing.T) {
	var out bytes.Buffer
	ps := runtimeTestPipeline(NewSynchronizedWriter(&out))
	ps.sessionDir = t.TempDir()
	ps.cfg.DryRun = true
	ps.checkpoint = &SwarmCheckpoint{CompletedPhases: []string{SwarmPhasePlan}, Plan: &SwarmPlan{}}
	ps.cfg.PhaseCallback = func(string) { t.Error("restored phase must not trigger the CLI start callback") }
	if err := (planSwarmStep{}).Run(context.Background(), ps); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "phase started:") || strings.Count(out.String(), "plan restored from checkpoint\n") != 1 || strings.Count(out.String(), "phase finished: duration=") != 1 {
		t.Fatalf("restored plan events: %s", out.String())
	}
	if ps.result.SwarmPlan != ps.checkpoint.Plan || !ps.stop {
		t.Fatal("restore/dry-run behavior changed")
	}
}

const runtimeSensitiveTarget = "https://private-user:private-password@example.invalid/private-path?access_token=private-query#private-fragment"

func assertNoRuntimeSensitiveDetails(t *testing.T, text string) {
	t.Helper()
	for _, detail := range []string{runtimeSensitiveTarget, "private-user", "private-password", "private-path", "private-query", "private-fragment", "native-error-detail", "free-warning-detail"} {
		if strings.Contains(text, detail) {
			t.Fatalf("sensitive detail leaked into runtime metadata: %q", detail)
		}
	}
}

func TestSwarmRuntimeProgress_NativeWarningsDoNotLeakURLs(t *testing.T) {
	// Simulate the free-form errors native callbacks return. No native scans,
	// HTTP requests or LLM calls: URLs appear only in the fake error strings.
	for _, category := range []string{"TargetsRejected", "TargetsUnreachable"} {
		for _, phase := range []string{SwarmPhaseDiscover, SwarmPhaseScan} {
			t.Run(category+"/"+phase, func(t *testing.T) {
				var out bytes.Buffer
				ps := runtimeTestPipeline(NewSynchronizedWriter(&out))
				ps.sessionDir = t.TempDir()
				nativeErr := fmt.Errorf("%s: native-error-detail %s", category, runtimeSensitiveTarget)
				callback := func(context.Context) error {
					if _, err := ps.cfg.StreamWriter.Write([]byte("raw AI chunk\x1b[32m\r\n")); err != nil {
						t.Fatal(err)
					}
					return nativeErr
				}
				var step swarmPhaseStep = discoverySwarmStep{}
				wantWarning := "discovery phase failed: " + nativeErr.Error()
				ps.cfg.DiscoverFunc = callback
				if phase == SwarmPhaseScan {
					step = scanSwarmStep{}
					ps.cfg.ScanFunc = func(ctx context.Context, _ ScanRequest) error { return callback(ctx) }
					wantWarning = "scan phase encountered an error: " + nativeErr.Error()
				}
				if err := step.Run(context.Background(), ps); err != nil {
					t.Fatalf("non-fatal callback error changed: %v", err)
				}
				if _, err := ps.runner.finishRun(context.Background(), ps.cfg, ps.agenticScan, ps.result, time.Now(), nil); err != nil {
					t.Fatal(err)
				}
				if len(ps.result.Warnings) != 1 || ps.result.Warnings[0] != wantWarning || ps.agenticScan.ErrorMessage != wantWarning {
					t.Fatal("original warning must remain intact for result and DB consumers")
				}
				assertNoRuntimeSensitiveDetails(t, out.String())
				if strings.Count(out.String(), "raw AI chunk\x1b[32m\r\n") != 1 || strings.Count(out.String(), "warning: warnings recorded: count=1; see run details\n") != 1 {
					t.Fatalf("raw stream changed or safe warning count missing: %s", out.String())
				}
				if !strings.Contains(out.String(), "["+phase+"] phase finished: duration=") || !strings.Contains(out.String(), "status=completed_with_warnings") {
					t.Fatalf("phase completion missing: %s", out.String())
				}
			})
		}
	}
}

func TestSwarmRuntimeProgress_FinishRunPreservesCancellationSemantics(t *testing.T) {
	nativeErr := fmt.Errorf("native-error-detail %s", runtimeSensitiveTarget)
	for _, tc := range []struct {
		name        string
		contextErr  error
		runErr      error
		warnings    bool
		wantStatus  string
		wantTimeout bool
	}{
		{name: "cancelled-context-nil-error", contextErr: context.Canceled, wantStatus: "completed"},
		{name: "deadline-context-nil-error", contextErr: context.DeadlineExceeded, wantStatus: "completed"},
		{name: "cancelled-error", contextErr: context.Canceled, runErr: context.Canceled, wantStatus: "cancelled"},
		{name: "deadline-error", contextErr: context.DeadlineExceeded, runErr: context.DeadlineExceeded, wantStatus: "timeout", wantTimeout: true},
		{name: "native-error", runErr: nativeErr, wantStatus: "failed"},
		{name: "native-error-cancelled-context", contextErr: context.Canceled, runErr: nativeErr, wantStatus: "cancelled"},
		{name: "native-error-deadline-context", contextErr: context.DeadlineExceeded, runErr: nativeErr, wantStatus: "timeout", wantTimeout: true},
		{name: "free-warning", warnings: true, wantStatus: "completed_with_warnings"},
	} {
		for _, logging := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/logging=%v", tc.name, logging), func(t *testing.T) {
				ctx := context.Background()
				switch tc.contextErr {
				case context.Canceled:
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case context.DeadlineExceeded:
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer cancel()
				}
				var out bytes.Buffer
				var writer io.Writer
				if logging {
					writer = NewSynchronizedWriter(&out)
				}
				runner := NewSwarmRunner(nil, nil)
				scan := &database.AgenticScan{}
				result := &SwarmResult{}
				wantMessage := ""
				if tc.warnings {
					wantMessage = "free-warning-detail " + runtimeSensitiveTarget
					runner.addWarning(result, "%s", wantMessage)
				}
				if tc.runErr != nil {
					wantMessage = tc.runErr.Error()
				}
				gotResult, gotErr := runner.finishRun(ctx, SwarmConfig{StreamWriter: writer}, scan, result, time.Now(), tc.runErr)
				if gotResult != result || gotErr != tc.runErr || scan.Status != tc.wantStatus || result.TimedOut != tc.wantTimeout || scan.ErrorMessage != wantMessage {
					t.Fatalf("original finalization semantics changed: err=%v status=%s timeout=%v message=%q", gotErr, scan.Status, result.TimedOut, scan.ErrorMessage)
				}
				if tc.warnings && (len(result.Warnings) != 1 || result.Warnings[0] != wantMessage) {
					t.Fatal("original warning changed")
				}
				assertNoRuntimeSensitiveDetails(t, out.String())
				if logging {
					if !strings.Contains(out.String(), "run finished: status="+tc.wantStatus) {
						t.Fatalf("terminal summary missing: %s", out.String())
					}
					if tc.runErr != nil && strings.Count(out.String(), "error: error recorded; see run details\n") != 1 {
						t.Fatalf("safe error metadata missing: %s", out.String())
					}
					if tc.contextErr == context.Canceled && !strings.Contains(out.String(), "context cancellation observed at run finish\n") {
						t.Fatal("context cancellation not observed in metadata")
					}
					if tc.contextErr == context.DeadlineExceeded && !strings.Contains(out.String(), "context deadline observed at run finish\n") {
						t.Fatal("context deadline not observed in metadata")
					}
				} else if out.Len() != 0 {
					t.Fatal("nil writer received output")
				}
			})
		}
	}
}

func TestSwarmRuntimeProgress_RunWarningsAndSummary(t *testing.T) {
	var out bytes.Buffer
	result, err := NewSwarmRunner(nil, nil).Run(context.Background(), SwarmConfig{
		StreamWriter: NewSynchronizedWriter(&out), SessionDir: t.TempDir(),
		SourceAnalysisOnly: true, Auth: true, Browser: false,
		Credentials: "secret-not-for-runtime-metadata", Instruction: "private-prompt",
		ReconExtraHeaders: map[string]string{"Authorization": "private-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Degraded || len(result.Warnings) != 1 {
		t.Fatalf("warning semantics changed: %+v", result)
	}
	if strings.Count(out.String(), "warning: warnings recorded: count=1; see run details\n") != 1 || !strings.Contains(out.String(), "run finished: status=completed_with_warnings") {
		t.Fatalf("safe warning count/summary missing or duplicated: %s", out.String())
	}
	if strings.Contains(out.String(), result.Warnings[0]) {
		t.Fatal("free-form warning must not be copied into runtime metadata")
	}
	if _, ok := result.PhaseTimings[SwarmPhaseNormalize]; !ok {
		t.Fatal("silent normalize phase duration missing")
	}
	for _, secret := range []string{"secret-not-for-runtime-metadata", "private-prompt", "private-token"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("config secret leaked: %q", secret)
		}
	}
}

func TestSwarmRuntimeProgress_RunFatalError(t *testing.T) {
	var out bytes.Buffer
	result, err := NewSwarmRunner(nil, nil).Run(context.Background(), SwarmConfig{
		StreamWriter: NewSynchronizedWriter(&out), SessionDir: t.TempDir(), Inputs: []string{"not a supported input"},
	})
	if err == nil || !strings.Contains(err.Error(), "input normalization failed") {
		t.Fatalf("expected normalization error, got %v", err)
	}
	if strings.Count(out.String(), "error: error recorded; see run details\n") != 1 || !strings.Contains(out.String(), "run finished: status=failed") {
		t.Fatalf("safe terminal error missing/duplicated: %s", out.String())
	}
	if strings.Contains(out.String(), err.Error()) {
		t.Fatal("free-form error must not be copied into runtime metadata")
	}
	if !strings.Contains(out.String(), "["+SwarmPhaseNormalize+"] phase interrupted: duration=") {
		t.Fatalf("failed phase duration not logged: %s", out.String())
	}
	if _, ok := result.PhaseTimings[SwarmPhaseNormalize]; !ok {
		t.Fatal("failed phase duration not retained")
	}
}

func TestSwarmRuntimeProgress_RunCancelledContextPreservesPhases(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		for _, logging := range []bool{false, true} {
			t.Run(fmt.Sprintf("deadline=%v/logging=%v", deadline, logging), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				observed := "context cancellation observed at run finish\n"
				if deadline {
					var cancelDeadline context.CancelFunc
					ctx, cancelDeadline = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					defer cancelDeadline()
					observed = "context deadline observed at run finish\n"
				}
				var out bytes.Buffer
				var writer io.Writer
				if logging {
					writer = NewSynchronizedWriter(&out)
				}
				// Empty inputs/source and no engine keep this offline. Originally,
				// these steps complete despite ctx.Err(): normalization and the auth
				// warning run, then source-analysis-only stops the pipeline.
				result, err := NewSwarmRunner(nil, nil).Run(ctx, SwarmConfig{
					StreamWriter: writer, SessionDir: t.TempDir(),
					SourceAnalysisOnly: true, Auth: true, Browser: false,
				})
				if err != nil || result.TimedOut || len(result.Warnings) != 1 || !result.Degraded {
					t.Fatalf("original cancelled-context behavior changed: err=%v result=%+v", err, result)
				}
				if _, ok := result.PhaseTimings[SwarmPhaseNormalize]; !ok {
					t.Fatal("cancelled context must not introduce a new early phase exit")
				}
				if logging {
					if !strings.Contains(out.String(), observed) || !strings.Contains(out.String(), "run finished: status=completed_with_warnings") || strings.Contains(out.String(), "error: error recorded;") {
						t.Fatalf("context observation must not change terminal outcome: %s", out.String())
					}
				} else if out.Len() != 0 {
					t.Fatal("nil writer received output")
				}
			})
		}
	}
}

func TestSwarmRuntimeProgress_ConcurrentRunsAreIsolated(t *testing.T) {
	// No engine, records or live callbacks: both runs stop after normalization.
	// Concurrent parent/native writes reuse each run's wrapper, not a global sink.
	var out [2]bytes.Buffer
	writers := [2]io.Writer{NewSynchronizedWriter(&out[0]), NewSynchronizedWriter(&out[1])}
	dirs := [2]string{t.TempDir(), t.TempDir()}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for run := range out {
		wg.Go(func() {
			<-start
			_, err := NewSwarmRunner(nil, nil).Run(context.Background(), SwarmConfig{
				AgenticScanUUID: fmt.Sprintf("run-%d", run), SessionDir: dirs[run],
				StreamWriter: writers[run], SourceAnalysisOnly: true,
			})
			if err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			<-start
			for chunk := 0; chunk < 100; chunk++ {
				if _, err := fmt.Fprintf(writers[run], "AI-%d-%d\x1b[31m\r\n", run, chunk); err != nil {
					t.Error(err)
				}
				if err := WriteRuntimeProgress(writers[run], "native", "scan", fmt.Sprintf("native-%d-%d", run, chunk)); err != nil {
					t.Error(err)
				}
			}
		})
	}
	close(start)
	wg.Wait()
	for run := range out {
		text := out[run].String()
		if strings.Count(text, "run started: "+fmt.Sprintf("run-%d", run)+"\n") != 1 || strings.Count(text, "run finished: status=completed") != 1 {
			t.Fatalf("run %d terminal events missing: %s", run, text)
		}
		for _, prefix := range []string{"run-", "AI-", "native-"} {
			if strings.Contains(text, fmt.Sprintf("%s%d", prefix, 1-run)) {
				t.Fatalf("run %d received another session's data", run)
			}
		}
		for chunk := 0; chunk < 100; chunk++ {
			if strings.Count(text, fmt.Sprintf("AI-%d-%d\x1b[31m\r\n", run, chunk)) != 1 || strings.Count(text, fmt.Sprintf("[native] [scan] native-%d-%d\n", run, chunk)) != 1 {
				t.Fatalf("run %d chunk %d changed, interleaved or duplicated", run, chunk)
			}
		}
	}
}

func TestSwarmRuntimeProgress_RescanErrorsDoNotLeakURLs(t *testing.T) {
	for _, category := range []string{"TargetsRejected", "TargetsUnreachable"} {
		t.Run(category, func(t *testing.T) {
			var out bytes.Buffer
			wantErr := fmt.Errorf("%s: native-error-detail %s", category, runtimeSensitiveTarget)
			cfg := SwarmConfig{
				StreamWriter: NewSynchronizedWriter(&out),
				ScanFunc: func(_ context.Context, req ScanRequest) error {
					if req.ScanUUID != "test-scan" {
						t.Fatal("scan request changed")
					}
					return wantErr
				},
			}
			gotErr := swarmRescanFunc(cfg)(context.Background(), ScanRequest{ScanUUID: "test-scan"})
			if gotErr != wantErr || gotErr.Error() != wantErr.Error() {
				t.Fatal("original native error must remain intact for consumers")
			}
			assertNoRuntimeSensitiveDetails(t, out.String())
			if strings.Count(out.String(), "warning: rescan failed; see run details\n") != 1 || strings.Count(out.String(), "phase finished: duration=") != 1 {
				t.Fatalf("safe rescan warning/completion missing: %s", out.String())
			}
		})
	}
}

func TestSwarmRuntimeProgress_FilesystemFailureMetadataIsSafe(t *testing.T) {
	var out bytes.Buffer
	ps := runtimeTestPipeline(NewSynchronizedWriter(&out))
	// A file in place of a session directory makes the checkpoint write fail.
	// The existing filesystem error includes this sensitive-looking path;
	// only the new runtime metadata must omit it.
	ps.sessionDir = filepath.Join(t.TempDir(), "private-path")
	if err := os.WriteFile(ps.sessionDir, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	ps.writeCheckpoint(nil, 0)
	assertNoRuntimeSensitiveDetails(t, out.String())
	if strings.Count(out.String(), "warning: failed to write checkpoint; see run details\n") != 1 {
		t.Fatalf("safe filesystem warning missing: %s", out.String())
	}
}

func TestSwarmRuntimeProgress_RescanAndWriterFailure(t *testing.T) {
	if swarmRescanFunc(SwarmConfig{}) != nil {
		t.Fatal("nil scan callback must stay nil")
	}
	var out bytes.Buffer
	wantErr := errors.New("fake scan failure")
	cfg := SwarmConfig{StreamWriter: NewSynchronizedWriter(&out), ScanFunc: func(_ context.Context, req ScanRequest) error {
		if req.ScanUUID != "test-scan" {
			t.Error("scan request changed")
		}
		return wantErr
	}}
	if err := swarmRescanFunc(cfg)(context.Background(), ScanRequest{ScanUUID: "test-scan"}); err != wantErr {
		t.Fatalf("callback error changed: %v", err)
	}
	if strings.Count(out.String(), "warning: rescan failed; see run details\n") != 1 || strings.Count(out.String(), "phase finished: duration=") != 1 {
		t.Fatalf("rescan completion/warning missing: %s", out.String())
	}
	// A logging failure must never turn a successful offline run into failure.
	_, err := NewSwarmRunner(nil, nil).Run(context.Background(), SwarmConfig{
		StreamWriter: &runtimeTestWriter{err: errors.New("log failed")}, SessionDir: t.TempDir(), SourceAnalysisOnly: true,
	})
	if err != nil {
		t.Fatalf("best-effort log changed Run result: %v", err)
	}
}
