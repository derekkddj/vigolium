package server

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"go.uber.org/zap"
)

// swarmRuntimeTee writes the disk record first, but a full/broken filesystem
// must not hide live output from a connected client. It is always wrapped in
// agent.NewSynchronizedWriter before concurrent producers use it.
type swarmRuntimeTee struct {
	log    io.Writer
	stream io.Writer
}

func (w *swarmRuntimeTee) Write(p []byte) (int, error) {
	if w.log != nil {
		n, err := w.log.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		if err != nil {
			zap.L().Warn("Agent session runtime log write failed; keeping live SSE output", zap.Error(err))
			w.log = nil // Warn once; do not retry a failed disk on every chunk.
		}
	}
	return w.stream.Write(p)
}

// The runtime writer belongs to a run, not the process. Context propagation
// also reaches discovery/rescan callbacks built before the handler opens the
// session log, without capturing a stale copy of SwarmConfig.StreamWriter.
type swarmRuntimeOutputKey struct{}

func withSwarmRuntimeOutput(ctx context.Context, writer io.Writer) context.Context {
	if writer == nil {
		return ctx
	}
	return context.WithValue(ctx, swarmRuntimeOutputKey{}, writer)
}

func attachSwarmNativeRuntimeOutput(ctx context.Context, scanRunner *runner.Runner) {
	if callback := swarmNativeRuntimeCallback(ctx); callback != nil {
		scanRunner.SetEventCallback(callback)
	}
}

func swarmNativeRuntimeCallback(ctx context.Context) func(scanevents.Event) {
	writer, _ := ctx.Value(swarmRuntimeOutputKey{}).(io.Writer)
	if writer == nil {
		return nil
	}
	return func(event scanevents.Event) {
		writeSwarmNativeRuntimeEvent(writer, event)
	}
}

// Only progress metadata is forwarded. Request/response bodies, finding values,
// auth configuration and raw error messages stay in the scan's evidence store.
func writeSwarmNativeRuntimeEvent(writer io.Writer, event scanevents.Event) {
	switch event.Type {
	case scanevents.TypeScanStarted, scanevents.TypeScanFinished,
		scanevents.TypePhaseStarted, scanevents.TypePhaseProgress,
		scanevents.TypePhaseFinished, scanevents.TypeFindingNew,
		scanevents.TypeError, scanevents.TypeModuleError,
		scanevents.TypeExtensionFailed, scanevents.TypeOASTUnavailable,
		scanevents.TypeScanSetup:
	default:
		return
	}
	fields := []string{event.Type}
	if event.ScanUUID != "" {
		fields = append(fields, "scan="+event.ScanUUID)
	}
	if event.Status != "" {
		fields = append(fields, "status="+event.Status)
	}
	if event.RequestsSent != nil {
		fields = append(fields, fmt.Sprintf("requests=%d", *event.RequestsSent))
	}
	if event.Findings != nil {
		fields = append(fields, fmt.Sprintf("findings=%d", *event.Findings))
	}
	if event.Done != nil {
		progress := fmt.Sprintf("%s=%d", event.Unit, *event.Done)
		if event.Total != nil {
			progress += fmt.Sprintf("/%d", *event.Total)
		}
		fields = append(fields, progress)
	}
	if event.Type == scanevents.TypePhaseFinished || event.Type == scanevents.TypeScanFinished {
		fields = append(fields, fmt.Sprintf("duration_ms=%d", event.DurationMS))
	}
	if len(event.Reasons) > 0 {
		fields = append(fields, "reasons="+strings.Join(event.Reasons, ","))
	}
	if len(event.Limits) > 0 {
		fields = append(fields, "limits="+strings.Join(event.Limits, ","))
	}
	if event.StopReason != "" {
		fields = append(fields, "stop_reason="+event.StopReason)
	}
	if event.Type == scanevents.TypeFindingNew {
		fields = append(fields, "module="+event.ModuleID, "severity="+event.Severity)
		if origin := swarmRuntimeOrigin(event.URL); origin != "" {
			fields = append(fields, "origin="+origin)
		}
	}
	if event.Type == scanevents.TypeModuleError || event.Type == scanevents.TypeExtensionFailed {
		fields = append(fields, "module="+event.ModuleID)
		if event.ErrorKind != "" {
			fields = append(fields, "kind="+event.ErrorKind)
		}
		if event.Stage != "" {
			fields = append(fields, "stage="+event.Stage)
		}
		if event.Count != nil {
			fields = append(fields, fmt.Sprintf("count=%d", *event.Count))
		}
	}
	if event.Type == scanevents.TypeScanSetup {
		fields = append(fields, "component="+event.Component, "state="+event.State)
	}
	if event.Type == scanevents.TypeError || event.Message != "" {
		fields = append(fields, "error recorded; see scan details")
	}
	agent.WriteRuntimeProgress(writer, "native", event.Phase, strings.Join(fields, " "))
}

// Only the origin is safe to forward: userinfo, query, fragments AND path
// segments (password-reset links, signed download URLs) can carry credentials.
func swarmRuntimeOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}
