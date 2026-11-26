package runner

import (
	"io"
	"os"
)

// consoleRef boxes the writer so the runner can publish it atomically.
type consoleRef struct{ w io.Writer }

// stderr is where this runner writes its operator-facing console output.
//
// A scan's raw console output is persisted per scan (scan_logs trace entries
// and, with persist_logs, the session runtime.log). It used to be captured by
// redirecting the process-wide os.Stderr to the first scan that claimed it, so
// in server mode every concurrent scan's output — another project's traffic
// lines included — was stored under whichever scan held the claim (often the
// long-lived scan-on-receive runner), and the other scans stored none of their
// own. Each runner now writes to its own console: the real stderr plus that
// scan's own capture. Output that does not go through a runner's console is
// shown on stderr only and attributed to no scan.
func (r *Runner) stderr() io.Writer {
	if c := r.console.Load(); c != nil {
		return c.w
	}
	return os.Stderr
}

// setConsole installs (w != nil) or removes (w == nil) this runner's console.
func (r *Runner) setConsole(w io.Writer) {
	if w == nil {
		r.console.Store(nil)
		return
	}
	r.console.Store(&consoleRef{w: w})
}
