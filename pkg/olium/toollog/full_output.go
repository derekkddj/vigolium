package toollog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// WithFullOutput replaces abbreviated tool cards with full arguments/results in
// recorded operator logs. Configure before handling events. Raw bash streams are
// copied from the authoritative archive with bounded memory, not from its capped
// tool-returned preview. Empty sessionDir keeps the ordinary CLI summary mode.
func (l *Logger) WithFullOutput(sessionDir string) *Logger {
	if l != nil {
		l.fullDir = sessionDir
	}
	return l
}

// Err is sticky for this logger: a failed render must not imply a complete log.
// Archive evidence remains available independently of the runtime writer.
func (l *Logger) Err() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fullErr
}

// ReportIncomplete attempts a safe terminal marker after a sink recovers. It
// never contaminates assistant text or turns an evidence error into a retry.
func (l *Logger) ReportIncomplete() {
	if l.Err() != nil && l.w != nil {
		l.fullBlock(func(w io.Writer) error {
			_, err := io.WriteString(w, "\n[Runtime log incomplete: tool rendering failed; inspect retained invocation archives. No missing bytes reconstructed.]\n")
			return err
		})
	}
}

func (l *Logger) fullBlock(write func(io.Writer) error) {
	var err error
	if w, ok := l.w.(interface {
		WriteBlock(func(io.Writer) error) error
	}); ok {
		err = w.WriteBlock(write)
	} else {
		err = write(l.w)
	}
	if err != nil {
		l.mu.Lock()
		// Do not retain tool-controlled paths/body text in general warnings.
		first := l.fullErr == nil
		l.fullErr = errors.New("complete runtime tool rendering failed")
		l.mu.Unlock()
		if first {
			zap.L().Warn("Runtime tool log rendering degraded; use the private invocation archive for retained evidence")
		}
	}
}

func (l *Logger) writeFullStart(ev engine.Event) {
	l.fullBlock(func(w io.Writer) error {
		if _, err := fmt.Fprintf(w, "\nTool call %q: %s\n", ev.ToolCallID, ev.ToolName); err != nil {
			return err
		}
		args := ev.ToolArgs
		argsLabel := "Arguments (JSON):\n"
		if ev.ToolName == "bash" {
			if command, ok := args["command"].(string); ok {
				if _, err := fmt.Fprintf(w, "Command (verbatim):\n%s\n", command); err != nil {
					return err
				}
				argsLabel = "Arguments (JSON; bash command shown verbatim above):\n"
				args = make(map[string]any, len(ev.ToolArgs))
				for key, value := range ev.ToolArgs {
					if key != "command" {
						args[key] = value
					}
				}
			}
		}
		if _, err := io.WriteString(w, argsLabel); err != nil {
			return err
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(args); err != nil {
			_, _ = io.WriteString(w, "[Arguments could not be rendered; inspect the private invocation archive.]\n")
			return err
		}
		return nil
	})
}

func (l *Logger) writeFullEnd(ev engine.Event, elapsed time.Duration) {
	l.fullBlock(func(w io.Writer) error {
		status := "success"
		if ev.ToolIsErr {
			status = "failed"
		}
		if _, err := fmt.Fprintf(w, "\nTool result %q: %s — %s (%s)\n", ev.ToolCallID, ev.ToolName, status, formatElapsed(elapsed)); err != nil {
			return err
		}
		var degraded error
		receipt, archived := ev.ToolDetails[tool.ArchiveDetailsKey].(map[string]any)
		if archived && receipt["complete"] != true {
			if _, err := io.WriteString(w, "[Archive incomplete: full output retention is not guaranteed.]\n"); err != nil {
				return err
			}
		}
		streams, _ := receipt["streams"].(map[string]any)
		rawBash := ev.ToolName == "bash" && len(streams) > 0
		if rawBash {
			for _, name := range []string{"stdout", "stderr"} {
				entry, _ := streams[name].(map[string]any)
				path, _ := entry["path"].(string)
				if _, err := fmt.Fprintf(w, "%s (raw archived bytes):\n", name); err != nil {
					return err
				}
				if err := copyFullArtifact(w, l.fullDir, path, name+".bin", entry); err != nil {
					degraded = err
					if _, werr := io.WriteString(w, "\n[Archived stream unavailable, unreadable or changed since capture; displayed bytes are not verified. No replacement bytes fabricated.]\n"); werr != nil {
						return werr
					}
				}
				if _, err := io.WriteString(w, "\n"); err != nil {
					return err
				}
			}
		}
		// Bash raw streams are shown instead of the successful capped preview.
		// On failure also retain all returned execution/timeout annotations.
		if !rawBash || ev.ToolIsErr {
			label := "Result (tool-returned bytes before model truncation):\n"
			if ev.ToolName == "bash" {
				label = "Tool-returned result and execution annotations (shell preview may be capped; raw streams above are separate):\n"
			}
			if _, err := io.WriteString(w, label); err != nil {
				return err
			}
			if _, err := io.WriteString(w, ev.ToolResult); err != nil {
				return err
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
		if ev.ToolDetails != nil {
			if _, err := io.WriteString(w, "Original capture details (JSON; not proof of runtime rendering or current storage integrity):\n"); err != nil {
				return err
			}
			if err := json.NewEncoder(w).Encode(ev.ToolDetails); err != nil {
				return err
			}
		}
		return degraded
	})
}

// Copy only generated archive paths under the session root, never absolute/tool-
// controlled paths. Nonblocking opens reject FIFO replacements without waiting.
// Reads stop at the initial regular-file length; no whole-output allocation.
func copyFullArtifact(w io.Writer, sessionDir, relative, leaf string, expected map[string]any) error {
	parts := strings.Split(relative, "/")
	if len(parts) != 3 || !safeArchiveLabel(strings.Join(parts[:2], "/")) || parts[2] != leaf {
		return errors.New("invalid full-output archive path")
	}
	stored, validLength := archiveStoredLength(expected["stored_bytes"])
	digest, _ := expected["sha256"].(string)
	if !validLength || len(digest) != sha256.Size*2 {
		return errors.New("missing full-output integrity metadata")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return errors.New("invalid full-output digest")
	}
	root, err := os.OpenRoot(sessionDir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.FromSlash(relative)
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("full-output archive is not a regular file")
	}
	f, err := openFullArtifact(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return errors.New("full-output archive changed during open")
	}
	if info.Size() != stored {
		return errors.New("full-output archive length changed since capture")
	}
	hash := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(w, hash), f, stored); err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || !os.SameFile(info, after) {
		return errors.New("full-output archive changed while reading")
	}
	current, err := root.Lstat(name)
	if err != nil || !os.SameFile(info, current) || !current.Mode().IsRegular() || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), digest) {
		return errors.New("full-output archive integrity mismatch")
	}
	return nil
}

func archiveStoredLength(value any) (int64, bool) {
	switch n := value.(type) {
	case int64:
		return n, n >= 0
	case int:
		return int64(n), n >= 0
	case float64:
		if n >= 0 && n < 1<<63 && math.Trunc(n) == n {
			return int64(n), true
		}
	}
	return 0, false
}
