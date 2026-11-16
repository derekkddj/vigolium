package tool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ArchiveDetailsKey identifies a private, session-relative evidence receipt.
// It contains paths/counts/status only, never tool parameters or output. Consumers
// hydrate these files through the existing authenticated, project-scoped session
// artifacts API (download=1 for a full streamed export).
const ArchiveDetailsKey = "tool_archive"

// ArchiveDirectory is relative to the private session directory. Archive receipt
// paths are rooted here and are accepted unchanged by session artifact hydration.
const ArchiveDirectory = "tool-archive"

type archiveContextKey struct{}

type archiveFile struct {
	f      *os.File
	hash   hash.Hash
	seen   int64
	stored int64
	err    error
}

// CallArchive is an append-only archive for one invocation, not one provider ID.
// Reused/malicious provider IDs never enter filenames. Streams are raw bytes;
// JSON metadata retains []byte details as base64 and never substitutes text for
// binary evidence. A lifecycle with no completion record means an interrupted
// archive, not a claim that historical bytes were captured.
//
// All writes are synchronous before returning to the tool/model path. Raw-stream
// and result writes bound extra memory by chunk size, not output size. Archive
// errors degrade observability, not execution; inspect Err or the result receipt.
// Finish or Close must be called on every path, including cancellation/failure.
type CallArchive struct {
	mu        sync.Mutex
	root      *os.Root
	lifecycle *os.File
	path      string
	id        string
	files     map[string]*archiveFile
	closed    bool
	err       error
	receipt   map[string]any
}

// NewCallArchive durably stores full decoded tool arguments BEFORE execution.
// sessionDir must already exist and be the private directory for the scoped run.
// All file operations are rooted there, including symlink-aware containment.
func NewCallArchive(sessionDir, callID, toolName string, args map[string]any) (*CallArchive, error) {
	root, err := os.OpenRoot(sessionDir)
	if err != nil {
		return nil, fmt.Errorf("tool archive: open session: %w", err)
	}
	a := &CallArchive{root: root, files: make(map[string]*archiveFile)}
	fail := func(err error) (*CallArchive, error) {
		if a.lifecycle != nil {
			err = errors.Join(err, a.lifecycle.Close())
		}
		return nil, errors.Join(err, root.Close())
	}
	if err := root.Mkdir(ArchiveDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fail(fmt.Errorf("tool archive: mkdir: %w", err))
	}
	for attempts := 0; attempts < 8; attempts++ {
		id, idErr := uuid.NewRandom()
		if idErr != nil {
			return fail(fmt.Errorf("tool archive: allocate id: %w", idErr))
		}
		a.id = id.String()
		a.path = filepath.Join(ArchiveDirectory, a.id)
		if err = root.Mkdir(a.path, 0o700); !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return fail(fmt.Errorf("tool archive: allocate call: %w", err))
	}
	if args == nil {
		args = map[string]any{}
	}
	if err := a.writeJSONLocked("arguments.json", map[string]any{
		"version": 1, "archive_id": a.id, "tool_call_id": callID,
		"tool_name": toolName, "arguments": args,
	}); err != nil {
		return fail(err)
	}
	if err := a.appendLifecycleLocked(map[string]any{
		"type": "start", "version": 1, "archive_id": a.id,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return fail(err)
	}
	// Persist the new directory entries as well as the file bytes. A success
	// receipt must not be issued for a call whose parameters never reached disk.
	for _, dir := range []string{a.path, ArchiveDirectory, "."} {
		if err := a.syncDirectoryLocked(dir); err != nil {
			return fail(err)
		}
	}
	return a, nil
}

// WithCallArchive associates a per-call archive with the tool context; it is not
// process-global, so concurrent runs/projects cannot share output accidentally.
// A nil archive explicitly clears an inherited enclosing-call archive.
func WithCallArchive(ctx context.Context, a *CallArchive) context.Context {
	return context.WithValue(ctx, archiveContextKey{}, a)
}

func callArchiveFrom(ctx context.Context) *CallArchive {
	a, _ := ctx.Value(archiveContextKey{}).(*CallArchive)
	return a
}

// ArchiveExecution is the engine integration boundary. Wrap the ENTIRE dispatch
// (including lookup/invalid arguments/timeout annotation) in execute, before any
// model shrink/spill/hook and before emitting ToolExecEnd. Even tiny results and
// failed calls are archived. Empty sessionDir explicitly disables archiving.
func ArchiveExecution(ctx context.Context, sessionDir, callID, toolName string, args map[string]any, execute func(context.Context) Result) Result {
	if sessionDir == "" {
		return execute(WithCallArchive(ctx, nil))
	}
	a, err := NewCallArchive(sessionDir, callID, toolName, args)
	if err != nil {
		// Never inherit an enclosing invocation's archive on a failure: that
		// would silently attribute this call's output to another call/project.
		res := execute(WithCallArchive(ctx, nil))
		return withArchiveReceipt(res, map[string]any{"version": 1, "status": "failed", "complete": false, "error": "initialization_failed"})
	}
	defer a.Close() // also closes on panic; interrupted lifecycle remains explicit
	res := execute(WithCallArchive(ctx, a))
	return withArchiveReceipt(res, a.Finish(res))
}

func withArchiveReceipt(res Result, receipt map[string]any) Result {
	// Do not mutate a tool's shared details map; preserve existing capture
	// receipts (including BLOB/base64 payloads) without overwriting their keys.
	details := make(map[string]any, len(res.Details)+1)
	for key, value := range res.Details {
		details[key] = value
	}
	details[ArchiveDetailsKey] = receipt
	res.Details = details
	return res
}

// WriteStream stores raw stdout, stderr or their observed combined ordering.
// A stream's error is sticky: later bytes are counted as observed, not fabricated
// as retained. Invalid stream names are rejected instead of becoming file paths.
func (a *CallArchive) WriteStream(stream string, p []byte) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	switch stream {
	case "stdout", "stderr", "combined":
	default:
		a.err = errors.Join(a.err, errors.New("tool archive: invalid stream"))
		return
	}
	f := a.files[stream]
	if f == nil {
		f = &archiveFile{hash: sha256.New()}
		a.files[stream] = f
		f.f, f.err = a.root.OpenFile(filepath.Join(a.path, stream+".bin"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if f.err != nil {
			a.err = errors.Join(a.err, f.err)
		}
	}
	f.seen += int64(len(p))
	if f.err != nil {
		return
	}
	n, err := f.f.Write(p)
	if n > 0 {
		_, _ = f.hash.Write(p[:n])
		f.stored += int64(n)
	}
	if n != len(p) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	if err != nil {
		f.err = err
		a.err = errors.Join(a.err, err)
	}
}

// markStreamsIncomplete records a pipe-drain failure separately from disk
// retention. Observed bytes can all be stored while unseen trailing bytes are
// missing; such a receipt must never claim complete stdout/stderr capture.
func (a *CallArchive) markStreamsIncomplete() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	err := errors.New("tool archive: output pipe did not drain completely")
	a.err = errors.Join(a.err, err)
	for _, f := range a.files {
		f.err = errors.Join(f.err, err)
	}
}

// Err reports archive health without exposing command/result bytes.
func (a *CallArchive) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// Finish stores the complete tool-returned result (before model truncation) and
// its original structured details. It fsyncs/closes streams before appending the
// final lifecycle receipt. Raw streams may be complete even when the command
// failed/timed out; this records captured bytes, not successful tool execution.
// The result.bin file is the exact byte sequence; result metadata is never the
// canonical representation for binary output. Idempotent; no files overwritten.
func (a *CallArchive) Finish(res Result) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return a.receipt
	}
	resultPath := filepath.Join(a.path, "result.bin")
	f, err := a.root.OpenFile(resultPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	var stored int64
	resultHash := sha256.New()
	if err == nil {
		// Hide strings.Reader.WriteTo so hashing never converts a whole large
		// result to a second []byte allocation. io.Copy uses a bounded buffer.
		stored, err = io.Copy(io.MultiWriter(f, resultHash), struct{ io.Reader }{strings.NewReader(res.Content)})
		err = errors.Join(err, f.Sync(), f.Close())
	}
	a.err = errors.Join(a.err, err)
	a.err = errors.Join(a.err, a.writeJSONLocked("result-metadata.json", map[string]any{
		"version": 1, "archive_id": a.id, "is_error": res.IsError, "details": res.Details,
		"result_bytes": len(res.Content), "stored_bytes": stored,
	}))
	receipt := a.finishStreamsLocked()
	receipt["result"] = filepath.ToSlash(resultPath)
	receipt["result_bytes"] = len(res.Content)
	receipt["result_stored_bytes"] = stored
	receipt["result_sha256"] = hex.EncodeToString(resultHash.Sum(nil))
	receipt["arguments"] = filepath.ToSlash(filepath.Join(a.path, "arguments.json"))
	receipt["metadata"] = filepath.ToSlash(filepath.Join(a.path, "result-metadata.json"))
	a.completeLocked(receipt, "finish")
	return a.receipt
}

// Close releases every descriptor, marking an unfinished invocation interrupted.
// It never promotes an unfinished archive to complete. Idempotent, including
// errors; concurrent Close and Finish are serialized.
func (a *CallArchive) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		a.completeLocked(a.finishStreamsLocked(), "interrupted")
	}
	return a.err
}

func (a *CallArchive) finishStreamsLocked() map[string]any {
	streams := make(map[string]any, len(a.files))
	for name, f := range a.files {
		if f.f != nil {
			f.err = errors.Join(f.err, f.f.Sync(), f.f.Close())
			f.f = nil
			a.err = errors.Join(a.err, f.err)
		}
		streams[name] = map[string]any{
			"path":           filepath.ToSlash(filepath.Join(a.path, name+".bin")),
			"observed_bytes": f.seen, "stored_bytes": f.stored,
			"sha256": hex.EncodeToString(f.hash.Sum(nil)), "complete": f.err == nil,
		}
	}
	return map[string]any{"version": 1, "archive_id": a.id,
		"path": filepath.ToSlash(a.path), "streams": streams}
}

func (a *CallArchive) completeLocked(receipt map[string]any, kind string) {
	receipt["complete"] = kind == "finish" && a.err == nil
	receipt["status"] = "complete"
	if kind != "finish" {
		receipt["status"] = "interrupted"
	}
	if a.err != nil {
		receipt["status"] = "partial"
		receipt["error"] = "archive_io_failed"
	}
	a.err = errors.Join(a.err, a.syncDirectoryLocked(a.path))
	// Refresh after the directory sync; a durable receipt cannot conceal it.
	if a.err != nil {
		receipt["complete"] = false
		receipt["status"] = "partial"
		receipt["error"] = "archive_io_failed"
	}
	a.err = errors.Join(a.err, a.appendLifecycleLocked(map[string]any{
		"type": kind, "timestamp": time.Now().UTC().Format(time.RFC3339Nano), "receipt": receipt,
	}))
	if a.lifecycle != nil {
		a.err = errors.Join(a.err, a.lifecycle.Close())
		a.lifecycle = nil
	}
	if a.root != nil {
		a.err = errors.Join(a.err, a.root.Close())
		a.root = nil
	}
	if a.err != nil {
		receipt["complete"] = false
		receipt["status"] = "partial"
		receipt["error"] = "archive_io_failed"
	}
	a.receipt = receipt
	a.closed = true
}

func (a *CallArchive) writeJSONLocked(name string, value any) error {
	f, err := a.root.OpenFile(filepath.Join(a.path, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// Marshal before writing so a failed value cannot leave a plausible prefix.
	b, err := json.Marshal(value)
	if err == nil {
		var n int
		b = append(b, '\n')
		n, err = f.Write(b)
		if n != len(b) {
			err = errors.Join(err, io.ErrShortWrite)
		}
	}
	return errors.Join(err, f.Sync(), f.Close())
}

func (a *CallArchive) appendLifecycleLocked(value any) error {
	if a.lifecycle == nil {
		var err error
		a.lifecycle, err = a.root.OpenFile(filepath.Join(a.path, "lifecycle.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
	}
	// Keep the exclusively-created descriptor open for the entire lifecycle;
	// never reopen a mutable pathname that could alias an older call's log.
	b, err := json.Marshal(value)
	if err == nil {
		b = append(b, '\n')
		var n int
		n, err = a.lifecycle.Write(b)
		if n != len(b) {
			err = errors.Join(err, io.ErrShortWrite)
		}
	}
	return errors.Join(err, a.lifecycle.Sync())
}

func (a *CallArchive) syncDirectoryLocked(name string) error {
	f, err := a.root.Open(name)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
