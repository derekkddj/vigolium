// Package sessionlog records an olium engine run as a Pi-compatible JSONL
// session transcript for debugging. Each run is an append-only event tree:
// a `session` header, then `model_change` + `thinking_level_change`, then
// `message` lines (role user / assistant / toolResult) chained via parentId.
// The shape mirrors the Pi coding agent's session logs so the same viewers
// that read a Pi transcript can read a vigolium one.
//
// A Recorder implements engine.EventRecorder: the engine tees every event
// (plus each initiating user prompt) through it at a single chokepoint. The
// recorder coalesces the engine's delta-level events into message records —
// thinking/text deltas accumulate within a provider attempt and flush as an
// assistant message on EventTurnDone or a partial message on EventStreamRetry.
// Each EventToolExecEnd becomes a toolResult message with
// the complete tool-returned output and its structured receipt details. Tools
// may already have clipped/omitted content; recording cannot recover that or
// provider-opaque reasoning. Only surfaced events are persisted.
//
// Fidelity note: the transcript is structurally Pi-compatible and readable,
// but a few provider-opaque fields Pi persists for *resume* — per-message
// signatures, the per-component cost split, the provider responseId — are not
// surfaced at olium's event layer and so are omitted or best-effort. The log
// is for reading and debugging, not for replaying back into Pi.
package sessionlog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// Filename is the conventional name of the transcript file within a session
// directory. The writers (pkg/olium runner + autopilot) and the `vigolium log`
// reader all reference this single const so the name can't drift between them.
const Filename = "transcript.jsonl"

// sessionFormatVersion matches the Pi session log schema version so Pi
// viewers accept the file.
const sessionFormatVersion = 3

// defaultThinkingLevel is emitted when the caller doesn't supply one; "medium"
// matches Pi's default reasoning level.
const defaultThinkingLevel = "medium"

// Meta carries the per-session header values written once at the top of the
// transcript. All fields are optional: SessionID is generated when empty and
// ThinkingLevel defaults to "medium".
type Meta struct {
	SessionID     string // session UUID; generated if empty
	Provider      string // provider name (e.g. "anthropic-api-key")
	Model         string // resolved model id
	ThinkingLevel string // reasoning effort: low|medium|high
	Cwd           string // working directory for the run
}

type transcriptFile interface {
	io.Writer
	Sync() error
	Close() error
}

// Recorder writes a Pi-compatible JSONL transcript for one engine session.
// It implements engine.EventRecorder and io.Closer. Safe for the engine's
// sequential calls; an internal mutex also guards against an accidental
// concurrent Close.
type Recorder struct {
	mu     sync.Mutex
	f      transcriptFile
	meta   Meta
	closed bool
	err    error  // sticky: after a failed line, appending could corrupt the JSONL chain
	lastID string // parent-chain head; "" => next parentId is null

	// Per-turn accumulators for the deltas that make up one assistant
	// message. Reset on each flush.
	think strings.Builder
	text  strings.Builder
}

// New opens (creating parent dirs as needed) the transcript file at path in
// append mode and writes the session header. An empty path is an error so
// callers must gate on a configured session directory before constructing a
// recorder.
func New(path string, meta Meta) (*Recorder, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sessionlog: empty path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("sessionlog: mkdir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sessionlog: open %s: %w", path, err)
	}
	return newWithFile(f, meta)
}

// newWithFile also provides deterministic fault injection for recorder tests.
func newWithFile(f transcriptFile, meta Meta) (*Recorder, error) {
	if strings.TrimSpace(meta.SessionID) == "" {
		meta.SessionID = uuid.NewString()
	}
	if strings.TrimSpace(meta.ThinkingLevel) == "" {
		meta.ThinkingLevel = defaultThinkingLevel
	}
	r := &Recorder{f: f, meta: meta}
	r.mu.Lock()
	r.writeHeaderLocked()
	r.mu.Unlock()
	if r.Err() != nil {
		return nil, r.Close()
	}
	return r, nil
}

// Err reports recording health without interrupting the observed run. Once a
// marshal/write fails, recording stops; Close also reports this error.
func (r *Recorder) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// UserPrompt records the user message that seeds a Run. Any unflushed
// assistant turn from a prior interrupted Run is flushed first so it is not
// merged into the next assistant message.
func (r *Recorder) UserPrompt(prompt string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	r.flushAssistantLocked(nil, "interrupted", nil)
	id := newID()
	r.writeChainedLocked(id, messageEvt{
		Type:      "message",
		ID:        id,
		ParentID:  r.parentPtr(),
		Timestamp: nowISO(),
		Message: userMsg{
			Role:      "user",
			Content:   []any{textPart{Type: "text", Text: prompt}},
			Timestamp: nowMillis(),
		},
	})
}

// Record consumes one engine event. Thinking/text deltas accumulate;
// EventTurnDone flushes the assistant message; EventToolExecEnd emits a
// toolResult message; EventStreamRetry flushes a partial attempt and records
// its nonterminal boundary; EventError records a terminal error line. Every other
// event type (tool-exec start/progress, toolcall_start, run_done, info) is
// intentionally ignored — the data the transcript needs is already captured
// by the events above.
func (r *Recorder) Record(ev engine.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	switch ev.Type {
	case engine.EventThinkingDelta:
		r.think.WriteString(ev.Delta)
	case engine.EventTextDelta:
		r.text.WriteString(ev.Delta)
	case engine.EventTurnDone:
		r.flushAssistantLocked(ev.ToolCalls, string(ev.StopReason), ev.Usage)
	case engine.EventStreamRetry:
		r.flushAssistantLocked(ev.ToolCalls, "interrupted", ev.Usage)
		id := newID()
		r.writeChainedLocked(id, streamRetryEvt{
			Type:      "stream_retry",
			ID:        id,
			ParentID:  r.parentPtr(),
			Timestamp: nowISO(),
			Attempt:   ev.Attempt,
			Error:     ev.Err,
		})
	case engine.EventToolExecEnd:
		id := newID()
		r.writeChainedLocked(id, messageEvt{
			Type:      "message",
			ID:        id,
			ParentID:  r.parentPtr(),
			Timestamp: nowISO(),
			Message: toolResultMsg{
				Role:       "toolResult",
				ToolCallID: ev.ToolCallID,
				ToolName:   ev.ToolName,
				Content:    []any{textPart{Type: "text", Text: ev.ToolResult}},
				IsError:    ev.ToolIsErr,
				Details:    ev.ToolDetails,
				Timestamp:  nowMillis(),
			},
		})
	case engine.EventError:
		// Non-Pi but useful for debugging: record a terminal engine error as
		// a standalone line. Pi viewers ignore unknown event types.
		id := newID()
		r.flushAssistantLocked(nil, "error", nil)
		r.writeChainedLocked(id, errorEvt{
			Type:      "error",
			ID:        id,
			ParentID:  r.parentPtr(),
			Timestamp: nowISO(),
			Error:     ev.Err,
		})
	}
}

// SectionStart records the opening of a durable-autopilot bounded section.
// Any unflushed assistant turn from the prior section is flushed first so the
// boundary reads cleanly. Additive, non-Pi event (viewers ignore it). Safe for
// the engine's single-writer discipline; operator sections are serial.
func (r *Recorder) SectionStart(id string, seq int, kind, task string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	r.flushAssistantLocked(nil, "interrupted", nil)
	evtID := newID()
	r.writeChainedLocked(evtID, sectionStartEvt{
		Type:      "section_start",
		ID:        evtID,
		ParentID:  r.parentPtr(),
		Timestamp: nowISO(),
		SectionID: id,
		Seq:       seq,
		Kind:      kind,
		Task:      task,
	})
}

// SectionEnd records the close of a durable-autopilot bounded section along
// with its rotation reason and closing summary.
func (r *Recorder) SectionEnd(id, status, rotationReason, summary string, durationMs int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	r.flushAssistantLocked(nil, "interrupted", nil)
	evtID := newID()
	r.writeChainedLocked(evtID, sectionEndEvt{
		Type:           "section_end",
		ID:             evtID,
		ParentID:       r.parentPtr(),
		Timestamp:      nowISO(),
		SectionID:      id,
		Status:         status,
		RotationReason: rotationReason,
		Summary:        summary,
		DurationMs:     durationMs,
	})
}

// SectionInterrupted records a section that was interrupted (e.g. a run
// resumed after a crash marks any still-running section this way).
func (r *Recorder) SectionInterrupted(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	r.flushAssistantLocked(nil, "interrupted", nil)
	evtID := newID()
	r.writeChainedLocked(evtID, sectionInterruptedEvt{
		Type:      "section_interrupted",
		ID:        evtID,
		ParentID:  r.parentPtr(),
		Timestamp: nowISO(),
		SectionID: id,
	})
}

// Close flushes any assistant turn that never reached its turn_done (e.g. a
// run cancelled mid-stream) and closes the file. Idempotent.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.err
	}
	r.flushAssistantLocked(nil, "interrupted", nil)
	r.closed = true
	if r.f != nil {
		if err := r.f.Sync(); err != nil {
			r.err = errors.Join(r.err, fmt.Errorf("sessionlog: sync: %w", err))
		}
		if err := r.f.Close(); err != nil {
			r.err = errors.Join(r.err, fmt.Errorf("sessionlog: close: %w", err))
		}
		r.f = nil
	}
	return r.err
}

// writeHeaderLocked writes the session header (session + model_change +
// thinking_level_change) once, at construction time. Caller must hold r.mu.
func (r *Recorder) writeHeaderLocked() {
	// session — standalone header, not part of the parentId chain (lastID
	// stays empty so the first chained node below gets parentId: null, as Pi
	// does).
	r.writeLocked(sessionEvt{
		Type:      "session",
		Version:   sessionFormatVersion,
		ID:        r.meta.SessionID,
		Timestamp: nowISO(),
		Cwd:       r.meta.Cwd,
	})

	mcID := newID()
	r.writeChainedLocked(mcID, modelChangeEvt{
		Type:      "model_change",
		ID:        mcID,
		ParentID:  r.parentPtr(), // nil here -> "parentId": null
		Timestamp: nowISO(),
		Provider:  r.meta.Provider,
		ModelID:   r.meta.Model,
	})

	tlID := newID()
	r.writeChainedLocked(tlID, thinkingLevelEvt{
		Type:          "thinking_level_change",
		ID:            tlID,
		ParentID:      r.parentPtr(),
		Timestamp:     nowISO(),
		ThinkingLevel: r.meta.ThinkingLevel,
	})
}

// flushAssistantLocked writes the accumulated thinking/text plus the turn's
// tool calls as one assistant message, then resets the accumulators. A turn
// with nothing to show (no thinking, no text, no tool calls — e.g. a nudged
// empty turn) writes nothing. Caller must hold r.mu.
func (r *Recorder) flushAssistantLocked(toolCalls []stream.ToolCall, stopReason string, usage *stream.Usage) {
	if r.closed || r.err != nil {
		return
	}
	think := r.think.String()
	text := r.text.String()
	if think == "" && text == "" && len(toolCalls) == 0 {
		return
	}
	content := make([]any, 0, 2+len(toolCalls))
	if think != "" {
		content = append(content, thinkingPart{Type: "thinking", Thinking: think})
	}
	if text != "" {
		content = append(content, textPart{Type: "text", Text: text})
	}
	for _, tc := range toolCalls {
		args := tc.Arguments
		if args == nil {
			args = map[string]any{}
		}
		content = append(content, toolCallPart{
			Type:      "toolCall",
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: args,
		})
	}
	id := newID()
	r.writeChainedLocked(id, messageEvt{
		Type:      "message",
		ID:        id,
		ParentID:  r.parentPtr(),
		Timestamp: nowISO(),
		Message: assistantMsg{
			Role:       "assistant",
			Content:    content,
			Provider:   r.meta.Provider,
			Model:      r.meta.Model,
			Usage:      mapUsage(usage),
			StopReason: stopReason,
			Timestamp:  nowMillis(),
		},
	})
	if r.err == nil {
		r.think.Reset()
		r.text.Reset()
	}
}

// writeChainedLocked commits the chain head only after a complete line write.
func (r *Recorder) writeChainedLocked(id string, v any) {
	if r.writeLocked(v) {
		r.lastID = id
	}
}

// writeLocked stops at the first marshal/write failure. A short write may have
// left an incomplete JSON line, so continuing would produce misleading evidence.
// Errors are observable through Err/Close without taking down the agent run.
func (r *Recorder) writeLocked(v any) bool {
	if r.f == nil || r.closed || r.err != nil {
		return false
	}
	b, err := json.Marshal(v)
	if err != nil {
		r.err = fmt.Errorf("sessionlog: marshal: %w", err)
		return false
	}
	b = append(b, '\n')
	n, err := r.f.Write(b)
	if n != len(b) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	if err != nil {
		r.err = fmt.Errorf("sessionlog: write: %w", err)
		return false
	}
	return true
}

// parentPtr returns the current chain head as a pointer, or nil when the
// chain is empty so the field marshals to JSON null (matching Pi's first
// chained node).
func (r *Recorder) parentPtr() *string {
	if r.lastID == "" {
		return nil
	}
	id := r.lastID
	return &id
}

// newID returns an 8-hex-character event id, matching Pi's per-event ids.
func newID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively impossible; degrade to a
		// constant rather than panic in a debug-logging path.
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// nowISO formats the current UTC time as Pi's millisecond ISO-8601 stamp
// (e.g. "2026-06-03T09:03:45.863Z").
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// nowMillis is the epoch-millisecond stamp used inside message envelopes.
func nowMillis() int64 {
	return time.Now().UnixMilli()
}

// mapUsage converts the engine's flat usage into Pi's nested shape. olium
// surfaces only a single aggregate Cost, so it lands in cost.total with the
// per-component split left zero.
func mapUsage(u *stream.Usage) *usageObj {
	if u == nil {
		return nil
	}
	return &usageObj{
		Input:       u.Input,
		Output:      u.Output,
		CacheRead:   u.CacheRead,
		CacheWrite:  u.CacheWrite,
		TotalTokens: u.TotalTokens,
		Cost:        costObj{Total: u.Cost},
	}
}
