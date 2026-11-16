'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { buildApiUrl, buildAuthHeaders, errorMessageFromBody } from '@/api/client';
import { isTerminalAgentStatus } from '@/api/types';
import { useProjectContext } from '@/contexts/ProjectContext';

export type AgentLogConnection = 'idle' | 'connecting' | 'connected' | 'retrying' | 'complete' | 'error' | 'exhausted';

export interface AgentSessionLogsState {
  logs: string;
  /** A connected log follower, not the agent run's lifecycle status. */
  isStreaming: boolean;
  connection: AgentLogConnection;
  error: string | null;
  /** Sticky for this project/session, independent of markers in the tail. */
  truncated: boolean;
  logSize: number | null;
  retry: () => void;
}

const MAX_LOG_BYTES = 512 * 1024;
// JS strings use UTF-16 code units, not bytes. Bound both the staging buffer
// and React text to this many units (at most ~1 MiB each), without splitting
// surrogate pairs. Terminal requests additionally have a 512 KiB byte cap.
export const MAX_LOG_CODE_UNITS = 512 * 1024;
const MAX_SSE_FRAME_CODE_UNITS = 4 * MAX_LOG_CODE_UNITS;
const FLUSH_INTERVAL_MS = 250;
const MAX_RECONNECTS = 50;
const MAX_FAILURE_RETRIES = 6;
const MAX_NOT_FOUND_RETRIES = 6;

export function capAgentLogTail(text: string, limit = MAX_LOG_CODE_UNITS): { text: string; truncated: boolean } {
  if (text.length <= limit) return { text, truncated: false };
  let start = text.length - limit;
  // If the boundary lands on the low half of a pair, omit the whole rune.
  const code = text.charCodeAt(start);
  if (code >= 0xdc00 && code <= 0xdfff && start > 0) {
    const previous = text.charCodeAt(start - 1);
    if (previous >= 0xd800 && previous <= 0xdbff) start++;
  }
  return { text: text.slice(start), truncated: true };
}

interface Snapshot {
  key: string;
  logs: string;
  connection: AgentLogConnection;
  error: string | null;
  truncated: boolean;
  logSize: number | null;
}

function emptySnapshot(key: string): Snapshot {
  return { key, logs: '', connection: 'idle', error: null, truncated: false, logSize: null };
}

function hasOmissionMarker(text: string): boolean {
  return text.includes('...[earlier output omitted]...') || text.includes('...[truncated head]...');
}

export function useAgentSessionLogs(uuid: string | null, status?: string): AgentSessionLogsState {
  const { projectUUID } = useProjectContext();
  const key = JSON.stringify([projectUUID, uuid]);
  const [state, setState] = useState<Snapshot>(() => emptySnapshot(key));
  const stateRef = useRef(state);
  const generationRef = useRef(0);
  const [retryVersion, setRetryVersion] = useState(0);
  const retry = useCallback(() => setRetryVersion((version) => version + 1), []);
  // Poll-induced status changes don't reconnect until the run becomes terminal.
  const terminal = isTerminalAgentStatus(status);

  useEffect(() => {
    const generation = ++generationRef.current;
    const abort = new AbortController();
    const current = () => !abort.signal.aborted && generation === generationRef.current;
    let snapshot = stateRef.current.key === key ? stateRef.current : emptySnapshot(key);
    const publish = (patch: Partial<Snapshot>) => {
      if (!current()) return;
      snapshot = { ...snapshot, ...patch };
      stateRef.current = snapshot;
      setState(snapshot);
    };
    publish({ connection: uuid ? 'connecting' : 'idle', error: null });
    if (!uuid) return () => abort.abort();

    const url = buildApiUrl(`/api/agent/sessions/${encodeURIComponent(uuid)}/logs?strip=1`);
    // Capture the scope for the entire generation, including retries. Reading
    // mutable localStorage alone can send an old session request to a new project.
    const headers = () => {
      const result = buildAuthHeaders({ sse: !terminal });
      if (projectUUID) result['X-Project-UUID'] = projectUUID;
      else delete result['X-Project-UUID'];
      return result;
    };
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let liveText = snapshot.logs;
    let omitted = snapshot.truncated;
    let fresh = true;
    const flush = () => {
      if (timer) clearTimeout(timer);
      timer = null;
      publish({ logs: liveText, truncated: omitted });
    };
    const push = (text: string) => {
      if (!current()) return;
      const combined = (fresh ? '' : liveText) + text;
      fresh = false;
      const tail = capAgentLogTail(combined);
      omitted ||= tail.truncated || hasOmissionMarker(combined);
      liveText = tail.text;
      if (!timer) timer = setTimeout(flush, FLUSH_INTERVAL_MS);
    };
    const sleep = (ms: number) => new Promise<void>((resolve) => {
      const finish = () => {
        clearTimeout(timeout);
        abort.signal.removeEventListener('abort', finish);
        resolve();
      };
      const timeout = setTimeout(finish, ms);
      abort.signal.addEventListener('abort', finish, { once: true });
      if (abort.signal.aborted) finish();
    });
    const httpError = async (res: Response) => {
      let message = res.statusText;
      try { message = errorMessageFromBody(await res.json(), message); } catch { /* non-JSON error */ }
      return `${res.status}: ${message}`;
    };

    (async () => {
      let reconnects = 0;
      let failures = 0;
      let notFound = 0;
      const scheduleRetry = async (message: string | null, attempt: number, limit: number, baseDelay: number) => {
        if (!current()) return false;
        if (attempt > limit) {
          publish({ connection: 'exhausted', error: `${message || 'Log connection closed'}. Automatic retries exhausted; retry the console tail manually.` });
          return false;
        }
        publish({ connection: 'retrying', error: message });
        await sleep(Math.min(baseDelay * 2 ** (attempt - 1), 8000));
        return current();
      };
      while (current()) {
        try {
          publish({ connection: 'connecting' });
          const res = await fetch(terminal ? `${url}&max_bytes=${MAX_LOG_BYTES}` : url, { headers: headers(), signal: abort.signal });
          if (!current()) return;
          if (!res.ok) {
            const message = await httpError(res);
            if (!current()) return;
            // Session directory creation can race the initial 202 response.
            if (!terminal && res.status === 404) {
              if (await scheduleRetry(message, ++notFound, MAX_NOT_FOUND_RETRIES, 1000)) continue;
            } else if (res.status >= 500 || res.status === 408 || res.status === 429) {
              if (await scheduleRetry(message, ++failures, MAX_FAILURE_RETRIES, 2000)) continue;
            } else {
              // In particular, do not endlessly retry authentication failures.
              publish({ connection: 'error', error: message });
            }
            return;
          }
          if (terminal) {
            const text = await res.text();
            if (!current()) return;
            const tail = capAgentLogTail(text);
            const sizeHeader = res.headers.get('X-Log-Size');
            const size = sizeHeader === null || sizeHeader.trim() === '' ? NaN : Number(sizeHeader);
            publish({
              logs: tail.text,
              connection: 'complete',
              error: null,
              truncated: snapshot.truncated || tail.truncated || hasOmissionMarker(text) || ['1', 'true'].includes(res.headers.get('X-Log-Truncated') || ''),
              logSize: Number.isSafeInteger(size) && size >= 0 ? size : null,
            });
            return;
          }
          reader = res.body?.getReader();
          if (!reader) throw new Error('No response body');
          publish({ connection: 'connected', error: null });
          fresh = true;
          let sawDone = false;
          let sawReconnect = false;
          const decoder = new TextDecoder();
          let buffer = '';
          while (current() && !sawDone && !sawReconnect) {
            const { done, value } = await reader.read();
            if (!current()) return;
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            // Bound malformed/unterminated frames too, not just displayed text.
            let newline: number;
            while ((newline = buffer.indexOf('\n')) !== -1) {
              const line = buffer.slice(0, newline);
              buffer = buffer.slice(newline + 1);
              if (line.length > MAX_SSE_FRAME_CODE_UNITS) throw new Error('Log event exceeds the console frame limit');
              if (!line.startsWith('data: ')) continue;
              const payload = line.slice(6).trim();
              if (!payload) continue;
              let parsed;
              try { parsed = JSON.parse(payload); } catch { push(payload); continue; }
              if (parsed?.type === 'chunk' && typeof parsed.text === 'string') push(parsed.text);
              else if (parsed?.type === 'error' && typeof parsed.error === 'string') throw new Error(parsed.error);
              else if (parsed?.type === 'done') sawDone = true;
              else if (parsed?.type === 'reconnect') sawReconnect = true;
            }
            if (buffer.length > MAX_SSE_FRAME_CODE_UNITS) throw new Error('Log event exceeds the console frame limit');
          }
          flush();
          if (!current()) return;
          if (sawDone) {
            publish({ connection: 'complete' });
            return;
          }
          if (!await scheduleRetry(null, ++reconnects, MAX_RECONNECTS, 2000)) return;
        } catch (err) {
          if (!current()) return;
          flush(); // Keep output already received before a network/read failure.
          const message = err instanceof Error ? err.message : 'Log connection failed';
          if (!await scheduleRetry(message, ++failures, MAX_FAILURE_RETRIES, 2000)) return;
        } finally {
          if (reader) {
            try { await reader.cancel(); } catch { /* already closed/aborted */ }
            reader.releaseLock();
            reader = undefined;
          }
        }
      }
    })();

    return () => {
      // Hand the bounded, not-yet-rendered tail to a same-key terminal fetch or
      // manual retry. A new project/session ignores this snapshot's old key.
      if (!terminal && current()) stateRef.current = { ...snapshot, logs: liveText, truncated: omitted };
      abort.abort();
      if (timer) clearTimeout(timer);
      void reader?.cancel().catch(() => { /* already closed/aborted */ });
    };
  }, [uuid, key, projectUUID, terminal, retryVersion]);

  // Hide previous-scope state immediately, even before effect cleanup runs.
  const visible = state.key === key ? state : emptySnapshot(key);
  return {
    logs: visible.logs,
    connection: visible.connection,
    isStreaming: visible.connection === 'connected',
    error: visible.error,
    truncated: visible.truncated,
    logSize: visible.logSize,
    retry,
  };
}
