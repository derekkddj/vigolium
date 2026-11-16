import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { capAgentLogTail, MAX_LOG_CODE_UNITS, useAgentSessionLogs } from '../useAgentSessionLogs';

const scope = vi.hoisted(() => ({ projectUUID: 'project-a' as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => scope }));

function sse(...events: object[]): Response {
  const body = events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join('');
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function eventRead(event: object): ReadableStreamReadResult<Uint8Array> {
  return { done: false, value: new TextEncoder().encode(`data: ${JSON.stringify(event)}\n\n`) };
}

// A reader that deliberately ignores abort/cancel, to exercise generation guards
// against late responses (rather than merely relying on fetch's abort behavior).
function readerResponse(read: ReturnType<typeof vi.fn>): Response {
  const reader = { read, cancel: vi.fn().mockResolvedValue(undefined), releaseLock: vi.fn() };
  return { ok: true, body: { getReader: () => reader } } as unknown as Response;
}

async function settle() {
  await act(async () => {
    for (let i = 0; i < 30; i++) await Promise.resolve();
  });
}

async function advance(ms: number) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
  await settle();
}

beforeEach(() => {
  vi.useFakeTimers();
  scope.projectUUID = 'project-a';
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('useAgentSessionLogs (live run)', () => {
  it('reconnects after reconnect and replaces, not duplicates, the replayed backlog', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'line 1\n' }, { type: 'reconnect' }))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'line 1\nline 2\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-1', 'running'));
    await settle();
    expect(result.current.logs).toBe('line 1\n');
    expect(result.current.connection).toBe('retrying');
    expect(result.current.isStreaming).toBe(false);
    await advance(2000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.current.connection).toBe('complete');
    expect(result.current.logs).toBe('line 1\nline 2\n');
  });

  it('retries an initial 404 while the session directory is being created', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('{"error":"session directory not found"}', { status: 404 }))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'started\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-2', 'running'));
    await settle();
    expect(result.current.connection).toBe('retrying');
    await advance(1000);
    expect(result.current.logs).toBe('started\n');
    expect(result.current.error).toBeNull();
  });

  it('does not reconnect after done, even if the polled status is still running', async () => {
    const fetchMock = vi.fn().mockResolvedValue(sse({ type: 'chunk', text: 'x\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-3', 'running'));
    await settle();
    expect(result.current.connection).toBe('complete');
    expect(result.current.isStreaming).toBe(false);
    await advance(60000);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps chunks alongside a network error, then retries and replaces replayed output', async () => {
    const read = vi.fn()
      .mockResolvedValueOnce(eventRead({ type: 'chunk', text: 'retained before failure\n' }))
      .mockRejectedValueOnce(new TypeError('network lost'));
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(readerResponse(read))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'retained before failure\nrecovered\n' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-network', 'running'));
    await settle();
    expect(result.current.logs).toBe('retained before failure\n');
    expect(result.current.error).toBe('network lost');
    expect(result.current.connection).toBe('retrying');
    expect(result.current.isStreaming).toBe(false);
    await advance(2000);
    expect(result.current.logs).toBe('retained before failure\nrecovered\n');
    expect(result.current.error).toBeNull();
    expect(result.current.connection).toBe('complete');
  });

  it('reports bounded retry exhaustion and permits manual retry', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('offline'));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-offline', 'running'));
    await settle();
    for (const delay of [2000, 4000, 8000, 8000, 8000, 8000]) await advance(delay);
    expect(fetchMock).toHaveBeenCalledTimes(7);
    expect(result.current.connection).toBe('exhausted');
    expect(result.current.error).toContain('Automatic retries exhausted');
    await advance(120000);
    expect(fetchMock).toHaveBeenCalledTimes(7);
    fetchMock.mockResolvedValue(sse({ type: 'chunk', text: 'online' }, { type: 'done' }));
    act(() => result.current.retry());
    await settle();
    expect(result.current.logs).toBe('online');
    expect(result.current.error).toBeNull();
    expect(result.current.connection).toBe('complete');
  });

  it('reports exhaustion after the bounded normal reconnect budget, retaining the tail', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(sse({ type: 'chunk', text: 'still running' }, { type: 'reconnect' })));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-reconnect-limit', 'running'));
    await settle();
    for (let i = 0; i < 50; i++) await advance(Math.min(2000 * 2 ** i, 8000));
    expect(fetchMock).toHaveBeenCalledTimes(51);
    expect(result.current.logs).toBe('still running');
    expect(result.current.connection).toBe('exhausted');
    expect(result.current.error).toContain('Automatic retries exhausted');
    await advance(120000);
    expect(fetchMock).toHaveBeenCalledTimes(51);
  });

  it('bounds initial 404 retries and does not retry authentication failures', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response('{"error":"missing"}', { status: 404 })));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-missing', 'running'));
    await settle();
    for (const delay of [1000, 2000, 4000, 8000, 8000, 8000]) await advance(delay);
    expect(result.current.connection).toBe('exhausted');
    expect(fetchMock).toHaveBeenCalledTimes(7);
    fetchMock.mockResolvedValue(new Response('{"error":"forbidden"}', { status: 403 }));
    act(() => result.current.retry());
    await settle();
    expect(result.current.connection).toBe('error');
    expect(result.current.error).toBe('403: forbidden');
    await advance(120000);
    expect(fetchMock).toHaveBeenCalledTimes(8);
  });

  it('recognizes an SSE omission marker even when no client-side cap is hit', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(sse({ type: 'chunk', text: '...[earlier output omitted]...\nshort tail' }, { type: 'reconnect' }))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'replayed short tail' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-server-omitted', 'running'));
    await settle();
    expect(result.current.logs.length).toBeLessThan(MAX_LOG_CODE_UNITS);
    expect(result.current.truncated).toBe(true);
    await advance(2000);
    expect(result.current.logs).toBe('replayed short tail');
    expect(result.current.truncated).toBe(true);
  });

  it('keeps omission state after the server marker is evicted and after reconnect', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(sse(
        { type: 'chunk', text: '...[earlier output omitted]...\n' },
        { type: 'chunk', text: 'a'.repeat(MAX_LOG_CODE_UNITS + 100) },
        { type: 'reconnect' },
      ))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'new tail' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-long', 'running'));
    await settle();
    expect(result.current.logs.length).toBe(MAX_LOG_CODE_UNITS);
    expect(result.current.logs).not.toContain('omitted');
    expect(result.current.truncated).toBe(true);
    await advance(2000);
    expect(result.current.logs).toBe('new tail');
    expect(result.current.truncated).toBe(true);
  });

  it('bounds batched text before flushing and never splits a surrogate pair', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(sse(
      { type: 'chunk', text: 'prefix😀' + 'a'.repeat(MAX_LOG_CODE_UNITS - 1) },
      { type: 'done' },
    )));
    const { result } = renderHook(() => useAgentSessionLogs('run-unicode', 'running'));
    await settle();
    expect(result.current.logs).toBe('a'.repeat(MAX_LOG_CODE_UNITS - 1));
    expect(result.current.truncated).toBe(true);
  });

  it('shows connected only while the follower is actually connected', async () => {
    const waiting = deferred<ReadableStreamReadResult<Uint8Array>>();
    const fetchMock = vi.fn().mockResolvedValue(readerResponse(vi.fn().mockReturnValue(waiting.promise)));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-connected', 'running'));
    expect(result.current.isStreaming).toBe(false);
    await settle();
    expect(result.current.connection).toBe('connected');
    expect(result.current.isStreaming).toBe(true);
    waiting.resolve(eventRead({ type: 'done' }));
    await settle();
    expect(result.current.isStreaming).toBe(false);
  });
});

describe('useAgentSessionLogs (finished run)', () => {
  it('caps terminal text and preserves the full log-size/truncation response headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('a'.repeat(600 * 1024), {
      headers: { 'Content-Type': 'text/plain', 'X-Log-Size': '9000000', 'X-Log-Truncated': 'true' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-4', 'completed_with_warnings'));
    await settle();
    expect(result.current.logs.length).toBe(MAX_LOG_CODE_UNITS);
    expect(result.current.logSize).toBe(9000000);
    expect(result.current.truncated).toBe(true);
    expect(result.current.connection).toBe('complete');
    expect(String(fetchMock.mock.calls[0][0])).toContain('max_bytes=524288');
    expect(fetchMock.mock.calls[0][1]?.headers?.Accept).toBeUndefined();
  });

  it('recognizes header-only truncation and does not invent missing metadata', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('small stripped tail', { headers: { 'X-Log-Size': '999999', 'X-Log-Truncated': '1' } }))
      .mockResolvedValueOnce(new Response('complete small log'));
    vi.stubGlobal('fetch', fetchMock);
    const { result, rerender } = renderHook(({ uuid }) => useAgentSessionLogs(uuid, 'completed'), { initialProps: { uuid: 'large' } });
    await settle();
    expect(result.current.truncated).toBe(true);
    expect(result.current.logSize).toBe(999999);
    rerender({ uuid: 'small' });
    await settle();
    expect(result.current.truncated).toBe(false);
    expect(result.current.logSize).toBeNull();
  });

  it('retries terminal network failures with backoff and retains response metadata', async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError('offline'))
      .mockResolvedValueOnce(new Response('saved tail', { headers: { 'X-Log-Size': '999999', 'X-Log-Truncated': 'true' } }));
    vi.stubGlobal('fetch', fetchMock);
    const { result } = renderHook(() => useAgentSessionLogs('run-terminal-network', 'completed'));
    await settle();
    expect(result.current.connection).toBe('retrying');
    expect(result.current.error).toBe('offline');
    await advance(2000);
    expect(result.current.logs).toBe('saved tail');
    expect(result.current.error).toBeNull();
    expect(result.current.truncated).toBe(true);
    expect(result.current.logSize).toBe(999999);
  });

  it('hands an unflushed bounded live tail to the terminal fetch before aborting', async () => {
    const waiting = deferred<ReadableStreamReadResult<Uint8Array>>();
    const read = vi.fn()
      .mockResolvedValueOnce(eventRead({ type: 'chunk', text: 'not flushed yet' }))
      .mockReturnValueOnce(waiting.promise);
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(readerResponse(read))
      .mockResolvedValueOnce(new Response('{"error":"not retained"}', { status: 404 })));
    const { result, rerender } = renderHook(({ status }) => useAgentSessionLogs('run-unflushed', status), { initialProps: { status: 'running' } });
    await settle();
    expect(result.current.logs).toBe(''); // Still within the 250 ms batching window.
    rerender({ status: 'completed' });
    await settle();
    expect(result.current.logs).toBe('not flushed yet');
    expect(result.current.error).toBe('404: not retained');
    waiting.resolve({ done: true, value: undefined });
    await settle();
  });

  it('retains live text while the terminal fetch is pending or fails', async () => {
    const terminal = deferred<Response>();
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'last live chunk' }, { type: 'done' }))
      .mockReturnValueOnce(terminal.promise));
    const { result, rerender } = renderHook(({ status }) => useAgentSessionLogs('run-finishing', status), { initialProps: { status: 'running' } });
    await settle();
    rerender({ status: 'completed' });
    expect(result.current.logs).toBe('last live chunk');
    terminal.resolve(new Response('{"error":"not retained"}', { status: 404 }));
    await settle();
    expect(result.current.logs).toBe('last live chunk');
    expect(result.current.error).toBe('404: not retained');
    expect(result.current.connection).toBe('error');
  });
});

describe('useAgentSessionLogs project isolation', () => {
  it('aborts and resets on project switch, rejecting late old-project chunks', async () => {
    const late = deferred<ReadableStreamReadResult<Uint8Array>>();
    const read = vi.fn()
      .mockResolvedValueOnce(eventRead({ type: 'chunk', text: '...[earlier output omitted]...\nproject-a secret' }))
      .mockReturnValueOnce(late.promise);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(readerResponse(read))
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'project-b output' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result, rerender } = renderHook(() => useAgentSessionLogs('same-uuid', 'running'));
    await settle();
    await advance(250);
    expect(result.current.logs).toContain('project-a secret');
    expect(result.current.truncated).toBe(true);
    scope.projectUUID = 'project-b';
    rerender();
    expect(result.current.logs).toBe('');
    expect(result.current.error).toBeNull();
    expect(result.current.truncated).toBe(false);
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
    await settle();
    expect(fetchMock.mock.calls[0][1].headers['X-Project-UUID']).toBe('project-a');
    expect(fetchMock.mock.calls[1][1].headers['X-Project-UUID']).toBe('project-b');
    late.resolve(eventRead({ type: 'chunk', text: 'late project-a secret' }));
    await settle();
    await advance(250);
    expect(result.current.logs).toBe('project-b output');
    expect(result.current.error).toBeNull();
  });

  it('does not publish late read exceptions or error bodies from the previous project', async () => {
    const lateRead = deferred<ReadableStreamReadResult<Uint8Array>>();
    const lateError = deferred<unknown>();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(readerResponse(vi.fn().mockReturnValue(lateRead.promise)))
      .mockResolvedValueOnce({ ok: false, status: 403, statusText: 'Forbidden', json: () => lateError.promise })
      .mockResolvedValueOnce(sse({ type: 'chunk', text: 'project-c output' }, { type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result, rerender } = renderHook(() => useAgentSessionLogs('same-uuid', 'running'));
    await settle();
    scope.projectUUID = 'project-b';
    rerender();
    await settle();
    scope.projectUUID = 'project-c';
    rerender();
    await settle();
    lateRead.reject(new Error('late project-a network error'));
    lateError.resolve({ error: 'late project-b permission error' });
    await settle();
    expect(result.current.logs).toBe('project-c output');
    expect(result.current.error).toBeNull();
    expect(result.current.connection).toBe('complete');
  });

  it('clears retained errors and stops backoff retries when switching projects', async () => {
    const read = vi.fn()
      .mockResolvedValueOnce(eventRead({ type: 'chunk', text: 'project-a text' }))
      .mockRejectedValueOnce(new Error('project-a error'));
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(readerResponse(read))
      .mockResolvedValueOnce(sse({ type: 'done' }));
    vi.stubGlobal('fetch', fetchMock);
    const { result, rerender } = renderHook(() => useAgentSessionLogs('same-uuid', 'running'));
    await settle();
    expect(result.current.error).toBe('project-a error');
    scope.projectUUID = 'project-b';
    rerender();
    expect(result.current.logs).toBe('');
    expect(result.current.error).toBeNull();
    await settle();
    await advance(120000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.current.connection).toBe('complete');
  });
});

describe('capAgentLogTail', () => {
  it('keeps complete astral characters or removes the entire boundary pair', () => {
    expect(capAgentLogTail('a😀bc', 4)).toEqual({ text: '😀bc', truncated: true });
    expect(capAgentLogTail('a😀bc', 3)).toEqual({ text: 'bc', truncated: true });
    expect(capAgentLogTail('😀bc', 4)).toEqual({ text: '😀bc', truncated: false });
    expect(capAgentLogTail('😀', 1)).toEqual({ text: '', truncated: true });
  });
});
