import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { HTTPRecord } from '@/api/types';
import { useHttpRecord } from '@/api/hooks';
import { getProjectUUID, onProjectNotFound, setBaseUrl, setProjectUUID, setToken } from '@/api/client';
import { fetchSelectedHttpRecord } from '@/lib/selectedRecordApi';

const scope = vi.hoisted(() => ({ project: 'project-a' as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: scope.project }) }));
const clients: QueryClient[] = [];
function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  return { client, Wrapper: ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> };
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const record = (uuid: string) => ({ uuid, raw_request: 'fetched-full-request', raw_response: 'fetched-full-response' } as HTTPRecord);
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  scope.project = 'project-a';
  setProjectUUID('project-a');
  setBaseUrl('https://api.example.invalid');
  setToken('record-fixture-token');
});
afterEach(() => { clients.forEach((client) => client.clear()); clients.length = 0; vi.unstubAllGlobals(); });

describe('Isolated full selected-record reads', () => {
  it('uses the hydrated storage snapshot for both query key and authenticated project header', async () => {
    scope.project = null;
    const fetcher = vi.fn().mockResolvedValue(json(record('selected')));
    vi.stubGlobal('fetch', fetcher);
    const { Wrapper, client } = wrapper();
    const { result } = renderHook(() => useHttpRecord('selected'), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.data).toEqual(record('selected')));
    expect(client.getQueryData(['project-a', 'http-record', 'selected'])).toEqual(record('selected'));
    expect(fetcher).toHaveBeenCalledWith('https://api.example.invalid/api/http-records/selected', expect.objectContaining({
      headers: expect.objectContaining({ Authorization: 'Bearer record-fixture-token', 'X-Project-UUID': 'project-a' }), signal: expect.any(AbortSignal),
    }));
  });

  it.each(['v1', 'v2'])('ignores a delayed old-project %s project_not_found without resetting B or retrying unscoped', async (version) => {
    const old = deferred<Response>();
    const fetcher = vi.fn().mockReturnValueOnce(old.promise).mockResolvedValueOnce(json(record('selected')));
    vi.stubGlobal('fetch', fetcher);
    const reset = vi.fn();
    const unsubscribe = onProjectNotFound(reset);
    try {
      const { Wrapper, client } = wrapper();
      const { result, rerender } = renderHook(() => useHttpRecord('selected'), { wrapper: Wrapper });
      await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
      const oldSignal = fetcher.mock.calls[0][1].signal as AbortSignal;
      scope.project = 'project-b'; setProjectUUID('project-b');
      rerender();
      expect(oldSignal.aborted).toBe(true);
      await waitFor(() => expect(result.current.data?.uuid).toBe('selected'));
      await act(async () => { old.resolve(json(version === 'v1'
        ? { error: 'project removed', error_code: 'project_not_found' }
        : { ok: false, error: { code: 'project_not_found', message: 'project removed' } }, 404)); });
      expect(getProjectUUID()).toBe('project-b');
      expect(reset).not.toHaveBeenCalled();
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(fetcher.mock.calls[1][1].headers['X-Project-UUID']).toBe('project-b');
      expect(client.getQueryData(['project-a', 'http-record', 'selected'])).toBeUndefined();
      expect(result.current.isError).toBe(false);
    } finally { unsubscribe(); }
  });

  it('cancels old UUID/project reads and discards successful responses even when fetch ignores abort', async () => {
    const first = deferred<Response>();
    const second = deferred<Response>();
    const fetcher = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise).mockResolvedValueOnce(json(record('new')));
    vi.stubGlobal('fetch', fetcher);
    const { Wrapper, client } = wrapper();
    const { result, rerender } = renderHook(({ uuid }) => useHttpRecord(uuid), { initialProps: { uuid: 'old' }, wrapper: Wrapper });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    rerender({ uuid: 'new' });
    expect(fetcher.mock.calls[0][1].signal.aborted).toBe(true);
    expect(result.current.data).toBeUndefined();
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    scope.project = 'project-b'; setProjectUUID('project-b');
    rerender({ uuid: 'new' });
    expect(fetcher.mock.calls[1][1].signal.aborted).toBe(true);
    await act(async () => { first.resolve(json(record('old'))); second.resolve(json(record('stale-a'))); });
    await waitFor(() => expect(result.current.data?.uuid).toBe('new'));
    expect(client.getQueryData(['project-a', 'http-record', 'old'])).toBeUndefined();
    expect(client.getQueryData(['project-a', 'http-record', 'new'])).toBeUndefined();
  });

  it('reports a current project_not_found locally without clearing the project or falling back', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ ok: false, error: { code: 'project_not_found', message: 'project removed' } }, 404));
    vi.stubGlobal('fetch', fetcher);
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useHttpRecord('selected'), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.error).toMatchObject({ status: 404, code: 'project_not_found' }));
    expect(getProjectUUID()).toBe('project-a');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('uses context when storage is absent, and intentionally omits the header only for a captured null scope', async () => {
    setProjectUUID(null);
    const fetcher = vi.fn().mockResolvedValueOnce(json(record('selected'))).mockResolvedValueOnce(json(record('default')));
    vi.stubGlobal('fetch', fetcher);
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useHttpRecord('selected'), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.data?.uuid).toBe('selected'));
    expect(fetcher.mock.calls[0][1].headers['X-Project-UUID']).toBe('project-a');
    setProjectUUID('mutable-other-project');
    await fetchSelectedHttpRecord('default', null, new AbortController().signal);
    expect(fetcher.mock.calls[1][1].headers).not.toHaveProperty('X-Project-UUID');
    expect(getProjectUUID()).toBe('mutable-other-project');
  });

  it('does not fetch a null selection', () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    const { Wrapper } = wrapper();
    renderHook(() => useHttpRecord(null), { wrapper: Wrapper });
    expect(fetcher).not.toHaveBeenCalled();
  });
});
