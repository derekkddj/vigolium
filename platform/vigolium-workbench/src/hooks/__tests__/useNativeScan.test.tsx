import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { useScan, useScanLogs } from '@/api/hooks';
import type { Scan } from '@/api/types';

const mocks = vi.hoisted(() => ({ project: 'project-a' }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: mocks.project }) }));
const scan = (uuid: string, status = 'completed'): Scan => ({ uuid, status, total_findings: 3, processed_count: 8, started_at: '', created_at: '' });
const clients: QueryClient[] = [];
function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  return { client, Wrapper: ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> };
}
function json(body: unknown) { return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } }); }
beforeEach(() => { mocks.project = 'project-a'; localStorage.setItem('vigolium_project_uuid', 'project-a'); });
afterEach(() => { clients.forEach((client) => client.clear()); clients.length = 0; vi.unstubAllGlobals(); });

describe('Single Native scan queries', () => {
  it('fetches a UUID absent from any history list and refetches updated status/counts', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(json(scan('outside-list', 'running'))).mockResolvedValueOnce(json({ ...scan('outside-list'), processed_count: 19, total_findings: 5 }));
    vi.stubGlobal('fetch', fetcher);
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useScan('outside-list'), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.data?.status).toBe('running'));
    expect(String(fetcher.mock.calls[0][0])).toContain('/api/scans/outside-list');
    await act(async () => { await result.current.refetch(); });
    await waitFor(() => expect(result.current.data).toMatchObject({ status: 'completed', total_findings: 5, processed_count: 19 }));
  });

  it('aborts old UUID/project requests and never shows stale A data in B', async () => {
    const pending: { signal: AbortSignal; resolve: (response: Response) => void; headers: Record<string, string> }[] = [];
    vi.stubGlobal('fetch', vi.fn((_url: string, options: { signal: AbortSignal; headers: Record<string, string> }) => new Promise<Response>((resolve) => pending.push({ ...options, resolve }))));
    const { Wrapper, client } = wrapper();
    const { result, rerender } = renderHook(({ uuid }) => useScan(uuid), { initialProps: { uuid: 'scan-a' }, wrapper: Wrapper });
    await waitFor(() => expect(pending).toHaveLength(1));
    rerender({ uuid: 'scan-b' });
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(pending[0].signal.aborted).toBe(true);
    expect(result.current.data).toBeUndefined();
    act(() => { mocks.project = 'project-b'; localStorage.setItem('vigolium_project_uuid', 'project-b'); });
    rerender({ uuid: 'scan-b' });
    await waitFor(() => expect(pending).toHaveLength(3));
    expect(pending[1].signal.aborted).toBe(true);
    expect(pending[2].headers['X-Project-UUID']).toBe('project-b');
    await act(async () => { pending[0].resolve(json(scan('scan-a'))); pending[1].resolve(json(scan('scan-b'))); pending[2].resolve(json({ ...scan('scan-b'), project_uuid: 'project-b', total_findings: 7 })); });
    await waitFor(() => expect(result.current.data?.total_findings).toBe(7));
    expect(client.getQueryData(['project-a', 'scan', 'scan-a'])).toBeUndefined();
  });

  it('does not fetch a null selection', () => {
    const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
    const { Wrapper } = wrapper();
    renderHook(() => useScan(null), { wrapper: Wrapper });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('retains fetched data when a later refresh fails, exposing an error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json(scan('one'))).mockResolvedValueOnce(new Response(JSON.stringify({ error: { message: 'temporarily unavailable', code: 'unavailable' } }), { status: 503 })));
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => {
      const query = useScan('one');
      return { data: query.data, isError: query.isError, error: query.error, refetch: query.refetch };
    }, { wrapper: Wrapper });
    await waitFor(() => expect(result.current.data?.uuid).toBe('one'));
    await act(async () => { await result.current.refetch(); });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(result.current.error?.message).toBe('temporarily unavailable');
    expect(result.current.data?.uuid).toBe('one');
  });
});

describe('Native scan logs over REST', () => {
  it.each(['logs', 'data', 'items'])('makes %s structured rows visible with source and total', async (key) => {
    const log = { id: 1, scan_uuid: 'one', message: 'structured message', level: 'info', created_at: '' };
    const fetcher = vi.fn().mockResolvedValue(json({ [key]: [log], total: 401, offset: 200, limit: 200, has_more: true, source: 'retained-db' }));
    vi.stubGlobal('fetch', fetcher);
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useScanLogs('one', { offset: 200, limit: 200 }), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.data?.logs).toEqual([log]));
    expect(result.current.data).toMatchObject({ total: 401, offset: 200, has_more: true, source: 'retained-db' });
    expect(String(fetcher.mock.calls[0][0])).toContain('max_bytes=262144');
    expect(String(fetcher.mock.calls[0][0])).toContain('offset=200');
  });
  it.each([undefined, 'true', 'false'])('retains text and only reports known truncation (%j)', async (truncated) => {
    const headers: Record<string, string> = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (truncated !== undefined) { headers['X-Log-Truncated'] = truncated; headers['X-Log-Size'] = '999999'; }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('runtime tail', { headers })));
    const { Wrapper } = wrapper();
    const { result } = renderHook(() => useScanLogs('one'), { wrapper: Wrapper });
    await waitFor(() => expect(result.current.data?.text).toBe('runtime tail'));
    expect(result.current.data?.total).toBeUndefined();
    expect(result.current.data?.truncated).toBe(truncated === undefined ? undefined : truncated === 'true');
    expect(result.current.data?.log_size).toBe(truncated === undefined ? undefined : 999999);
  });
});
