import type { ReactNode } from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setBaseUrl, setProjectUUID, setToken } from '@/api/client';
import { useAgentsLogic } from '../useAgentsLogic';

const project = vi.hoisted(() => ({ projectUUID: 'project-a' as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => project }));
vi.mock('@/lib/useAgentSessionLogs', () => ({ useAgentSessionLogs: () => ({ logs: '' }) }));
vi.mock('@/api/hooks', async importOriginal => {
  const actual = await importOriginal<typeof import('@/api/hooks')>();
  return {
    ...actual,
    useAgentSessions: () => ({ data: { data: [] } }),
    useAgentSessionDetail: () => ({}), useAgentRunStatus: () => ({}),
    useUploadRepo: () => ({}), useStartAutopilotRun: () => ({}), useStartAgentRun: () => ({}),
    // Cancellation deliberately uses the real TanStack mutation and API transport.
  };
});
function deferred() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>(done => { resolve = done; });
  return { promise, resolve };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false }, queries: { retry: false } } });
  const invalidations = vi.spyOn(client, 'invalidateQueries');
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return { ...renderHook(() => useAgentsLogic(), { wrapper }), invalidations };
}
const success = () => new Response(JSON.stringify({ status: 'cancelling' }), { headers: { 'Content-Type': 'application/json' } });
const refused = () => new Response(JSON.stringify({ error: 'run not found or already finished' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
beforeEach(() => {
  localStorage.clear(); project.projectUUID = 'project-a';
  setBaseUrl('https://api.example.invalid'); setProjectUUID('project-a'); setToken('fixture-token');
  window.history.replaceState({}, '', '/agentic-scan');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(success()));
});

describe('session row cancellation', () => {
  it('posts the row UUID without a locally active run, with explicit project/auth, and invalidates its session list', async () => {
    const { result, invalidations } = mount();
    act(() => result.current.cancelRunByUuid('external-run'));
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    expect(fetch).toHaveBeenCalledWith('https://api.example.invalid/api/agent/scans/external-run/cancel', expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ Authorization: 'Bearer fixture-token', 'X-Project-UUID': 'project-a' }) }));
    await waitFor(() => expect(invalidations).toHaveBeenCalledWith({ queryKey: ['project-a', 'agent-sessions'] }));
    await waitFor(() => expect(result.current.cancelingUuids.size).toBe(0));
    expect(result.current.expandedSessionUuid).toBeNull();
  });

  it('deduplicates immediately while independently settling concurrent row mutations', async () => {
    const first = deferred(); const second = deferred();
    vi.mocked(fetch).mockReset().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const { result, invalidations } = mount();
    act(() => { result.current.cancelRunByUuid('first'); result.current.cancelRunByUuid('first'); result.current.cancelRunByUuid('second'); });
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    expect(result.current.cancelingUuids).toEqual(new Set(['first', 'second']));
    await act(async () => { first.resolve(refused()); });
    await waitFor(() => expect(result.current.cancelErrorForUuid('first')).toBe('run not found or already finished'));
    expect(result.current.cancelErrorForUuid('second')).toBe('');
    expect(result.current.cancelingUuids).toEqual(new Set(['second']));
    await act(async () => { second.resolve(success()); });
    await waitFor(() => expect(result.current.cancelingUuids.size).toBe(0));
    expect(invalidations).toHaveBeenCalledOnce();
    act(() => result.current.cancelRunByUuid('first'));
    expect(result.current.cancelErrorForUuid('first')).toBe('');
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
  });

  it('ignores stale handlers and completions across A → B → A, including a new request for the same UUID', async () => {
    const old = deferred(); const current = deferred();
    vi.mocked(fetch).mockReset().mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise);
    const { result, rerender, invalidations } = mount();
    const stale = result.current.cancelRunByUuid;
    act(() => stale('same-run'));
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    project.projectUUID = 'project-b'; setProjectUUID('project-b'); rerender();
    expect(result.current.cancelingUuids.size).toBe(0);
    act(() => stale('old-project-run'));
    project.projectUUID = 'project-a'; setProjectUUID('project-a'); rerender();
    act(() => stale('old-project-run'));
    expect(fetch).toHaveBeenCalledOnce();
    act(() => result.current.cancelRunByUuid('same-run'));
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
    await act(async () => { old.resolve(refused()); });
    expect(result.current.cancelingUuids).toEqual(new Set(['same-run']));
    expect(result.current.cancelErrorForUuid('same-run')).toBe('');
    expect(invalidations).not.toHaveBeenCalled();
    await act(async () => { current.resolve(success()); });
    await waitFor(() => expect(result.current.cancelingUuids.size).toBe(0));
    expect(invalidations).toHaveBeenCalledOnce();
  });

  it('does not submit without a project or an UUID, and ignores completions after unmount', async () => {
    project.projectUUID = null; setProjectUUID(null);
    const noProject = mount();
    act(() => noProject.result.current.cancelRunByUuid('run'));
    expect(fetch).not.toHaveBeenCalled(); noProject.unmount();
    project.projectUUID = 'project-a'; setProjectUUID('project-a');
    const late = deferred(); vi.mocked(fetch).mockReturnValue(late.promise);
    const { result, unmount, invalidations } = mount();
    act(() => { result.current.cancelRunByUuid(''); result.current.cancelRunByUuid('run'); });
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce());
    unmount(); await act(async () => { late.resolve(success()); });
    expect(invalidations).not.toHaveBeenCalled();
  });
});
