import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { hydrateRoot } from 'react-dom/client';
import { renderToString } from 'react-dom/server';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useDetailSelection } from '@/hooks/useDetailSelection';
import { useFinding, useHttpRecord } from '@/api/hooks';

const scope = vi.hoisted(() => ({ project: 'project-a' as string | null, search: null as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: scope.project }) }));
vi.mock('next/navigation', () => ({ useSearchParams: () => scope.search === null ? null : new URLSearchParams(scope.search) }));
const clients: QueryClient[] = [];
function queryWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  clients.push(client);
  return function QueryWrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  };
}
function restoreEntry(href: string, state: unknown) {
  window.history.replaceState(state, '', href);
  window.dispatchEvent(new PopStateEvent('popstate', { state }));
}
beforeEach(() => {
  scope.project = 'project-a';
  scope.search = null;
  localStorage.setItem('vigolium_project_uuid', 'project-a');
  window.history.replaceState({}, '', '/findings/');
});
afterEach(() => {
  clients.forEach((client) => client.clear());
  clients.length = 0;
  window.history.replaceState({}, '', '/');
  vi.unstubAllGlobals();
});

describe('Hydrated project-scoped detail selection', () => {
  it('starts empty, reads a cold query after hydration, and matches the static SSR HTML', async () => {
    window.history.replaceState({}, '', '/findings/?id=1105');
    const rendered: (number | null)[] = [];
    function Selection() {
      const { selectedId } = useDetailSelection('finding');
      rendered.push(selectedId);
      return <span>{selectedId ?? 'none'}</span>;
    }
    const html = renderToString(<Selection />);
    expect(html).toBe('<span>none</span>');
    const container = document.createElement('div');
    container.innerHTML = html;
    document.body.appendChild(container);
    const recoverableError = vi.fn();
    let root: ReturnType<typeof hydrateRoot>;
    await act(async () => { root = hydrateRoot(container, <Selection />, { onRecoverableError: recoverableError }); });
    expect(rendered[0]).toBeNull();
    expect(rendered[1]).toBeNull();
    expect(container).toHaveTextContent('1105');
    expect(recoverableError).not.toHaveBeenCalled();
    act(() => root!.unmount());
    container.remove();
  });

  it('does not mistake saved-project context bootstrap for a project switch', () => {
    scope.project = null;
    window.history.replaceState({}, '', '/findings/?id=1105');
    const { result, rerender } = renderHook(() => useDetailSelection('finding'));
    expect(result.current.selectedId).toBe(1105);
    scope.project = 'project-a';
    rerender();
    expect(result.current.selectedId).toBe(1105);
    expect(window.location.search).toBe('?id=1105');
  });

  it('reads encoded record queries without changing their identity', () => {
    window.history.replaceState({}, '', '/http-records/?uuid=%41BC%2D123_legacy');
    const seen: (string | null)[] = [];
    const { result } = renderHook(() => {
      const selection = useDetailSelection('http-record');
      seen.push(selection.selectedId);
      return selection;
    });
    expect(seen[0]).toBeNull();
    expect(result.current.selectedId).toBe('ABC-123_legacy');
    act(() => result.current.selectDetail('record-B'));
    expect(window.location.pathname).toBe('/http-records/');
    expect(window.location.search).toBe('?uuid=record-B');
  });

  it('keeps React selection in sync with open, close, back and forward entries', () => {
    const { result } = renderHook(() => useDetailSelection('finding'));
    const listEntry = { href: window.location.href, state: window.history.state };
    act(() => result.current.selectDetail(1105));
    const detailEntry = { href: window.location.href, state: window.history.state };
    expect(window.location.pathname).toBe('/findings/');
    expect(window.location.search).toBe('?id=1105');
    expect(result.current.selectedId).toBe(1105);
    act(() => result.current.selectDetail(null));
    const closedEntry = { href: window.location.href, state: window.history.state };
    expect(result.current.selectedId).toBeNull();
    expect(window.location.search).toBe('');
    act(() => restoreEntry(detailEntry.href, detailEntry.state));
    expect(result.current.selectedId).toBe(1105);
    act(() => restoreEntry(listEntry.href, listEntry.state));
    expect(result.current.selectedId).toBeNull();
    act(() => restoreEntry(detailEntry.href, detailEntry.state));
    expect(result.current.selectedId).toBe(1105);
    act(() => restoreEntry(closedEntry.href, closedEntry.state));
    expect(result.current.selectedId).toBeNull();
  });

  it('reacts to Next same-page query changes even without popstate', () => {
    window.history.replaceState({}, '', '/findings/?id=1105');
    scope.search = 'id=1105';
    const { result, rerender } = renderHook(() => useDetailSelection('finding'));
    expect(result.current.selectedId).toBe(1105);
    for (const [search, expected] of [['id=1106', 1106], ['', null], ['id=1e3', null]] as const) {
      window.history.pushState({}, '', `/findings/${search ? `?${search}` : ''}`);
      scope.search = search;
      rerender();
      expect(result.current.selectedId).toBe(expected);
    }
  });

  it('retains validated legacy initialId in dev, but closes onto the exported page without reopening', () => {
    window.history.replaceState({}, '', '/findings/1105/');
    const { result, rerender } = renderHook(({ initialId }) => useDetailSelection('finding', initialId), { initialProps: { initialId: 1105 as number | null } });
    expect(result.current.selectedId).toBe(1105);
    act(() => result.current.selectDetail(null));
    expect(window.location.pathname).toBe('/findings/');
    expect(result.current.selectedId).toBeNull();
    act(() => window.dispatchEvent(new PopStateEvent('popstate')));
    expect(result.current.selectedId).toBeNull();
    rerender({ initialId: null });
    expect(result.current.selectedId).toBeNull();
    window.history.replaceState({}, '', '/findings/1106/');
    rerender({ initialId: 1106 });
    expect(result.current.selectedId).toBe(1106);
  });

  it('clears before the first new-project render and never reopens a known old-project history entry', () => {
    window.history.replaceState({}, '', '/findings/?id=1105&demo_key=public-demo');
    const seen: { project: string; id: number | null }[] = [];
    const { result, rerender } = renderHook(() => {
      const selection = useDetailSelection('finding', 1105);
      seen.push({ project: selection.projectKey, id: selection.selectedId });
      return selection;
    });
    const oldEntry = { href: window.location.href, state: window.history.state };
    scope.project = 'project-b';
    localStorage.setItem('vigolium_project_uuid', 'project-b');
    rerender();
    expect(seen.filter((entry) => entry.project === 'project-b').every((entry) => entry.id === null)).toBe(true);
    expect(result.current.selectedId).toBeNull();
    expect(window.location.search).toBe('?demo_key=public-demo');
    act(() => restoreEntry(oldEntry.href, oldEntry.state));
    expect(result.current.selectedId).toBeNull();
    expect(window.location.search).toBe('?demo_key=public-demo');
    expect(scope.project).toBe('project-b');
    act(() => result.current.selectDetail(1106));
    expect(result.current.selectedId).toBe(1106);
  });

  it.each(['NaN', '1e3', '01', '-1', '9007199254740992', '1105/extra'])('never fetches invalid finding %s (including NaN)', async (id) => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    window.history.replaceState({}, '', `/findings/?id=${encodeURIComponent(id)}`);
    const { result } = renderHook(() => {
      const selection = useDetailSelection('finding', NaN);
      useFinding(selection.selectedId);
      return selection;
    }, { wrapper: queryWrapper() });
    await act(async () => {});
    expect(result.current.selectedId).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each(['one/two', '../two', 'one\\two', '%2F', ' bad', 'bad?token=secret'])('never fetches unsafe HTTP record %j', async (uuid) => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    window.history.replaceState({}, '', `/http-records/?uuid=${encodeURIComponent(uuid)}`);
    const { result } = renderHook(() => {
      const selection = useDetailSelection('http-record');
      useHttpRecord(selection.selectedId);
      return selection;
    }, { wrapper: queryWrapper() });
    await act(async () => {});
    expect(result.current.selectedId).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('fetches cold detail directly in the active project, independently of list pages and without token URLs', async () => {
    localStorage.setItem('vigolium_api_token', 'secret-bearer');
    window.history.replaceState({}, '', '/findings/?id=1105');
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 1105 }), { headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetcher);
    renderHook(() => {
      const selection = useDetailSelection('finding');
      return useFinding(selection.selectedId);
    }, { wrapper: queryWrapper() });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    const [url, options] = fetcher.mock.calls[0];
    expect(String(url)).toContain('/api/findings/1105');
    expect(String(url)).not.toContain('secret-bearer');
    expect(options.headers['X-Project-UUID']).toBe('project-a');
    expect(options.headers.Authorization).toBe('Bearer secret-bearer');
  });
});
