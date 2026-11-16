import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useFindings } from '../hooks';
import type { Finding, FindingsQueryParams, PaginatedResponse } from '../types';

const mocks = vi.hoisted(() => ({ project: 'project-a', get: vi.fn() }));
vi.mock('@/api/client', async importOriginal => ({
  ...await importOriginal<typeof import('@/api/client')>(),
  getProjectUUID: () => mocks.project,
  apiGet: mocks.get,
}));

function page(id: number): PaginatedResponse<Finding> {
  return { data: [{ id, severity: 'high' } as Finding], total: 260, offset: 0, limit: 100, has_more: true };
}
function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }
  return Wrapper;
}
beforeEach(() => { mocks.project = 'project-a'; mocks.get.mockReset(); });

describe('useFindings placeholder scope', () => {
  it('keeps same-project metadata while the server processes a new sort and exposes it as placeholder data', async () => {
    const original = page(1), sorted = page(2);
    mocks.get.mockResolvedValueOnce(original);
    const { result, rerender } = renderHook((params: FindingsQueryParams) => useFindings(params), {
      initialProps: { limit: 100, offset: 0 } as FindingsQueryParams, wrapper: wrapper(),
    });
    await waitFor(() => expect(result.current.data).toEqual(original));
    let finish!: (value: PaginatedResponse<Finding>) => void;
    mocks.get.mockReturnValueOnce(new Promise<PaginatedResponse<Finding>>(resolve => { finish = resolve; }));
    rerender({ limit: 100, offset: 0, sort: 'severity', order: 'desc' });
    expect(result.current.isPlaceholderData).toBe(true);
    expect(result.current.data?.total).toBe(260);
    expect(mocks.get).toHaveBeenLastCalledWith('/api/findings', { limit: 100, offset: 0, sort: 'severity', order: 'desc' });
    await act(async () => { finish(sorted); });
    await waitFor(() => expect(result.current.data).toEqual(sorted));
    expect(result.current.isPlaceholderData).toBe(false);
  });

  it('never returns previous-project findings while the new scope is pending', async () => {
    const original = page(1), nextProject = page(99);
    mocks.get.mockResolvedValueOnce(original);
    const { result, rerender } = renderHook(() => useFindings({ limit: 100, offset: 0 }), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.data).toEqual(original));
    let finish!: (value: PaginatedResponse<Finding>) => void;
    mocks.get.mockReturnValueOnce(new Promise<PaginatedResponse<Finding>>(resolve => { finish = resolve; }));
    mocks.project = 'project-b';
    rerender();
    expect(result.current.data).toBeUndefined();
    expect(result.current.isPlaceholderData).toBe(false);
    expect(result.current.isPending).toBe(true);
    await act(async () => { finish(nextProject); });
    await waitFor(() => expect(result.current.data).toEqual(nextProject));
    expect(result.current.data?.data[0].id).toBe(99);
  });
});
