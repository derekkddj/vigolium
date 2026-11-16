import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useScans } from '../hooks';
import type { PaginatedResponse, Scan, ScansQueryParams } from '../types';

const mocks = vi.hoisted(() => ({ project: 'project-a', get: vi.fn() }));
vi.mock('@/api/client', async importOriginal => ({
  ...await importOriginal<typeof import('@/api/client')>(),
  getProjectUUID: () => mocks.project,
  apiGet: mocks.get,
}));

function page(project: string, status: string): PaginatedResponse<Scan> {
  return {
    project_uuid: project,
    data: [{
      uuid: 'shared-scan-uuid', project_uuid: project, name: project, status,
      total_findings: 1, processed_count: 1,
      started_at: '2026-11-10T12:00:00Z', created_at: '2026-11-10T12:00:00Z',
    }],
    total: 1, offset: 0, limit: 5, has_more: false,
  };
}

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }
  return Wrapper;
}

beforeEach(() => { mocks.project = 'project-a'; mocks.get.mockReset(); });

describe('useScans project scope', () => {
  it('retains same-project data while a different history page is pending', async () => {
    const original = page('project-a', 'running');
    const nextPage = page('project-a', 'completed');
    mocks.get.mockResolvedValueOnce(original);
    const { result, rerender } = renderHook((params: ScansQueryParams) => useScans(params), {
      initialProps: { limit: 5, offset: 0 }, wrapper: wrapper(),
    });
    await waitFor(() => expect(result.current.data).toEqual(original));

    let finish!: (value: PaginatedResponse<Scan>) => void;
    mocks.get.mockReturnValueOnce(new Promise<PaginatedResponse<Scan>>(resolve => { finish = resolve; }));
    rerender({ limit: 5, offset: 5 });

    expect(result.current.data).toEqual(original);
    expect(result.current.isPlaceholderData).toBe(true);
    await act(async () => { finish(nextPage); });
    await waitFor(() => expect(result.current.data).toEqual(nextPage));
    expect(result.current.isPlaceholderData).toBe(false);
  });

  it('does not display the previous project scan when the same scan UUID is pending in the new project', async () => {
    const original = page('project-a', 'running');
    const nextProject = page('project-b', 'failed');
    mocks.get.mockResolvedValueOnce(original);
    const { result, rerender } = renderHook(() => useScans({ limit: 5, offset: 0 }), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.data).toEqual(original));

    let finish!: (value: PaginatedResponse<Scan>) => void;
    mocks.get.mockReturnValueOnce(new Promise<PaginatedResponse<Scan>>(resolve => { finish = resolve; }));
    mocks.project = 'project-b';
    rerender();

    expect(result.current.data).toBeUndefined();
    expect(result.current.isPlaceholderData).toBe(false);
    await act(async () => { finish(nextProject); });
    await waitFor(() => expect(result.current.data).toEqual(nextProject));
  });
});
