import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useAgentSessions, useDbRecords, useHttpRecords, useOASTInteractions } from '../hooks';

const mocks = vi.hoisted(() => ({ project: 'project-a', get: vi.fn() }));
vi.mock('@/api/client', async importOriginal => ({
  ...await importOriginal<typeof import('@/api/client')>(),
  getProjectUUID: () => mocks.project,
  apiGet: mocks.get,
}));

const scenarios = [
  { name: 'HTTP records', useList: (offset: number) => useHttpRecords({ limit: 5, offset }) },
  { name: 'OAST interactions', useList: (offset: number) => useOASTInteractions({ limit: 5, offset }) },
  { name: 'agent sessions', useList: (offset: number) => useAgentSessions({ limit: 5, offset }) },
  { name: 'database records', useList: (offset: number) => useDbRecords('findings', { limit: 5, offset }) },
] as const;

function response(project: string, row = 'shared-row-uuid') {
  return {
    project_uuid: project,
    data: [{ uuid: row, project_uuid: project, status: 'completed' }],
    records: [{ uuid: row, project_uuid: project }],
    table: 'findings', total: 1, offset: 0, limit: 5, has_more: false, columns: [],
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

describe('project-scoped list placeholders', () => {
  it.each(scenarios)('$name does not expose the previous project while the new scope is pending', async ({ useList }) => {
    const original = response('project-a');
    const nextProject = response('project-b');
    mocks.get.mockResolvedValueOnce(original);
    const { result, rerender } = renderHook((offset: number) => useList(offset), { initialProps: 0, wrapper: wrapper() });
    await waitFor(() => expect(result.current.data).toEqual(original));

    let finish!: (value: ReturnType<typeof response>) => void;
    mocks.get.mockReturnValueOnce(new Promise<ReturnType<typeof response>>(resolve => { finish = resolve; }));
    mocks.project = 'project-b';
    rerender(0);

    expect(result.current.data).toBeUndefined();
    expect(result.current.isPlaceholderData).toBe(false);
    await act(async () => { finish(nextProject); });
    await waitFor(() => expect(result.current.data).toEqual(nextProject));
  });

  it.each(scenarios)('$name retains placeholders for same-project pagination', async ({ useList }) => {
    const original = response('project-a', 'page-zero-row');
    const nextPage = response('project-a', 'page-five-row');
    mocks.get.mockResolvedValueOnce(original);
    const { result, rerender } = renderHook((offset: number) => useList(offset), { initialProps: 0, wrapper: wrapper() });
    await waitFor(() => expect(result.current.data).toEqual(original));

    let finish!: (value: ReturnType<typeof response>) => void;
    mocks.get.mockReturnValueOnce(new Promise<ReturnType<typeof response>>(resolve => { finish = resolve; }));
    rerender(5);

    expect(result.current.data).toEqual(original);
    expect(result.current.isPlaceholderData).toBe(true);
    await act(async () => { finish(nextPage); });
    await waitFor(() => expect(result.current.data).toEqual(nextPage));
    expect(result.current.isPlaceholderData).toBe(false);
  });
});
