import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useDeleteProject } from '../hooks';
import type { DeleteProjectResponse } from '../types';

const mocks = vi.hoisted(() => ({
  activeProject: 'project-123' as string | null,
  setProject: vi.fn(),
  apiDelete: vi.fn(),
}));

vi.mock('@/api/client', async importOriginal => ({
  ...await importOriginal<typeof import('@/api/client')>(),
  apiDelete: mocks.apiDelete,
  getProjectUUID: () => mocks.activeProject,
}));
vi.mock('@/contexts/ProjectContext', () => ({
  useProjectContext: () => ({ projectUUID: mocks.activeProject, setProject: mocks.setProject }),
}));

function wrapperFor(client: QueryClient) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  };
}

beforeEach(() => {
  mocks.activeProject = 'project-123';
  mocks.setProject.mockReset();
  mocks.apiDelete.mockReset();
  mocks.apiDelete.mockResolvedValue({
    message: 'project deleted', uuid: 'project-123', mode: 'reassign_to_default',
    config_dir_deleted: false, session_dirs_deleted: 0, disk_deletion_failures: [],
  });
});

describe('useDeleteProject', () => {
  it.each([
    [false, '/api/projects/project-123'],
    [true, '/api/projects/project-123?delete_data=true'],
  ])('sends deleteData=%s to the matching endpoint and refreshes project selection', async (deleteData, endpoint) => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidate = vi.spyOn(client, 'invalidateQueries').mockResolvedValue(undefined);
    const { result } = renderHook(() => useDeleteProject(), { wrapper: wrapperFor(client) });

    await act(async () => {
      await result.current.mutateAsync({ uuid: 'project-123', deleteData });
    });

    expect(mocks.apiDelete).toHaveBeenCalledWith(endpoint);
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['projects'] });
    expect(mocks.setProject).toHaveBeenCalledWith(null);
  });

  it('does not clear a new project selected while deletion is in flight', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useDeleteProject(), { wrapper: wrapperFor(client) });
    let finishRequest!: (response: DeleteProjectResponse) => void;
    mocks.apiDelete.mockReturnValue(new Promise<DeleteProjectResponse>(resolve => { finishRequest = resolve; }));

    let pending!: Promise<DeleteProjectResponse>;
    await act(async () => { pending = result.current.mutateAsync({ uuid: 'project-123', deleteData: false }); });
    mocks.activeProject = 'still-active';
    await act(async () => {
      finishRequest({
        message: 'project deleted', uuid: 'project-123', mode: 'reassign_to_default',
        config_dir_deleted: false, session_dirs_deleted: 0, disk_deletion_failures: [],
      });
      await pending;
    });

    expect(mocks.setProject).not.toHaveBeenCalled();
  });
});
