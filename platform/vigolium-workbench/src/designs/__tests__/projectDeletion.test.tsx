import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import DarkSettingsPage from '@/designs/dark/SettingsPage';
import LightSettingsPage from '@/designs/light/SettingsPage';

const mocks = vi.hoisted(() => ({
  activeProject: 'project-123',
  setProject: vi.fn(),
  toast: vi.fn(),
  deleteMutate: vi.fn(),
}));

vi.mock('@/contexts/ProjectContext', () => ({
  useProjectContext: () => ({ projectUUID: mocks.activeProject, setProject: mocks.setProject }),
}));
vi.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ toast: mocks.toast }) }));
vi.mock('@/contexts/ThemeContext', () => ({ useTheme: () => ({ schemeId: 'default', setScheme: vi.fn() }) }));
vi.mock('@/lib/useDemoHref', () => ({ useDemoRouter: () => ({ replace: vi.fn() }) }));
vi.mock('@/lib/nav-settings', () => ({
  TOGGLEABLE_PAGES: [],
  useHiddenPages: () => new Set<string>(),
  setHiddenPages: vi.fn(),
}));
vi.mock('@/api/hooks', () => ({
  useConfig: () => ({ data: { entries: [] } }),
  useUpdateConfig: () => ({ mutate: vi.fn(), isPending: false }),
  useProjects: () => ({ data: [{ uuid: 'project-123', name: 'Engagement Alpha', description: 'Production scope', created_at: '2026-01-01T00:00:00Z' }] }),
  useDeleteProject: () => ({ mutate: mocks.deleteMutate }),
  useCreateProject: () => ({ mutate: vi.fn(), isPending: false }),
  useProjectStats: () => ({ data: {
    http_records: { total: 8, success: 6, redirect: 0, client_err: 1, server_err: 1 },
    findings: { total: 2, critical: 0, high: 1, medium: 1, low: 0, info: 0 },
    scans: 1, agent_runs: 1, oast_interactions: 0,
  } }),
  useCurrentUser: () => ({ data: undefined }),
  useCredits: () => ({ data: undefined }),
  useTeamMembers: () => ({ data: [], isLoading: false }),
  useInviteMember: () => ({ mutateAsync: vi.fn() }),
  useRemoveMember: () => ({ mutateAsync: vi.fn() }),
}));
vi.mock('@/designs/dark/PageShell', () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/light/PageShell', () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));

const successResponse = {
  message: 'project and its data purged',
  uuid: 'project-123',
  mode: 'purge',
  rows_deleted: { http_records: 8, findings: 2, projects: 1 },
  config_dir_deleted: true,
  session_dirs_deleted: 2,
  disk_deletion_failures: ['/tmp/agent-session'],
};

beforeEach(() => {
  mocks.activeProject = 'project-123';
  mocks.setProject.mockReset();
  mocks.toast.mockReset();
  mocks.deleteMutate.mockReset();
  mocks.deleteMutate.mockImplementation((variables, callbacks) => callbacks?.onSuccess?.({
    ...successResponse,
    mode: variables.deleteData ? 'purge' : 'reassign_to_default',
  }));
});

describe.each([
  ['dark', DarkSettingsPage],
  ['light', LightSettingsPage],
] as const)('%s project deletion controls', (_theme, SettingsPage) => {
  it('offers separate data-preserving and irreversible purge actions', () => {
    render(<SettingsPage initialTab="projects" />);
    fireEvent.click(screen.getByRole('button', { name: '[del]' }));

    expect(screen.getByRole('button', { name: 'Delete project, keep data (move to Default)' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete project AND all data (irreversible)' })).toBeInTheDocument();
    expect(screen.getByText(/merges it into Default/i)).toBeInTheDocument();
    expect(screen.getByText(/deletes project data from the database and disk/i)).toBeInTheDocument();
  });

  it('sends keep-data deletion without purge mode and summarizes the outcome', () => {
    render(<SettingsPage initialTab="projects" />);
    fireEvent.click(screen.getByRole('button', { name: '[del]' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete project, keep data (move to Default)' }));

    expect(mocks.deleteMutate).toHaveBeenCalledWith(
      { uuid: 'project-123', deleteData: false },
      expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) }),
    );
    expect(mocks.toast).toHaveBeenCalledWith(expect.stringMatching(/moved to Default/i), 'success');
  });

  it('requires typing the exact project name before purging and reports the deletion summary', () => {
    render(<SettingsPage initialTab="projects" />);
    fireEvent.click(screen.getByRole('button', { name: '[del]' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete project AND all data (irreversible)' }));

    expect(screen.getByText(/type the project name to confirm/i)).toBeInTheDocument();
    const confirmButton = screen.getByRole('button', { name: 'Confirm permanent deletion' });
    expect(confirmButton).toBeDisabled();
    expect(mocks.deleteMutate).not.toHaveBeenCalled();

    fireEvent.change(screen.getByRole('textbox', { name: 'Type project name to confirm' }), { target: { value: 'Engagement Alpha' } });
    expect(confirmButton).toBeEnabled();
    fireEvent.click(confirmButton);

    expect(mocks.deleteMutate).toHaveBeenCalledWith(
      { uuid: 'project-123', deleteData: true },
      expect.objectContaining({ onSuccess: expect.any(Function), onError: expect.any(Function) }),
    );
    expect(mocks.toast).toHaveBeenCalledWith(expect.stringMatching(/11 rows.*2 session directories.*config directory/i), 'success');
    expect(mocks.toast).toHaveBeenCalledWith(expect.stringMatching(/disk cleanup failed.*agent-session/i), 'error');
  });
});
