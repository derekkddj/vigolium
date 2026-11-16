import { useEffect, type ReactNode } from 'react';
import type { AgentArtifactsPanelProps } from '@/components/shared/AgentArtifactsPanel';
import type { AgentSession, AgentSessionDetail, AgentRunStatusResponse, PaginatedResponse } from '@/api/types';
import { act, fireEvent, render, renderHook, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAgentsLogic } from '../useAgentsLogic';
import DarkAgentsPage from '@/designs/dark/AgentsPage';
import LightAgentsPage from '@/designs/light/AgentsPage';
import { scrollOwners } from '@/components/shared/__tests__/scrollContract';

const mocks = vi.hoisted(() => ({
  project: { projectUUID: 'project-a' as string | null },
  sessions: { data: undefined as Partial<PaginatedResponse<AgentSession>> | undefined, error: null as Error | null, isPending: false, isFetching: false, isPlaceholderData: false, refetch: vi.fn() },
  detail: { data: undefined as AgentSessionDetail | undefined, error: null as Error | null, isPending: false, refetch: vi.fn() },
  status: { data: undefined as AgentRunStatusResponse | undefined, error: null as Error | null, refetch: vi.fn() },
  start: { isPending: false, mutate: vi.fn() },
  cancel: { isPending: false, mutate: vi.fn() },
  tail: { logs: 'retained unrelated console', connection: 'complete', error: '', truncated: false, logSize: 120, retry: vi.fn() },
  detailCalls: vi.fn(),
  listCalls: vi.fn(),
  requestEffects: vi.fn(),
}));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => mocks.project }));
vi.mock('@/lib/useAgentSessionLogs', () => ({ useAgentSessionLogs: () => mocks.tail }));
vi.mock('@/components/shared/AgentArtifactsPanel', () => ({ default: ({ selectedArtifact, onSelectArtifact }: AgentArtifactsPanelProps) => <div>
  Run artifacts preserved<span data-testid="controlled-artifact">{selectedArtifact}</span>
  <button onClick={() => onSelectArtifact?.('auth-config.yaml')}>Mock open artifact</button>
  <button onClick={() => onSelectArtifact?.(null)}>Mock close artifact</button>
</div> }));
vi.mock('@/components/shared/AgentRuntimeLogPanel', () => ({ default: () => <div>Full runtime log preserved</div> }));
vi.mock('@/api/hooks', () => ({
  useAgentSessions: (params: unknown) => { mocks.listCalls(mocks.project.projectUUID, params); return mocks.sessions; },
  useAgentSessionDetail: (uuid: string | null) => {
    const project = mocks.project.projectUUID;
    mocks.detailCalls(project, uuid);
    useEffect(() => { mocks.requestEffects(project, uuid, window.location.search); }, [project, uuid]);
    return mocks.detail;
  },
  useAgentRunStatus: (uuid: string | null) => uuid ? mocks.status : {},
  useUploadRepo: () => ({ mutate: vi.fn() }),
  useStartAutopilotRun: () => ({ mutate: vi.fn() }),
  useStartAgentRun: () => mocks.start,
  useCancelAgentRun: () => mocks.cancel,
}));
vi.mock('@/designs/dark/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/light/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/dark/Dropdown', () => ({ default: () => null }));
vi.mock('@/designs/light/Dropdown', () => ({ default: () => null }));

function sessions(count: number): AgentSession[] {
  return Array.from({ length: count }, (_, i) => ({
    uuid: `session-${i}`, status: 'completed', mode: 'autopilot', agent_name: 'default',
    duration_ms: 1000, started_at: '2026-10-27T00:00:00Z', created_at: '2026-10-27T00:00:00Z',
  }));
}
function popTo(url: string) {
  window.history.replaceState({}, '', url);
  window.dispatchEvent(new PopStateEvent('popstate'));
}
function startRun(result: { current: ReturnType<typeof useAgentsLogic> }, uuid = 'active-run') {
  act(() => result.current.setTargetUrl('https://example.com'));
  act(() => result.current.handleProfileSubmit());
  act(() => mocks.start.mutate.mock.calls.at(-1)![1].onSuccess({ agentic_scan_uuid: uuid }));
}

beforeEach(() => {
  localStorage.clear();
  window.history.replaceState({}, '', '/agentic-scan');
  mocks.project.projectUUID = 'project-a';
  Object.assign(mocks.sessions, { data: { data: [] }, error: null, isPending: false, isFetching: false, isPlaceholderData: false });
  Object.assign(mocks.detail, { data: undefined, error: null, isPending: false });
  Object.assign(mocks.status, { data: undefined, error: null });
  mocks.start.mutate.mockReset();
  mocks.cancel.mutate.mockReset();
  mocks.cancel.isPending = false;
});
afterEach(() => { window.history.replaceState({}, '', '/'); localStorage.clear(); });

describe('agent session selection and history queries', () => {
  it('writes click/functional toggle/close selections without losing other URL fields or history state', () => {
    window.history.replaceState({ keep: true }, '', '/agentic-scan?demo=keep#console');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    act(() => result.current.setExpandedSessionUuid('clicked'));
    expect(window.location.search).toBe('?demo=keep&session=clicked');
    expect(window.location.hash).toBe('#console');
    expect(window.history.state).toEqual({ keep: true });
    act(() => result.current.setExpandedSessionUuid(previous => previous === 'clicked' ? null : 'clicked'));
    rerender();
    expect(result.current.expandedSessionUuid).toBeNull();
    expect(window.location.search).toBe('?demo=keep');
  });

  it('follows popstate both to another session and to a URL without session', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=linked');
    const { result } = renderHook(() => useAgentsLogic());
    expect(result.current.expandedSessionUuid).toBe('linked');
    act(() => popTo('/agentic-scan?session=other'));
    expect(result.current.expandedSessionUuid).toBe('other');
    act(() => popTo('/agentic-scan?demo=keep'));
    expect(result.current.expandedSessionUuid).toBeNull();
  });

  it('keeps a persisted deep link when the project context hydrates', () => {
    localStorage.setItem('vigolium_project_uuid', 'project-a');
    mocks.project.projectUUID = null;
    window.history.replaceState({}, '', '/agentic-scan?session=linked');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    mocks.project.projectUUID = 'project-a';
    rerender();
    expect(result.current.expandedSessionUuid).toBe('linked');
    expect(window.location.search).toBe('?session=linked');
  });

  it('resets pagination and removes only session on project switch before querying old selection', () => {
    mocks.sessions.data = { data: sessions(20), has_more: true };
    window.history.replaceState({}, '', '/agentic-scan?session=old&demo=keep#console');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    act(() => result.current.sessionsNext());
    expect(result.current.sessionsOffset).toBe(20);
    mocks.project.projectUUID = 'project-b';
    rerender();
    expect(result.current.sessionsOffset).toBe(0);
    expect(result.current.expandedSessionUuid).toBeNull();
    expect(window.location.search).toBe('?demo=keep');
    expect(window.location.hash).toBe('#console');
    expect(mocks.detailCalls.mock.calls.filter(([project]) => project === 'project-b').every(([, uuid]) => uuid === null)).toBe(true);
    expect(mocks.listCalls.mock.calls.filter(([project]) => project === 'project-b').every(([, params]) => params.offset === 0)).toBe(true);
    act(() => window.dispatchEvent(new PopStateEvent('popstate')));
    rerender();
    expect(result.current.expandedSessionUuid).toBeNull();
  });

  it('uses has_more with unknown totals and falls back to totals or full pages only when absent', () => {
    mocks.sessions.data = { data: sessions(20), has_more: true };
    const { result, rerender } = renderHook(() => useAgentsLogic());
    expect(result.current.sessionsTotal).toBeNull();
    expect(result.current.sessionsHasNext).toBe(true);
    act(() => result.current.sessionsNext());
    expect(result.current.sessionsOffset).toBe(20);
    mocks.sessions.data = { data: sessions(20), total: 100, has_more: false };
    rerender();
    expect(result.current.sessionsHasNext).toBe(false);
    mocks.sessions.data = { data: sessions(20), total: 41 };
    rerender();
    expect(result.current.sessionsHasNext).toBe(true);
    mocks.sessions.data = { data: sessions(20), total: 40 };
    rerender();
    expect(result.current.sessionsHasNext).toBe(false);
    mocks.sessions.data = { data: sessions(20), total: -1 };
    rerender();
    expect(result.current.sessionsTotal).toBeNull();
    expect(result.current.sessionsHasNext).toBe(true);
    act(() => result.current.sessionsPrevious());
    expect(result.current.sessionsOffset).toBe(0);
  });

  it('does not mislabel placeholder rows as the requested page and exposes retry errors', () => {
    mocks.sessions.data = { data: sessions(20), total: 30, has_more: true };
    const { result, rerender } = renderHook(() => useAgentsLogic());
    act(() => result.current.sessionsNext());
    mocks.sessions.isPlaceholderData = true;
    mocks.sessions.isFetching = true;
    rerender();
    expect(result.current.sessionsLoading).toBe(true);
    expect(result.current.sessionsData).toBeUndefined();
    expect(result.current.sessionsHasNext).toBe(false);
    mocks.sessions.isPlaceholderData = false;
    mocks.sessions.error = new Error('history offline');
    rerender();
    expect(result.current.sessionsError).toBe('history offline');
    act(() => result.current.sessionsRetry());
    expect(mocks.sessions.refetch).toHaveBeenCalledOnce();
  });
});

describe('artifact URL selection', () => {
  it('pushes artifact links, preserves URL fields/state, closes and follows popstate', () => {
    window.history.replaceState({ keep: true }, '', '/agentic-scan?session=linked&demo=keep#console');
    const push = vi.spyOn(window.history, 'pushState');
    const { result } = renderHook(() => useAgentsLogic());
    act(() => result.current.setSelectedArtifact('commands/a + b.jsonl'));
    expect(push).toHaveBeenCalledOnce();
    expect(new URLSearchParams(window.location.search).get('artifact')).toBe('commands/a + b.jsonl');
    expect(window.history.state).toEqual({ keep: true });
    expect(window.location.hash).toBe('#console');
    act(() => result.current.setSelectedArtifact(null));
    expect(window.location.search).toBe('?session=linked&demo=keep');
    act(() => popTo('/agentic-scan?session=linked&artifact=second.txt'));
    expect(result.current.selectedArtifact).toBe('second.txt');
    act(() => popTo('/agentic-scan?session=linked'));
    expect(result.current.selectedArtifact).toBeNull();
  });

  it('hydrates the artifact with its session and clears it before switching sessions/projects', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=linked&artifact=auth-config.yaml&demo=keep');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    expect(result.current.selectedArtifact).toBe('auth-config.yaml');
    act(() => result.current.setExpandedSessionUuid('other'));
    expect(result.current.selectedArtifact).toBeNull();
    expect(window.location.search).toBe('?session=other&demo=keep');
    expect(mocks.requestEffects.mock.calls.filter(([, uuid]) => uuid === 'other').every(([, , url]) => !url.includes('artifact='))).toBe(true);
    act(() => result.current.setSelectedArtifact('second.txt'));
    const staleSelect = result.current.setSelectedArtifact;
    mocks.project.projectUUID = 'project-b'; rerender();
    expect(result.current.selectedArtifact).toBeNull();
    expect(window.location.search).toBe('?demo=keep');
    expect(mocks.requestEffects.mock.calls.filter(([project]) => project === 'project-b').every(([, , url]) => !url.includes('artifact='))).toBe(true);
    act(() => staleSelect('old.txt'));
    expect(window.location.search).toBe('?demo=keep');
    mocks.project.projectUUID = 'project-a'; rerender();
    act(() => result.current.setExpandedSessionUuid('other'));
    act(() => staleSelect('old.txt'));
    expect(result.current.selectedArtifact).toBeNull();
  });
});

describe('agent runtime failure scoping', () => {
  it('surfaces status/cancel failures without clearing a different selected console', () => {
    const { result, rerender } = renderHook(() => useAgentsLogic());
    startRun(result);
    expect(window.location.search).toBe('?session=active-run');
    act(() => result.current.setExpandedSessionUuid('historical-run'));
    mocks.status.error = new Error('status offline');
    rerender();
    expect(result.current.activeRunStatusError).toBe('status offline');
    act(() => result.current.handleScanCancel());
    expect(mocks.cancel.mutate).toHaveBeenCalledWith('active-run', expect.any(Object));
    act(() => mocks.cancel.mutate.mock.calls[0][1].onError(new Error('cancel refused')));
    expect(result.current.cancelError).toBe('cancel refused');
    expect(result.current.panelOutput).toBe('retained unrelated console');
    expect(result.current.expandedSessionUuid).toBe('historical-run');
    act(() => result.current.activeRunStatusRetry());
    expect(mocks.status.refetch).toHaveBeenCalledOnce();
    act(() => result.current.handleScanCancel());
    expect(result.current.cancelError).toBe('');
  });

  it('ignores stale cancel callbacks/handlers after project changes, including A → B → A', () => {
    const { result, rerender } = renderHook(() => useAgentsLogic());
    startRun(result);
    const staleHandler = result.current.handleScanCancel;
    act(() => staleHandler());
    const callbacks = mocks.cancel.mutate.mock.calls[0][1];
    mocks.project.projectUUID = 'project-b';
    rerender();
    act(() => staleHandler());
    expect(mocks.cancel.mutate).toHaveBeenCalledTimes(1);
    mocks.project.projectUUID = 'project-a';
    rerender();
    startRun(result, 'new-run');
    act(() => { callbacks.onError(new Error('old cancel error')); callbacks.onSuccess(); });
    expect(result.current.cancelError).toBe('');
    expect(result.current.expandedSessionUuid).toBe('new-run');
  });

  it('does not let an earlier run cancellation overwrite the current run failure', () => {
    const { result } = renderHook(() => useAgentsLogic());
    startRun(result, 'first-run');
    act(() => result.current.handleScanCancel());
    const first = mocks.cancel.mutate.mock.calls[0][1];
    startRun(result, 'second-run');
    act(() => result.current.handleScanCancel());
    act(() => mocks.cancel.mutate.mock.calls[1][1].onError(new Error('second refused')));
    act(() => { first.onError(new Error('first refused')); first.onSuccess(); });
    expect(result.current.cancelError).toBe('second refused');
  });
});

describe.each([['dark', DarkAgentsPage], ['light', LightAgentsPage]] as const)('%s agent observability views', (_theme, Page) => {
  it('connects artifact URL selection to the controlled panel in the mounted page', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=selected&artifact=second.txt');
    mocks.detail.data = { ...sessions(1)[0], uuid: 'selected' };
    render(<Page />);
    expect(screen.getByTestId('controlled-artifact')).toHaveTextContent('second.txt');
    fireEvent.click(screen.getByRole('button', { name: 'Mock open artifact' }));
    expect(new URLSearchParams(window.location.search).get('artifact')).toBe('auth-config.yaml');
    act(() => popTo('/agentic-scan?session=selected'));
    expect(screen.getByTestId('controlled-artifact')).toBeEmptyDOMElement();
    fireEvent.click(screen.getByRole('button', { name: 'Mock open artifact' }));
    fireEvent.click(screen.getByRole('button', { name: 'Mock close artifact' }));
    expect(window.location.search).toBe('?session=selected');
  });

  it.each([false, true])('keeps full-width session history and a single detail scroll owner (selected: %s)', (selected) => {
    mocks.sessions.data = { data: sessions(1) };
    if (selected) {
      window.history.replaceState({}, '', '/agentic-scan?session=session-0');
      mocks.detail.data = sessions(1)[0];
    }
    render(<Page />);
    const table = screen.getByRole('columnheader', { name: 'DURATION' }).closest('table')!;
    for (let el: Element | null = table; el; el = el.parentElement) {
      expect(el.className).not.toMatch(/w-1\/2|max-h-\[300px\]/);
    }
    if (selected) {
      const panel = screen.getByText('SESSION DETAILS');
      const owners = scrollOwners(panel);
      expect(owners).toHaveLength(1);
      expect(owners[0].className).toBe('flex-1 min-h-0 flex flex-col overflow-auto');
      expect(table.compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
  });

  it('shows 20-row pagination with unknown totals and supports previous/next', () => {
    mocks.sessions.data = { data: sessions(20), has_more: true };
    const { rerender } = render(<Page />);
    expect(screen.getByText('Showing 1–20 of unknown sessions')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous sessions' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next sessions' }));
    expect(screen.getByText('Showing 21–40 of unknown sessions')).toBeInTheDocument();
    mocks.sessions.data = { data: sessions(3), total: 23, has_more: false };
    rerender(<Page />);
    expect(screen.getByText('Showing 21–23 of 23 sessions')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next sessions' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Previous sessions' }));
    expect(mocks.listCalls).toHaveBeenLastCalledWith('project-a', { limit: 20, offset: 0 });
  });

  it('distinguishes loading/error/no history and allows list retry', () => {
    mocks.sessions.data = undefined;
    mocks.sessions.isPending = true;
    const { rerender } = render(<Page />);
    expect(screen.getByText('Loading session history…')).toBeInTheDocument();
    expect(screen.queryByText('No session history in the active project')).not.toBeInTheDocument();
    mocks.sessions.isPending = false;
    mocks.sessions.error = new Error('history offline');
    rerender(<Page />);
    expect(screen.getByRole('alert')).toHaveTextContent('Session history: history offline');
    fireEvent.click(screen.getByRole('button', { name: 'Retry session history' }));
    expect(mocks.sessions.refetch).toHaveBeenCalledOnce();
    mocks.sessions.error = null;
    mocks.sessions.data = { data: [], total: 0, has_more: false };
    rerender(<Page />);
    expect(screen.getByText('No session history in the active project')).toBeInTheDocument();
  });

  it('keeps no-data detail failure/retry/close visible separately from retained console', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=missing&demo=keep');
    mocks.detail.error = new Error('detail forbidden');
    render(<Page />);
    expect(screen.getByRole('alert')).toHaveTextContent('Session details: detail forbidden');
    expect(screen.getByText('Full runtime log preserved')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Live tail (bounded)' }));
    expect(screen.getByText('retained unrelated console')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry session details' }));
    expect(mocks.detail.refetch).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('button', { name: 'Close session details' }));
    expect(window.location.search).toBe('?demo=keep');
    expect(screen.queryByText('Session details: detail forbidden')).not.toBeInTheDocument();
  });

  it.each([
    { finding_count: 0, record_count: null, saved_count: -1, expected: ['findings 0', 'records unknown', 'saved unavailable'] },
    { finding_count: undefined, record_count: -1, saved_count: 0, expected: ['findings unknown', 'records unavailable', 'saved 0'] },
  ])('formats known, unknown and unavailable counts in the mounted session header ($expected)', ({ expected, ...counts }) => {
    window.history.replaceState({}, '', '/agentic-scan?session=selected');
    mocks.detail.data = { ...sessions(1)[0], uuid: 'selected', ...counts };
    render(<Page />);
    const header = screen.getByLabelText('Session summary counts');
    for (const text of expected) expect(header).toHaveTextContent(text);
    expect(header).not.toHaveTextContent('-1');
    expect(screen.getByLabelText('Stored run counts')).not.toHaveTextContent('-1');
  });

  it.each([
    { metrics: {}, count: 'unknown', duration: 'unknown' },
    { metrics: { finding_count: 0, record_count: 0, saved_count: 0, duration_ms: 0 }, count: '0', duration: '0ms' },
  ])('preserves sparse and zero-valued early failures in history and detail ($duration)', ({ metrics, count, duration }) => {
    const failed: AgentSessionDetail = {
      uuid: 'c65f661c-8b6a-4374-b61b-c2dbbc198734', mode: 'swarm', status: 'failed', agent_name: 'olium',
      started_at: '2026-11-06T13:23:35.728709Z', completed_at: '2026-11-06T13:23:35.761624Z',
      created_at: '2026-11-06T13:23:35Z', error_message: 'swarm initialization failed: project mismatch',
      ...metrics,
    };
    window.history.replaceState({}, '', `/agentic-scan?session=${failed.uuid}`);
    mocks.detail.data = failed;
    mocks.sessions.data = { data: [failed], total: 1 };
    const { container } = render(<Page />);
    expect(container).not.toHaveTextContent('NaN');
    expect(screen.getByLabelText('Session summary counts')).toHaveTextContent(`findings ${count}`);
    expect(screen.getByLabelText('Session summary counts')).toHaveTextContent(`records ${count}`);
    expect(screen.getByLabelText('Session summary counts')).toHaveTextContent(`saved ${count}`);
    expect(screen.getByText('duration').parentElement).toHaveTextContent(`duration ${duration}`);
    const row = screen.getByText('c65f661c').closest('tr')!;
    const cells = within(row).getAllByRole('cell');
    expect(cells[4]).toHaveTextContent(count);
    expect(cells[5]).toHaveTextContent(count);
    expect(cells[6]).toHaveTextContent(duration);
  });

  it('shows detail refresh failures without hiding artifacts or the retained console snapshot', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=selected');
    mocks.detail.data = { ...sessions(1)[0], uuid: 'selected', agent_raw_output: 'saved console snapshot' };
    mocks.detail.error = new Error('detail refresh failed');
    render(<Page />);
    expect(screen.getByRole('alert')).toHaveTextContent('detail refresh failed');
    expect(screen.getByText('Run artifacts preserved')).toBeInTheDocument();
    expect(screen.getByText('RETAINED CONSOLE SNAPSHOT')).toBeInTheDocument();
    expect(screen.getByText('saved console snapshot')).toBeInTheDocument();
    expect(screen.getByText('Full runtime log preserved')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Live tail (bounded)' }));
    expect(screen.getByText('retained unrelated console')).toBeInTheDocument();
  });

  it('keeps status and cancel failures visible even when the console is collapsed', () => {
    mocks.start.mutate.mockImplementation((_request, callbacks) => callbacks.onSuccess({ agentic_scan_uuid: 'active-run' }));
    mocks.status.error = new Error('status offline');
    mocks.cancel.mutate.mockImplementation((_uuid, callbacks) => callbacks.onError(new Error('cancel refused')));
    render(<Page />);
    fireEvent.change(screen.getByPlaceholderText(/paste a raw HTTP request/), { target: { value: 'https://example.com' } });
    fireEvent.click(screen.getByRole('button', { name: /START SCAN/ }));
    fireEvent.click(screen.getByRole('button', { name: /STOP/ }));
    fireEvent.click(screen.getByRole('button', { name: /AGENT RUNTIME LOG/ }));
    expect(screen.queryByText('retained unrelated console')).not.toBeInTheDocument();
    expect(screen.getAllByRole('alert').map(node => node.textContent).join('\n')).toContain('Run status: status offline');
    expect(screen.getAllByRole('alert').map(node => node.textContent).join('\n')).toContain('Cancel run: cancel refused');
    fireEvent.click(screen.getByRole('button', { name: 'Retry run status' }));
    expect(mocks.status.refetch).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('button', { name: 'Retry cancel run' }));
    expect(mocks.cancel.mutate).toHaveBeenCalledTimes(2);
  });
});
