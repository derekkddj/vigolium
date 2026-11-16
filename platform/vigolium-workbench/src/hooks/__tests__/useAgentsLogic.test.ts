import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAgentsLogic } from '../useAgentsLogic';

const mocks = vi.hoisted(() => ({
  project: { projectUUID: 'project-a' as string | null },
  startRun: { isPending: false, mutate: vi.fn() },
  tail: {
    logs: 'retained text', isStreaming: false, connection: 'retrying',
    error: 'network lost', truncated: true, logSize: 999999, retry: vi.fn(),
  },
  detailStatus: 'running',
  tailCalls: vi.fn(),
}));
vi.mock('@tanstack/react-query', async importOriginal => ({ ...await importOriginal<typeof import('@tanstack/react-query')>(), useQueryClient: () => ({ invalidateQueries: vi.fn() }) }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => mocks.project }));
vi.mock('@/lib/useAgentSessionLogs', () => ({ useAgentSessionLogs: (uuid: string | null) => { mocks.tailCalls(uuid); return mocks.tail; } }));
vi.mock('@/api/hooks', () => ({
  useAgentSessions: () => ({ data: { data: [] } }),
  useAgentSessionDetail: (uuid: string | null) => ({ data: uuid ? { uuid, status: mocks.detailStatus } : undefined }),
  useAgentRunStatus: () => ({}),
  useUploadRepo: () => ({ mutate: vi.fn() }),
  useStartAutopilotRun: () => ({ mutate: vi.fn() }),
  useStartAgentRun: () => mocks.startRun,
  useCancelAgentRun: () => ({ mutate: vi.fn() }),
}));

beforeEach(() => {
  mocks.project.projectUUID = 'project-a';
  mocks.detailStatus = 'running';
  mocks.startRun.mutate.mockReset();
  window.history.replaceState({}, '', '/agentic-scan');
});
afterEach(() => window.history.replaceState({}, '', '/'));

describe('useAgentsLogic console selection', () => {
  it('opens a session after search-param hydration without deleting the shareable URL', () => {
    const url = '/agentic-scan?session=linked-session&demo_key=keep-me#console';
    window.history.replaceState({}, '', url);
    const { result } = renderHook(() => useAgentsLogic());
    expect(result.current.expandedSessionUuid).toBe('linked-session');
    expect(window.location.pathname + window.location.search + window.location.hash).toBe(url);
    expect(result.current.streamingOpen).toBe(true);
    expect(result.current.consoleMode).toBe('full');
    expect(mocks.tailCalls).toHaveBeenLastCalledWith(null);
    act(() => result.current.setConsoleMode('tail'));
    expect(mocks.tailCalls).toHaveBeenLastCalledWith('linked-session');
    // Run liveness must not imply that the tail connection is connected.
    expect(result.current.panelIsRunning).toBe(true);
    expect(result.current.panelConnection).toBe('retrying');
    expect(result.current.panelOutput).toBe('retained text');
    expect(result.current.panelError).toBe('network lost');
    expect(result.current.panelTruncated).toBe(true);
    expect(result.current.panelLogSize).toBe(999999);
    act(() => result.current.panelRetry());
    expect(mocks.tail.retry).toHaveBeenCalled();
  });

  it('resets explicit tail mode on run/project changes, including returning to the previous run', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=first');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    act(() => result.current.setConsoleMode('tail'));
    expect(result.current.consoleMode).toBe('tail');
    act(() => result.current.setExpandedSessionUuid('second'));
    expect(result.current.consoleMode).toBe('full');
    expect(mocks.tailCalls).toHaveBeenLastCalledWith(null);
    act(() => result.current.setExpandedSessionUuid('first'));
    expect(result.current.consoleMode).toBe('full');
    act(() => result.current.setConsoleMode('tail'));
    mocks.project.projectUUID = 'project-b';
    rerender();
    expect(result.current.consoleMode).toBe('full');
    expect(mocks.tailCalls).toHaveBeenLastCalledWith(null);
  });

  it('does not re-open a closed linked session on unrelated rerenders and follows new history links', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=first');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    expect(result.current.expandedSessionUuid).toBe('first');
    act(() => result.current.setExpandedSessionUuid(null));
    rerender();
    expect(result.current.expandedSessionUuid).toBeNull();
    act(() => {
      window.history.replaceState({}, '', '/agentic-scan?session=second');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    expect(result.current.expandedSessionUuid).toBe('second');
  });

  it('clears selection on project switch without reapplying the unchanged session link', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=project-a-session');
    const { result, rerender } = renderHook(() => useAgentsLogic());
    expect(result.current.expandedSessionUuid).toBe('project-a-session');
    mocks.project.projectUUID = 'project-b';
    rerender();
    expect(result.current.expandedSessionUuid).toBeNull();
    expect(result.current.streamingOpen).toBe(false);
    expect(window.location.search).toBe('');
  });

  it('does not label a terminal watched session as an active run', () => {
    window.history.replaceState({}, '', '/agentic-scan?session=finished');
    mocks.detailStatus = 'completed_with_warnings';
    const { result } = renderHook(() => useAgentsLogic());
    expect(result.current.panelIsRunning).toBe(false);
    expect(result.current.panelConnection).toBe('retrying');
  });

  it('ignores old-project run submission callbacks, including after A → B → A', () => {
    const { result, rerender } = renderHook(() => useAgentsLogic());
    act(() => result.current.setTargetUrl('https://example.com'));
    act(() => result.current.handleProfileSubmit());
    expect(mocks.startRun.mutate).toHaveBeenCalledTimes(1);
    const callbacks = mocks.startRun.mutate.mock.calls[0][1];
    mocks.project.projectUUID = 'project-b';
    rerender();
    mocks.project.projectUUID = 'project-a';
    rerender();
    act(() => {
      callbacks.onSuccess({ agentic_scan_uuid: 'old-project-run' });
      callbacks.onError(new Error('old-project error'));
    });
    expect(result.current.expandedSessionUuid).toBeNull();
    expect(result.current.scanError).toBe('');
    expect(result.current.scanResult).toBeNull();
  });
});
