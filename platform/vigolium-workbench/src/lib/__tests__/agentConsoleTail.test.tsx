import type { ReactNode } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setBaseUrl, setToken } from '@/api/client';
import { evidencePalette } from '@/components/shared/HttpMessage';
import DarkAgentsPage from '@/designs/dark/AgentsPage';
import LightAgentsPage from '@/designs/light/AgentsPage';

const tail = vi.hoisted(() => ({
  logs: 'retained console text', isStreaming: false, connection: 'exhausted',
  error: 'Automatic retries exhausted', truncated: true, logSize: 9000000, retry: vi.fn(),
}));
vi.mock('@tanstack/react-query', async importOriginal => ({ ...await importOriginal<typeof import('@tanstack/react-query')>(), useQueryClient: () => ({ invalidateQueries: vi.fn() }) }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: 'project-a' }) }));
vi.mock('@/lib/useAgentSessionLogs', () => ({ useAgentSessionLogs: () => tail }));
vi.mock('@/components/shared/AgentArtifactsPanel', () => ({
  default: ({ runUUID, theme }: { runUUID: string; theme: string }) => <section aria-label="Mounted run artifacts" data-run={runUUID} data-theme={theme} />,
}));
vi.mock('@/api/hooks', () => ({
  useAgentSessions: () => ({ data: { data: [] } }),
  useAgentSessionDetail: () => ({ data: {
    uuid: 'selected', status: 'running', mode: 'autopilot', duration_ms: 1000,
    started_at: '2026-10-27T00:00:00Z', finding_count: 0, record_count: 0, saved_count: 0,
  } }),
  useAgentRunStatus: () => ({}),
  useUploadRepo: () => ({ mutate: vi.fn() }),
  useStartAutopilotRun: () => ({ mutate: vi.fn() }),
  useStartAgentRun: () => ({ mutate: vi.fn() }),
  useCancelAgentRun: () => ({ mutate: vi.fn() }),
}));
vi.mock('@/designs/dark/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/light/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/dark/Dropdown', () => ({ default: () => null }));
vi.mock('@/designs/light/Dropdown', () => ({ default: () => null }));

beforeEach(() => {
  setBaseUrl('https://api.example.invalid');
  setToken('console-fixture-token');
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response('complete command\ncomplete result\n', { headers: {
    'X-Artifact-Total-Size': '33', 'X-Artifact-Offset': '0', 'X-Artifact-Returned-Bytes': '33', 'X-Artifact-Truncated': '0',
  } })));
  Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: undefined });
});
afterEach(() => window.history.replaceState({}, '', '/'));

describe.each([
  ['dark', DarkAgentsPage],
  ['light', LightAgentsPage],
] as const)('%s agent log modes', (_theme, Page) => {
  it('opens the real full-log viewer by default and retains explicit bounded-tail diagnostics', async () => {
    window.history.replaceState({}, '', '/agentic-scan?session=selected');
    render(<Page />);
    expect(screen.getByRole('region', { name: 'Mounted run artifacts' })).toHaveAttribute('data-run', 'selected');
    expect(screen.getByRole('region', { name: 'Mounted run artifacts' })).toHaveAttribute('data-theme', _theme);
    expect(screen.getByText('AGENT RUNTIME LOG')).toBeInTheDocument();
    expect((await screen.findByLabelText('Runtime log text')).textContent).toBe('complete command\ncomplete result\n');
    expect(screen.getByLabelText('Runtime log text')).toHaveStyle({ background: evidencePalette[_theme].background });
    expect(screen.getByLabelText('Runtime log byte range')).toHaveTextContent('Bytes [0, 33) of 33');
    expect(vi.mocked(fetch).mock.calls[0][0]).toContain('/selected/artifacts/runtime.log?max_bytes=262144&offset=0');
    expect(vi.mocked(fetch).mock.calls[0][1]?.headers).toMatchObject({ Authorization: 'Bearer console-fixture-token', 'X-Project-UUID': 'project-a' });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Full log (paged)' })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByText('retained console text')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Live tail (bounded)' }));
    expect(screen.queryByRole('region', { name: 'Runtime log' })).not.toBeInTheDocument();
    expect(screen.getByText('AGENT CONSOLE TAIL')).toBeInTheDocument();
    expect(screen.getByText('retained console text').tagName).toBe('PRE');
    expect(screen.getByRole('status')).toHaveTextContent('Earlier output omitted from this bounded console tail.');
    expect(screen.getByRole('status')).toHaveTextContent('Saved log size: 9,000,000 bytes.');
    expect(screen.getByRole('alert')).toHaveTextContent('Automatic retries exhausted');
    // The server-side run remains active even when the log follower has stopped.
    expect(screen.getByText('run active')).toBeInTheDocument();
    expect(screen.getByText('tail exhausted')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry console tail' }));
    expect(tail.retry).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Full log (paged)' }));
    expect((await screen.findByLabelText('Runtime log text')).textContent).toBe('complete command\ncomplete result\n');
    expect(fetch).toHaveBeenCalledTimes(2); // Returning to full view starts again from byte 0.
    expect(screen.queryByText('retained console text')).not.toBeInTheDocument();
  });

  it('shows an absent runtime.log explicitly without substituting the old tail', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 404 }));
    window.history.replaceState({}, '', '/agentic-scan?session=selected');
    render(<Page />);
    expect(await screen.findByRole('alert')).toHaveTextContent('HTTP 404');
    expect(screen.queryByText('retained console text')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Runtime log text')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Full log (paged)' })).toHaveAttribute('aria-pressed', 'true');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
