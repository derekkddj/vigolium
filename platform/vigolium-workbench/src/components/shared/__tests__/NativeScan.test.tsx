import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { renderToString } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { Scan } from '@/api/types';
import DarkScanPage from '@/designs/dark/ScanPage';
import LightScanPage from '@/designs/light/ScanPage';
import NativeScanDetail from '../NativeScanDetail';
import NativeScanOverview from '../NativeScanOverview';

const mocks = vi.hoisted(() => ({
  project: 'project-a', params: '', detailError: false, logError: false, loading: false, empty: false, text: undefined as string | undefined,
  useScan: vi.fn(), useLogs: vi.fn(), retryDetails: vi.fn(), retryLogs: vi.fn(), historyOffset: 0,
}));
vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams(mocks.params) }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: mocks.project }) }));
vi.mock('@/designs/dark/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/light/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
const scan = (uuid: string): Scan => ({ uuid, name: uuid, project_uuid: mocks.project, status: 'completed', total_findings: 4, processed_count: 9, started_at: '', created_at: '', completeness: 'partial', stop_reason: 'scan_budget', target: 'https://target.test', scope_origin_mode: 'balanced', agentic_scan_uuid: 'parent-agent', phase_outcomes: [{ phase: 'assessment', state: 'partial', errors: 2, reasons: ['scan_budget'], duration_ms: 30 }], module_errors: { one: 3 }, extensions_failed: ['bad.js'] });
vi.mock('@/api/hooks', () => {
  const mutation = () => ({ mutate: vi.fn(), isPending: false });
  return {
    useScanURL: mutation, useScanRequest: mutation, useRunScan: mutation, useUploadRepo: mutation,
    useDeleteScan: mutation, useStopScan: mutation, usePauseScan: mutation, useResumeScan: mutation,
    useScans: ({ offset }: { offset: number }) => {
      mocks.historyOffset = offset;
      return { data: { project_uuid: mocks.project, data: [scan(offset === 0 ? 'first-page-row' : 'second-page-row')], total: 40 }, isLoading: false };
    },
    useScan: (uuid: string) => { mocks.useScan(uuid); return { data: mocks.loading || mocks.detailError ? undefined : scan(uuid), isLoading: mocks.loading, isError: mocks.detailError, error: new Error('scan unavailable'), refetch: mocks.retryDetails, isFetching: false }; },
    useScanLogs: (uuid: string, params: { offset: number; limit: number }) => {
      mocks.useLogs(uuid, params);
      return { data: mocks.loading || mocks.logError ? undefined : mocks.text !== undefined ? { logs: [], text: mocks.text } : { logs: mocks.empty ? [] : [{ id: params.offset + 1, scan_uuid: uuid, message: `log at ${params.offset}`, level: 'info', created_at: '' }], offset: params.offset, total: mocks.empty ? 0 : 401, has_more: !mocks.empty && params.offset < 400 }, isLoading: mocks.loading, isError: mocks.logError, error: new Error('logs unavailable'), refetch: mocks.retryLogs, isFetching: false };
    },
  };
});

beforeEach(() => {
  mocks.project = 'project-a'; mocks.params = ''; mocks.detailError = false; mocks.logError = false; mocks.loading = false; mocks.empty = false; mocks.text = undefined;
  localStorage.setItem('vigolium_project_uuid', mocks.project);
  window.history.replaceState(null, '', '/scan');
});

for (const [theme, Page] of [['dark', DarkScanPage], ['light', LightScanPage]] as const) {
  describe(`Native navigation (${theme})`, () => {
    it('keeps SSR static-safe and opens a cold link even with initially empty search params', () => {
      window.history.replaceState(null, '', '/scan?uuid=outside-list&keep=1#logs');
      expect(renderToString(<Page />)).not.toContain('Native scan details');
      render(<Page />);
      expect(screen.getByLabelText('Native scan details')).toBeInTheDocument();
      expect(mocks.useScan).toHaveBeenCalledWith('outside-list');
      expect(window.location.search).toBe('?uuid=outside-list&keep=1');
    });
    it('consumes asynchronously hydrated params and follows click URLs and popstate', async () => {
      const { rerender } = render(<Page />);
      expect(screen.queryByLabelText('Native scan details')).not.toBeInTheDocument();
      act(() => { window.history.replaceState(null, '', '/scan?uuid=late-link&keep=1#logs'); mocks.params = 'uuid=late-link&keep=1'; });
      rerender(<Page />);
      expect(mocks.useScan).toHaveBeenCalledWith('late-link');
      fireEvent.click(screen.getByText('first-page-row'));
      expect(window.location.search).toBe('?uuid=first-page-row&keep=1');
      expect(window.location.hash).toBe('#logs');
      fireEvent.click(screen.getByRole('button', { name: '[close]' }));
      expect(window.location.search).toBe('?keep=1');
      rerender(<Page />);
      expect(screen.queryByLabelText('Native scan details')).not.toBeInTheDocument();
      act(() => { window.history.replaceState(null, '', '/scan?uuid=back-link'); window.dispatchEvent(new PopStateEvent('popstate')); });
      await waitFor(() => expect(mocks.useScan).toHaveBeenCalledWith('back-link'));
    });
    it('preserves Next history state and restores same-project Back/Forward selections', () => {
      const nextState = { __NA: true, __PRIVATE_NEXTJS_INTERNALS_TREE: { segment: 'scan' }, keep: 'unchanged' };
      window.history.replaceState(nextState, '', '/scan?uuid=first&keep=1#logs');
      render(<Page />);
      const first = { href: window.location.href, state: window.history.state };
      expect(first.state).toMatchObject(nextState);
      expect(first.state.__vigoliumNativeScanProject).toBe('project-a');
      fireEvent.click(screen.getByText('first-page-row'));
      const second = { href: window.location.href, state: window.history.state };
      expect(second.state).toMatchObject(nextState);
      expect(second.state.__vigoliumNativeScanProject).toBe('project-a');
      fireEvent.click(screen.getByRole('button', { name: '[close]' }));
      expect(window.history.state).toMatchObject(nextState);
      // Restore entries exactly as popstate supplies them, without a real browser.
      for (const entry of [first, second]) {
        act(() => { window.history.replaceState(entry.state, '', entry.href); window.dispatchEvent(new PopStateEvent('popstate', { state: entry.state })); });
        expect(screen.getByLabelText('Native scan details')).toHaveTextContent(`uuid: ${new URL(entry.href).searchParams.get('uuid')}`);
        expect(window.history.state).toMatchObject(nextState);
        expect(window.location.hash).toBe('#logs');
      }
    });
    it('rejects known foreign Back/Forward entries but accepts an unstamped shared link in the active project', () => {
      const nextState = { __NA: true, __PRIVATE_NEXTJS_INTERNALS_TREE: { segment: 'scan' }, keep: 'unchanged' };
      window.history.replaceState(nextState, '', '/scan?uuid=old-first&keep=1#logs');
      const { rerender } = render(<Page />);
      const first = { href: window.location.href, state: window.history.state };
      fireEvent.click(screen.getByText('first-page-row'));
      const second = { href: window.location.href, state: window.history.state };
      act(() => { mocks.project = 'project-b'; localStorage.setItem('vigolium_project_uuid', 'project-b'); });
      rerender(<Page />);
      mocks.useScan.mockClear(); mocks.useLogs.mockClear();
      for (const entry of [first, second]) {
        act(() => { window.history.replaceState(entry.state, '', entry.href); window.dispatchEvent(new PopStateEvent('popstate', { state: entry.state })); });
        expect(screen.queryByLabelText('Native scan details')).not.toBeInTheDocument();
        expect(window.location.search).toBe('?keep=1');
        expect(window.location.hash).toBe('#logs');
        expect(window.history.state).toMatchObject({ ...nextState, __vigoliumNativeScanProject: 'project-b' });
      }
      expect(mocks.useScan).not.toHaveBeenCalled();
      expect(mocks.useLogs).not.toHaveBeenCalled();
      act(() => { window.history.replaceState(nextState, '', '/scan?uuid=shared-link&keep=1#logs'); window.dispatchEvent(new PopStateEvent('popstate')); });
      expect(screen.getByLabelText('Native scan details')).toHaveTextContent('uuid: shared-link');
      expect(mocks.useScan).toHaveBeenCalledWith('shared-link');
      expect(localStorage.getItem('vigolium_project_uuid')).toBe('project-b');
      expect(window.history.state).toMatchObject({ ...nextState, __vigoliumNativeScanProject: 'project-b' });
    });
    it('selection survives history paging but resets immediately on a project switch', () => {
      window.history.replaceState(null, '', '/scan?uuid=outside-list');
      const { rerender } = render(<Page />);
      fireEvent.click(screen.getByRole('button', { name: '>' }));
      expect(mocks.historyOffset).toBe(20);
      expect(screen.getByText('second-page-row')).toBeInTheDocument();
      expect(screen.getByLabelText('Native scan details')).toHaveTextContent('uuid: outside-list');
      act(() => { mocks.project = 'project-b'; localStorage.setItem('vigolium_project_uuid', 'project-b'); });
      rerender(<Page />);
      expect(screen.queryByLabelText('Native scan details')).not.toBeInTheDocument();
      expect(mocks.historyOffset).toBe(0);
      expect(window.location.search).toBe('');
    });
  });
  describe(`Native detail (${theme})`, () => {
    it('renders independent coverage, phase/error context, resolved scope, and agent parent', () => {
      render(<NativeScanOverview scan={scan('one')} theme={theme} />);
      expect(screen.getByText('Coverage: Partial')).toBeInTheDocument();
      expect(screen.getByText('assessment: partial')).toBeInTheDocument();
      expect(screen.getByText('phase errors: 2')).toBeInTheDocument();
      expect(screen.getByText('module errors: 3')).toBeInTheDocument();
      expect(screen.getByText('extensions failed to load: 1')).toBeInTheDocument();
      expect(screen.getByText('balanced')).toBeInTheDocument();
      expect(screen.getByRole('link', { name: 'parent-agent' })).toHaveAttribute('href', '/agentic-scan?session=parent-agent');
    });
    it('does not promote a completed legacy run to complete coverage', () => {
      render(<NativeScanOverview scan={{ ...scan('legacy'), completeness: undefined, phase_outcomes: undefined, module_errors: undefined, extensions_failed: undefined, scope_origin_mode: undefined }} theme={theme} />);
      expect(screen.getByText('Coverage: Unknown')).toBeInTheDocument();
      expect(screen.getByText('phase errors: Not recorded')).toBeInTheDocument();
      expect(screen.getByText('Unknown (not recorded)')).toBeInTheDocument();
      expect(screen.getByText(/No phase outcomes recorded/)).toBeInTheDocument();
    });
    it('shows an explicit empty structured page with a known zero total', () => {
      mocks.empty = true;
      render(<NativeScanDetail uuid="empty" theme={theme} onClose={vi.fn()} />);
      expect(screen.getByText(/Showing 0 \/ 0 entries/)).toBeInTheDocument();
      expect(screen.getByText('No structured logs on this page.')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Next logs' })).toBeDisabled();
    });
    it('uses explicit loading and unavailable/Retry states without hiding the panel', () => {
      mocks.loading = true;
      const { rerender } = render(<NativeScanDetail uuid="missing" theme={theme} onClose={vi.fn()} />);
      expect(screen.getByText('Loading scan details…')).toBeInTheDocument();
      expect(screen.getByText('Loading scan logs…')).toBeInTheDocument();
      mocks.loading = false; mocks.detailError = true; mocks.logError = true;
      rerender(<NativeScanDetail uuid="missing" theme={theme} onClose={vi.fn()} />);
      expect(screen.getByLabelText('Native scan details')).toBeInTheDocument();
      expect(screen.getByText(/Scan details unavailable in the active project/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Retry details' }));
      fireEvent.click(screen.getByRole('button', { name: 'Retry logs' }));
      expect(mocks.retryDetails).toHaveBeenCalled(); expect(mocks.retryLogs).toHaveBeenCalled();
    });
    it('paginates 200 structured logs with totals and resets log offset on UUID/project change', () => {
      const { rerender } = render(<NativeScanDetail uuid="one" theme={theme} onClose={vi.fn()} />);
      expect(screen.getByText(/Showing 1 \/ 401 entries/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Next logs' }));
      expect(mocks.useLogs).toHaveBeenLastCalledWith('one', { limit: 200, offset: 200 });
      expect(screen.getByText('log at 200')).toBeInTheDocument();
      rerender(<NativeScanDetail uuid="two" theme={theme} onClose={vi.fn()} />);
      expect(mocks.useLogs).toHaveBeenLastCalledWith('two', { limit: 200, offset: 0 });
      fireEvent.click(screen.getByRole('button', { name: 'Next logs' }));
      mocks.project = 'project-b'; localStorage.setItem('vigolium_project_uuid', 'project-b');
      rerender(<NativeScanDetail uuid="two" theme={theme} onClose={vi.fn()} />);
      expect(mocks.useLogs).toHaveBeenLastCalledWith('two', { limit: 200, offset: 0 });
    });
    it('labels text tails conservatively and renders an explicit empty text state', () => {
      mocks.text = '';
      render(<NativeScanDetail uuid="one" theme={theme} onClose={vi.fn()} />);
      expect(screen.getByText(/Latest 256 KiB runtime.log tail — not a full archive/)).toHaveTextContent('Truncation headers unavailable; completeness unknown.');
      expect(screen.getByText('The fetched runtime.log tail is empty.')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Next logs' })).not.toBeInTheDocument();
    });
  });
}
