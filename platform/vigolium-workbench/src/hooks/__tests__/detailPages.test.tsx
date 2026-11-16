import { act, fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import DarkFindingsPage from '@/designs/dark/FindingsPage';
import LightFindingsPage from '@/designs/light/FindingsPage';
import DarkHttpRecordsPage from '@/designs/dark/HttpRecordsPage';
import LightHttpRecordsPage from '@/designs/light/HttpRecordsPage';

const mocks = vi.hoisted(() => ({
  project: 'project-a',
  list: { data: { data: [], total: 0 }, isLoading: false, refetch: () => {}, isFetching: false },
  findingParams: vi.fn(), recordParams: vi.fn(),
}));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: mocks.project }) }));
vi.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/api/hooks', () => ({
  useFindings: (params: unknown) => { mocks.findingParams(params); return mocks.list; },
  useHttpRecords: (params: unknown) => { mocks.recordParams(params); return mocks.list; },
  useDeleteFinding: () => ({}), useDeleteHttpRecord: () => ({}), useScanRecords: () => ({}),
}));
vi.mock('@/lib/ag-grid-register', () => ({ registerAgGrid: () => {} }));
vi.mock('ag-grid-react', () => ({
  AgGridReact: ({ onRowClicked, onSelectionChanged }: {
    onRowClicked: (event: unknown) => void;
    onSelectionChanged: (event: unknown) => void;
  }) => <div>
    <button onClick={(event) => onRowClicked({ data: { id: 1105, uuid: 'record-A' }, event: event.nativeEvent })}>Select fixture row</button>
    <button onClick={() => onSelectionChanged({ api: { getSelectedRows: () => [{ id: 1105, uuid: 'record-A' }] } })}>Select fixture checkbox</button>
  </div>,
}));
vi.mock('@/designs/dark/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/light/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/dark/Dropdown', () => ({ default: () => null }));
vi.mock('@/designs/light/Dropdown', () => ({ default: () => null }));
vi.mock('@/designs/dark/ColumnChooser', () => ({ default: () => null }));
vi.mock('@/designs/light/ColumnChooser', () => ({ default: () => null }));
vi.mock('@/designs/dark/FindingDetailPanel', () => ({ default: ({ findingId, onClose }: { findingId: number; onClose: () => void }) => <section aria-label="Selected detail">{findingId}<button onClick={onClose}>Close detail</button></section> }));
vi.mock('@/designs/light/FindingDetailPanel', () => ({ default: ({ findingId, onClose }: { findingId: number; onClose: () => void }) => <section aria-label="Selected detail">{findingId}<button onClick={onClose}>Close detail</button></section> }));
vi.mock('@/designs/dark/HttpRecordDetailPanel', () => ({ default: ({ uuid, onClose }: { uuid: string; onClose: () => void }) => <section aria-label="Selected detail">{uuid}<button onClick={onClose}>Close detail</button></section> }));
vi.mock('@/designs/light/HttpRecordDetailPanel', () => ({ default: ({ uuid, onClose }: { uuid: string; onClose: () => void }) => <section aria-label="Selected detail">{uuid}<button onClick={onClose}>Close detail</button></section> }));

beforeEach(() => {
  mocks.project = 'project-a';
  localStorage.setItem('vigolium_project_uuid', 'project-a');
});
afterEach(() => window.history.replaceState({}, '', '/'));

describe.each([
  ['dark findings', DarkFindingsPage, '/findings/', 'id=1105', '1105', mocks.findingParams],
  ['light findings', LightFindingsPage, '/findings/', 'id=1105', '1105', mocks.findingParams],
  ['dark HTTP records', DarkHttpRecordsPage, '/http-records/', 'uuid=record-A', 'record-A', mocks.recordParams],
  ['light HTTP records', LightHttpRecordsPage, '/http-records/', 'uuid=record-A', 'record-A', mocks.recordParams],
] as const)('%s static selection', (_label, Page, path, query, identity, listParams) => {
  it('hydrates detail absent from the paginated list, warns about scope and closes/back-opens it', () => {
    window.history.replaceState({}, '', `${path}?${query}`);
    render(<Page />);
    expect(screen.getByRole('region', { name: 'Selected detail' })).toHaveTextContent(identity);
    expect(screen.getByRole('note')).toHaveTextContent('Detail links use the active project.');
    expect(screen.getByRole('note')).toHaveTextContent('links do not switch projects');
    const detailEntry = { href: window.location.href, state: window.history.state };
    fireEvent.click(screen.getByRole('button', { name: 'Close detail' }));
    expect(window.location.pathname).toBe(path);
    expect(window.location.search).toBe('');
    expect(screen.queryByRole('region', { name: 'Selected detail' })).not.toBeInTheDocument();
    act(() => {
      window.history.replaceState(detailEntry.state, '', detailEntry.href);
      window.dispatchEvent(new PopStateEvent('popstate', { state: detailEntry.state }));
    });
    expect(screen.getByRole('region', { name: 'Selected detail' })).toHaveTextContent(identity);
    expect(listParams.mock.calls.every(([params]) => params.limit === 100 && params.offset === 0)).toBe(true);
  });

  it('uses query URLs for row toggles and Escape, and clears detail/bulk selection on a project change', () => {
    window.history.replaceState({}, '', path);
    const { rerender } = render(<Page />);
    fireEvent.click(screen.getByRole('button', { name: 'Select fixture row' }));
    expect(window.location.pathname).toBe(path);
    expect(window.location.search).toBe(`?${query}`);
    expect(screen.getByRole('region', { name: 'Selected detail' })).toHaveTextContent(identity);
    fireEvent.click(screen.getByRole('button', { name: 'Select fixture row' }));
    expect(screen.queryByRole('region', { name: 'Selected detail' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Select fixture row' }));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(window.location.search).toBe('');
    expect(screen.queryByRole('region', { name: 'Selected detail' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Select fixture row' }));
    fireEvent.click(screen.getByRole('button', { name: 'Select fixture checkbox' }));
    expect(screen.getByText('1 selected')).toBeInTheDocument();
    mocks.project = 'project-b';
    localStorage.setItem('vigolium_project_uuid', 'project-b');
    rerender(<Page />);
    expect(window.location.search).toBe('');
    expect(screen.queryByRole('region', { name: 'Selected detail' })).not.toBeInTheDocument();
    expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
  });
});
