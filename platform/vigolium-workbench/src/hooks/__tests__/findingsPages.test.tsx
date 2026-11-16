import { fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import type { AgGridReactProps } from 'ag-grid-react';
import type { Finding, FindingsQueryParams } from '@/api/types';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FINDING_SORT_FIELDS } from '@/lib/findingsSorting';
import DarkFindingsPage from '@/designs/dark/FindingsPage';
import LightFindingsPage from '@/designs/light/FindingsPage';

const mocks = vi.hoisted(() => ({
  project: 'project-a', params: vi.fn(), fetching: false, placeholder: false, error: false,
  grid: {} as AgGridReactProps<Finding>,
}));
const findings = Array.from({ length: 260 }, (_, index) => ({
  id: index === 150 ? 4540 : index === 240 ? 1676 : index === 241 ? 1673 : 10000 + index,
  severity: [150, 240, 241].includes(index) ? 'high' : index % 2 ? 'medium' : 'info',
  module_name: `Module ${index}`, confidence: 'high', matched_at: ['https://example.test/path'],
  found_at: String(260 - index),
})) as Finding[];
const rank: Record<string, number> = { info: 0, suspect: 1, low: 2, medium: 3, high: 4, critical: 5 };
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: mocks.project }) }));
vi.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/api/hooks', () => ({
  useFindings: (params: FindingsQueryParams) => {
    mocks.params(params);
    const rows = findings.filter(row => !params.severity || row.severity === params.severity);
    if (params.sort === 'severity') rows.sort((a, b) => (rank[a.severity] - rank[b.severity]) * (params.order === 'asc' ? 1 : -1));
    const offset = params.offset || 0;
    return {
      data: { data: rows.slice(offset, offset + 100), total: rows.length, offset, limit: 100, has_more: offset + 100 < rows.length },
      isLoading: false, isFetching: mocks.fetching, isPlaceholderData: mocks.placeholder, isError: mocks.error, refetch: vi.fn(),
    };
  },
  useDeleteFinding: () => ({}),
}));
vi.mock('@/lib/ag-grid-register', () => ({ registerAgGrid: () => {} }));
vi.mock('ag-grid-react', () => ({
  AgGridReact: (props: AgGridReactProps<Finding>) => {
    mocks.grid = props;
    const sort = (direction: 'asc' | 'desc' | null) => props.onSortChanged?.({
      api: { getColumnState: () => [{ colId: 'severity', sort: direction }] },
    } as Parameters<NonNullable<typeof props.onSortChanged>>[0]);
    return <div aria-label="Finding rows">
      <button onClick={() => sort('desc')}>Sort SEV descending</button>
      <button onClick={() => sort('asc')}>Sort SEV ascending</button>
      <button onClick={() => sort(null)}>Clear sorting</button>
      {props.rowData?.map(row => <span key={row.id} data-testid="finding-row">{row.id}:{row.severity}</span>)}
    </div>;
  },
}));
vi.mock('@/designs/dark/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/light/PageShell', () => ({ default: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/designs/dark/ColumnChooser', () => ({ default: () => null }));
vi.mock('@/designs/light/ColumnChooser', () => ({ default: () => null }));
vi.mock('@/designs/dark/FindingDetailPanel', () => ({ default: () => null }));
vi.mock('@/designs/light/FindingDetailPanel', () => ({ default: () => null }));

const lastParams = () => mocks.params.mock.calls.at(-1)![0] as FindingsQueryParams;
beforeEach(() => {
  mocks.project = 'project-a'; mocks.fetching = false; mocks.placeholder = false; mocks.error = false;
  localStorage.setItem('vigolium_project_uuid', mocks.project);
  window.history.replaceState({}, '', '/findings/');
});
afterEach(() => window.history.replaceState({}, '', '/'));

describe.each([['dark', DarkFindingsPage], ['light', LightFindingsPage]] as const)('%s findings server pages', (_theme, Page) => {
  it('navigates 260 findings over three pages with clear controls and all three HIGH retained', () => {
    render(<Page />);
    expect(screen.getByRole('navigation', { name: 'Findings pagination' })).toHaveTextContent('1–100 of 260 findings');
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
    expect(screen.getAllByTestId('finding-row')).toHaveLength(100);
    expect(screen.queryByText('4540:high')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(lastParams()).toMatchObject({ limit: 100, offset: 100 });
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    expect(screen.getByText('4540:high')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(lastParams().offset).toBe(200);
    expect(screen.getAllByTestId('finding-row')).toHaveLength(60);
    expect(screen.getByText('201–260 of 260 findings')).toBeInTheDocument();
    expect(screen.getByText('1676:high')).toBeInTheDocument();
    expect(screen.getByText('1673:high')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    expect(lastParams().offset).toBe(100);
  });

  it('sorts globally in both directions, resets offset, preserves order on pagination and clears sorting', () => {
    render(<Page />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(screen.getByRole('button', { name: 'Sort SEV descending' }));
    expect(lastParams()).toMatchObject({ sort: 'severity', order: 'desc', offset: 0 });
    expect(screen.getAllByTestId('finding-row').slice(0, 3).map(row => row.textContent)).toEqual(['4540:high', '1676:high', '1673:high']);
    expect(mocks.grid.suppressMultiSort).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(lastParams()).toMatchObject({ sort: 'severity', order: 'desc', offset: 100 });
    fireEvent.click(screen.getByRole('button', { name: 'Sort SEV descending' }));
    expect(lastParams().offset).toBe(100); // Redundant/programmatic sort events must not reset the page.
    fireEvent.click(screen.getByRole('button', { name: 'Sort SEV ascending' }));
    expect(lastParams()).toMatchObject({ sort: 'severity', order: 'asc', offset: 0 });
    expect(screen.getAllByTestId('finding-row')[0]).toHaveTextContent(':info');
    fireEvent.click(screen.getByRole('button', { name: 'Clear sorting' }));
    expect(lastParams()).toMatchObject({ offset: 0, sort: undefined, order: undefined });
  });

  it('retains sort arrows and pagination after By Host, and filters HIGH across the entire project', () => {
    render(<Page />);
    fireEvent.click(screen.getByRole('button', { name: 'Sort SEV descending' }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(screen.getByRole('button', { name: 'By Host' }));
    expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Table' }));
    expect(lastParams()).toMatchObject({ sort: 'severity', order: 'desc', offset: 100 });
    expect(mocks.grid.columnDefs?.find(column => 'field' in column && column.field === 'severity')).toMatchObject({ sort: 'desc', sortable: true });
    fireEvent.click(screen.getByRole('button', { name: /sev:all/ }));
    fireEvent.click(screen.getByRole('button', { name: 'high' }));
    expect(lastParams()).toMatchObject({ severity: 'high', sort: 'severity', order: 'desc', offset: 0 });
    expect(screen.getAllByTestId('finding-row')).toHaveLength(3);
    expect(screen.getByText('1–3 of 3 findings')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'clear' }));
    expect(lastParams()).toMatchObject({ severity: undefined, sort: 'severity', order: 'desc', offset: 0 });
  });

  it('resets page, filters and ordering on a project change, including the first new-scope query', () => {
    const { rerender } = render(<Page />);
    fireEvent.click(screen.getByRole('button', { name: 'Sort SEV descending' }));
    fireEvent.click(screen.getByRole('button', { name: /sev:all/ }));
    fireEvent.click(screen.getByRole('button', { name: 'high' }));
    const previousCalls = mocks.params.mock.calls.length;
    mocks.project = 'project-b'; localStorage.setItem('vigolium_project_uuid', mocks.project);
    rerender(<Page />);
    for (const [params] of mocks.params.mock.calls.slice(previousCalls)) {
      expect(params).toMatchObject({ limit: 100, offset: 0 });
      expect(params.severity).toBeUndefined(); expect(params.sort).toBeUndefined();
    }
    expect(screen.getByRole('button', { name: /sev:all/ })).toBeInTheDocument();
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
  });

  it('hides previous-page rows while loading and only offers server-backed sorts', () => {
    const { rerender } = render(<Page />);
    for (const column of mocks.grid.columnDefs || []) {
      if ('field' in column && column.field) {
        expect(column.sortable).toBe(FINDING_SORT_FIELDS.has(column.field));
      }
    }
    mocks.placeholder = true; mocks.fetching = true;
    rerender(<Page />);
    expect(screen.queryAllByTestId('finding-row')).toHaveLength(0);
    expect(mocks.grid.loading).toBe(true);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.getByText('Loading findings…')).toBeInTheDocument();
    mocks.placeholder = false; mocks.fetching = false; mocks.error = true;
    rerender(<Page />);
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load findings');
  });
});
