'use client';

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { AgGridReact } from 'ag-grid-react';
import type { ColDef, RowClickedEvent, SelectionChangedEvent, SortChangedEvent } from 'ag-grid-community';
import { Shield, Globe, Box, Search, RefreshCw, List, Layers, X } from 'lucide-react';
import { useFindings, useDeleteFinding } from '@/api/hooks';
import { useDetailSelection } from '@/hooks/useDetailSelection';
import { DETAIL_LINK_CONTEXT } from '@/lib/detailSelection';
import FindingsPagination from '@/components/shared/FindingsPagination';
import FindingsByHost from '@/components/shared/FindingsByHost';
import { FINDING_SORT_FIELDS, FINDINGS_DEFAULT_COL_DEF, findingSortParams, preserveFindingResponseOrder } from '@/lib/findingsSorting';
import { useToast } from '@/contexts/ToastContext';
import type { Finding, FindingsQueryParams } from '@/api/types';
import { FINDING_STATUSES } from '@/api/types';

import { registerAgGrid } from '@/lib/ag-grid-register';
import { formatDate } from '@/lib/formatters';
import { SEVERITY_COLORS, CONFIDENCE_COLORS, MODULE_TYPE_COLORS, AG_GRID_THEME } from './theme';
import PageShell from './PageShell';
import FindingDetailPanel from './FindingDetailPanel';
import Dropdown from './Dropdown';
import ColumnChooser from './ColumnChooser';

registerAgGrid();

const PAGE_SIZE = 100;

type ViewTab = 'table' | 'by-host';

/* ── Grouped-by-host view ─────────────────────────────────────────── */
function GroupedByHostView({
  filters,
  onSelectFinding,
  selectedFindingId,
}: {
  filters: FindingsQueryParams;
  onSelectFinding: (id: number) => void;
  selectedFindingId: number | null;
}) {
  return (
    <FindingsByHost
      filters={filters}
      theme="dark"
      onSelectFinding={onSelectFinding}
      selectedFindingId={selectedFindingId}
    />
  );
}

function SeverityRenderer({ value }: { value: string }) {
  const color = SEVERITY_COLORS[value] || '#918175';
  return (
    <span className="text-xs font-bold uppercase" style={{ color }}>
      {value}
    </span>
  );
}

function ConfidenceRenderer({ value }: { value: string }) {
  const color = CONFIDENCE_COLORS[value] || '#918175';
  return (
    <span className="text-xs" style={{ color }}>
      {value}
    </span>
  );
}

function ModuleTypeRenderer({ value }: { value: string }) {
  const color = MODULE_TYPE_COLORS[value] || '#918175';
  return (
    <span className="text-xs" style={{ color }}>
      {value}
    </span>
  );
}

function DateRenderer({ value }: { value: string }) {
  return <span className="text-xs text-[#918175]">{formatDate(value)}</span>;
}

const HASH_COLORS = [
  '#7fd962', '#68a8e4', '#e4a868', '#c678dd', '#56b6c2',
  '#e06c75', '#d19a66', '#98c379', '#e5c07b', '#61afef',
];

function hashColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
  }
  return HASH_COLORS[Math.abs(hash) % HASH_COLORS.length];
}

function RepoNameRenderer({ value }: { value: string }) {
  if (!value) return null;
  return (
    <span className="text-xs font-medium" style={{ color: hashColor(value) }}>
      {value}
    </span>
  );
}

function TagsRenderer({ value }: { value: string[] }) {
  if (!value || value.length === 0) return null;
  return (
    <span className="text-xs">
      {value.map((tag, i) => (
        <span key={tag}>
          {i > 0 && <span className="text-[#918175]">, </span>}
          <span style={{ color: hashColor(tag) }}>{tag}</span>
        </span>
      ))}
    </span>
  );
}

export default function FindingsPage({ initialId }: { initialId?: number | null }) {
  const [params, setParams] = useState<FindingsQueryParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });
  const [searchInput, setSearchInput] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [domainFilter, setDomainFilter] = useState('');
  const [moduleFilter, setModuleFilter] = useState('');
  const [moduleTypeFilter, setModuleTypeFilter] = useState('');
  const [findingSourceFilter, setFindingSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const { selectedId: selectedFindingId, selectDetail: navigateToFinding, projectKey } = useDetailSelection('finding', initialId);
  const [selectedRows, setSelectedRows] = useState<Finding[]>([]);
  const gridRef = useRef<AgGridReact<Finding>>(null);
  const [hiddenColumns, setHiddenColumns] = useState<Set<string>>(new Set(['scan_uuid']));
  const [viewTab, setViewTab] = useState<ViewTab>('table');

  const deleteFinding = useDeleteFinding();
  const { toast } = useToast();

  const [paramsProject, setParamsProject] = useState(projectKey);
  const projectChanged = paramsProject !== projectKey;

  useEffect(() => {
    if (!projectChanged) return;
    setParamsProject(projectKey);
    setParams({ limit: PAGE_SIZE, offset: 0 });
    setSearchInput('');
    setSeverityFilter('');
    setDomainFilter('');
    setModuleFilter('');
    setModuleTypeFilter('');
    setFindingSourceFilter('');
    setStatusFilter('');
  }, [projectKey, projectChanged]);

  const handleDeleteSelected = useCallback(async () => {
    const ids = selectedRows.map((r) => r.id);
    const results = await Promise.allSettled(ids.map((id) => deleteFinding.mutateAsync(id)));
    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    const failed = results.length - succeeded;
    if (failed === 0) {
      toast(`Deleted ${succeeded} finding(s)`, 'success');
    } else {
      toast(`Deleted ${succeeded}, failed ${failed}`, 'error');
    }
    setSelectedRows([]);
    gridRef.current?.api?.deselectAll();
  }, [selectedRows, deleteFinding, toast]);

  const queryParams = useMemo(
    () => projectChanged ? { limit: PAGE_SIZE, offset: 0 } : ({
      ...params,
      severity: severityFilter || undefined,
      search: searchInput || undefined,
      domain: domainFilter || undefined,
      module_name: moduleFilter || undefined,
      module_type: moduleTypeFilter || undefined,
      finding_source: findingSourceFilter || undefined,
      status: statusFilter || undefined,
    }),
    [params, severityFilter, searchInput, domainFilter, moduleFilter, moduleTypeFilter, findingSourceFilter, statusFilter, projectChanged]
  );

  const { data, isLoading, refetch, isFetching, isPlaceholderData, isError } = useFindings(queryParams);
  const pageLoading = isLoading || isPlaceholderData || projectChanged;
  const rows = useMemo(() => pageLoading ? [] : data?.data || [], [pageLoading, data]);
  const postSortRows = useMemo(() => preserveFindingResponseOrder(rows), [rows]);

  useEffect(() => {
    setSelectedRows([]);
    gridRef.current?.api?.deselectAll();
  }, [queryParams, projectKey]);

  const onSortChanged = useCallback((event: SortChangedEvent<Finding>) => {
    if (projectChanged) return;
    const { sort, order } = findingSortParams(event.api.getColumnState());
    setParams((previous) => previous.sort === sort && previous.order === order
      ? previous
      : { ...previous, sort, order, offset: 0 });
  }, [projectChanged]);

  const columnDefs = useMemo<ColDef<Finding>[]>(
    () => [
      { width: 40, sortable: false, filter: false, resizable: false },
      { field: 'id', headerName: 'ID', width: 60 },
      { field: 'severity', headerName: 'SEV', width: 80, cellRenderer: SeverityRenderer },
      { field: 'confidence', headerName: 'CONF', width: 100, cellRenderer: ConfidenceRenderer },
      { field: 'module_name', headerName: 'MODULE', flex: 1, minWidth: 140 },
      { field: 'url', headerName: 'URL', flex: 1, minWidth: 180 },
      { field: 'module_type', headerName: 'TYPE', width: 80, cellRenderer: ModuleTypeRenderer },
      { field: 'status', headerName: 'STATUS', width: 110 },
      { field: 'description', headerName: 'DESCRIPTION', flex: 2, minWidth: 200 },
      {
        field: 'matched_at',
        headerName: 'MATCHED_AT',
        flex: 1,
        minWidth: 120,
        valueFormatter: (p) => (p.value as string[])?.join(', ') || '',
      },
      {
        field: 'tags',
        headerName: 'TAGS',
        width: 140,
        cellRenderer: TagsRenderer,
        valueFormatter: (p) => (p.value as string[])?.join(', ') || '',
      },
      { field: 'scan_uuid', headerName: 'SCAN_ID', width: 100 },
      { field: 'finding_source', headerName: 'SOURCE', width: 120 },
      { field: 'repo_name', headerName: 'REPO', width: 140, cellRenderer: RepoNameRenderer },
      { field: 'source_file', headerName: 'FILE', width: 160 },
      { field: 'found_at', headerName: 'TIME', width: 120, cellRenderer: DateRenderer },
    ],
    []
  );

  const toggleableColumns = useMemo(
    () => columnDefs.filter((c) => c.field).map((c) => ({ field: c.field!, label: c.headerName || c.field! })),
    [columnDefs]
  );

  const effectiveColumnDefs = useMemo<ColDef<Finding>[]>(
    () => columnDefs.map((c) => (!c.field ? c : {
      ...c,
      hide: hiddenColumns.has(c.field),
      sortable: FINDING_SORT_FIELDS.has(c.field),
      headerTooltip: FINDING_SORT_FIELDS.has(c.field) ? 'Order all matching findings across pages' : undefined,
      sort: !projectChanged && c.field === params.sort && (params.order === 'asc' || params.order === 'desc') ? params.order : null,
    })),
    [columnDefs, hiddenColumns, params.sort, params.order, projectChanged]
  );

  const goToPage = useCallback((page: number) => {
    if (isFetching || pageLoading || page < 1) return;
    setParams((prev) => ({ ...prev, offset: (page - 1) * PAGE_SIZE }));
  }, [isFetching, pageLoading]);

  const resetOffset = () => setParams((p) => ({ ...p, offset: 0 }));

  const hasActiveFilters = !!(severityFilter || domainFilter || moduleFilter || moduleTypeFilter || findingSourceFilter || statusFilter || searchInput);
  const clearFilters = () => {
    setSeverityFilter('');
    setDomainFilter('');
    setModuleFilter('');
    setModuleTypeFilter('');
    setFindingSourceFilter('');
    setStatusFilter('');
    setSearchInput('');
    resetOffset();
  };

  const selectedFindingIdRef = useRef(selectedFindingId);
  selectedFindingIdRef.current = selectedFindingId;

  const onRowClicked = useCallback((event: RowClickedEvent<Finding>) => {
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest('.ag-checkbox-input-wrapper, .ag-selection-checkbox')) return;
    if (event.data?.id != null) {
      navigateToFinding(selectedFindingIdRef.current === event.data!.id ? null : event.data!.id);
    }
  }, [navigateToFinding]);

  const onSelectionChanged = useCallback((event: SelectionChangedEvent<Finding>) => {
    setSelectedRows(event.api.getSelectedRows());
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedFindingId !== null) {
        const tag = (e.target as HTMLElement)?.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        navigateToFinding(null);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [selectedFindingId, navigateToFinding]);

  return (
    <PageShell>
      <div className="flex flex-1 min-h-0" style={{ minHeight: 500 }}>
        {/* Table section */}
        <div className={`border border-[#2e2b26] bg-[#1c1b19] overflow-hidden flex flex-col ${selectedFindingId !== null ? 'w-1/2' : 'w-full'} transition-all`}>
          <div className="px-3 py-1.5 border-b border-[#2e2b26] flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-[#7fd962] text-xs font-bold">FINDINGS</span>
              <button onClick={() => refetch()} className="text-[#918175] hover:text-[#7fd962] transition-colors" title="Refresh">
                <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
              </button>
              {/* View tabs */}
              <div className="flex items-center gap-0.5 ml-2 border border-[#2e2b26] rounded-sm">
                <button
                  onClick={() => setViewTab('table')}
                  className={`flex items-center gap-1 px-1.5 py-0.5 text-xs transition-colors ${
                    viewTab === 'table'
                      ? 'text-[#7fd962] bg-[#7fd962]/10'
                      : 'text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Table view"
                >
                  <List className="w-3 h-3" />
                  Table
                </button>
                <button
                  onClick={() => setViewTab('by-host')}
                  className={`flex items-center gap-1 px-1.5 py-0.5 text-xs transition-colors ${
                    viewTab === 'by-host'
                      ? 'text-[#7fd962] bg-[#7fd962]/10'
                      : 'text-[#918175] hover:text-[#fce8c3]'
                  }`}
                  title="Group by hostname"
                >
                  <Layers className="w-3 h-3" />
                  By Host
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs flex-wrap">
              <button
                onClick={clearFilters}
                disabled={!hasActiveFilters}
                title="Clear all filters"
                className={`flex items-center gap-1 border text-xs px-2 py-0.5 transition-colors ${
                  hasActiveFilters
                    ? 'border-[#ef2f27]/50 text-[#ef2f27] bg-[#1c1b19] hover:bg-[#ef2f27]/10'
                    : 'border-[#2e2b26] text-[#918175] bg-[#1c1b19] opacity-40 cursor-default'
                }`}
              >
                <X className="w-3 h-3" />
                clear
              </button>
              <Dropdown
                value={severityFilter}
                icon={<Shield className="w-3 h-3" />}
                options={[
                  { value: '', label: 'sev:all' },
                  { value: 'critical', label: 'critical' },
                  { value: 'high', label: 'high' },
                  { value: 'medium', label: 'medium' },
                  { value: 'low', label: 'low' },
                  { value: 'info', label: 'info' },
                ]}
                onChange={(v) => { setSeverityFilter(v); resetOffset(); }}
              />
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Globe className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={domainFilter} onChange={(e) => { setDomainFilter(e.target.value); resetOffset(); }} placeholder="domain..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Box className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={moduleFilter} onChange={(e) => { setModuleFilter(e.target.value); resetOffset(); }} placeholder="module..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-28 focus:outline-none" />
              </div>
              <Dropdown
                value={moduleTypeFilter}
                options={[
                  { value: '', label: 'type:all' },
                  { value: 'active', label: 'active' },
                  { value: 'passive', label: 'passive' },
                ]}
                onChange={(v) => { setModuleTypeFilter(v); resetOffset(); }}
              />
              <Dropdown
                value={findingSourceFilter}
                options={[
                  { value: '', label: 'source:all' },
                  { value: 'audit', label: 'audit' },
                  { value: 'spa', label: 'spa' },
                  { value: 'agent', label: 'agent' },
                  { value: 'oast', label: 'oast' },
                  { value: 'source-tools', label: 'source-tools' },
                  { value: 'extension', label: 'extension' },
                ]}
                onChange={(v) => { setFindingSourceFilter(v); resetOffset(); }}
              />
              <Dropdown
                value={statusFilter}
                options={[
                  { value: '', label: 'status:all' },
                  ...FINDING_STATUSES.map((s) => ({ value: s, label: s })),
                ]}
                onChange={(v) => { setStatusFilter(v); resetOffset(); }}
              />
              <div className="flex items-center border border-[#2e2b26] bg-[#1c1b19] focus-within:border-[#7fd962]/50">
                <Search className="w-3 h-3 text-[#918175] ml-1.5 shrink-0" />
                <input type="text" value={searchInput} onChange={(e) => { setSearchInput(e.target.value); resetOffset(); }} placeholder="search..." className="bg-transparent text-[#fce8c3] text-xs px-1.5 py-0.5 w-36 focus:outline-none" />
              </div>
              {viewTab === 'table' && (
                <ColumnChooser columns={toggleableColumns} hiddenColumns={hiddenColumns} onChange={setHiddenColumns} />
              )}
            </div>
          </div>

          {/* Action toolbar */}
          {viewTab === 'table' && selectedRows.length > 0 && (
            <div className="px-3 py-1.5 border-b border-[#2e2b26] bg-[#272520] flex items-center gap-3 text-xs">
              <span className="text-[#fce8c3]">{selectedRows.length} selected</span>
              <button
                onClick={handleDeleteSelected}
                disabled={deleteFinding.isPending}
                className="px-2 py-0.5 border border-[#ef2f27]/50 text-[#ef2f27] hover:bg-[#ef2f27]/10 disabled:opacity-50 transition-colors"
              >
                {deleteFinding.isPending ? 'deleting...' : '[DELETE SELECTED]'}
              </button>
            </div>
          )}

          {isError && <p role="alert" className="px-3 py-2 text-xs" style={{ color: 'var(--v-accent)' }}>Could not load findings. Use Refresh to retry.</p>}

          {/* Table view */}
          {viewTab === 'table' && (
            <>
              <div className={`${AG_GRID_THEME} w-full flex-1`}>
                <AgGridReact<Finding>
                  ref={gridRef}
                  rowData={rows}
                  columnDefs={effectiveColumnDefs}
                  defaultColDef={FINDINGS_DEFAULT_COL_DEF}
                  suppressMultiSort
                  onSortChanged={onSortChanged}
                  postSortRows={postSortRows}
                  loading={pageLoading}
                  suppressCellFocus
                  animateRows
                  domLayout="normal"
                  onRowClicked={onRowClicked}
                  rowSelection={{ mode: 'multiRow', headerCheckbox: true, checkboxes: true, enableClickSelection: false }}
                  onSelectionChanged={onSelectionChanged}
                  overlayNoRowsTemplate='<span style="color:#403d38">no findings</span>'
                />
              </div>

              {data && (data.total > 0 || data.has_more) && (
                <FindingsPagination
                  offset={queryParams.offset || 0}
                  pageSize={PAGE_SIZE}
                  returned={rows.length}
                  total={data.total}
                  hasMore={data.has_more}
                  busy={isFetching || pageLoading}
                  onPageChange={goToPage}
                />
              )}
            </>
          )}

          {/* Grouped by host view */}
          {viewTab === 'by-host' && (
            <GroupedByHostView
              filters={queryParams}
              onSelectFinding={(id) => navigateToFinding(selectedFindingId === id ? null : id)}
              selectedFindingId={selectedFindingId}
            />
          )}
        </div>

        {/* Detail panel */}
        {selectedFindingId !== null && (
          <div className="w-1/2 flex flex-col min-h-0">
            <p role="note" className="px-3 py-1 text-xs text-[#918175] border-b border-[#2e2b26]">{DETAIL_LINK_CONTEXT}</p>
            <FindingDetailPanel
              findingId={selectedFindingId}
              onClose={() => navigateToFinding(null)}
            />
          </div>
        )}
      </div>
    </PageShell>
  );
}
