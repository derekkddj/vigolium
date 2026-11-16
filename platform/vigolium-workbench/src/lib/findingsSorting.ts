import type { ColDef, ColumnState, PostSortRowsParams } from 'ag-grid-community';
import type { Finding, FindingsQueryParams } from '@/api/types';

// These displayed columns are supported by FindingsQueryBuilder on the server.
// Other headers must not offer misleading, page-local ordering.
export const FINDING_SORT_FIELDS = new Set([
  'severity', 'confidence', 'module_name', 'found_at', 'id', 'module_type', 'finding_source', 'status', 'url', 'scan_uuid', 'repo_name', 'source_file',
]);

export const FINDINGS_DEFAULT_COL_DEF: ColDef<Finding> = {
  sortable: false,
  sortingOrder: ['desc', 'asc', null],
  comparator: () => 0,
};

export function findingSortParams(columns: Pick<ColumnState, 'colId' | 'sort'>[]): Pick<FindingsQueryParams, 'sort' | 'order'> {
  const active = columns.find((column) => column.sort === 'asc' || column.sort === 'desc');
  return active && FINDING_SORT_FIELDS.has(active.colId)
    ? { sort: active.colId, order: active.sort! }
    : { sort: undefined, order: undefined };
}

/** Header arrows drive the API query; they must never reorder only this page. */
export function preserveFindingResponseOrder(rows: Finding[]) {
  const positions = new Map(rows.map((row, index) => [row.id, index]));
  return ({ nodes }: PostSortRowsParams<Finding>) => {
    const position = (id?: number) => id === undefined ? Number.MAX_SAFE_INTEGER : positions.get(id) ?? Number.MAX_SAFE_INTEGER;
    nodes.sort((a, b) => position(a.data?.id) - position(b.data?.id));
  };
}
