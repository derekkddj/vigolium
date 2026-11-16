import type { PostSortRowsParams } from 'ag-grid-community';
import { describe, expect, it } from 'vitest';
import type { Finding } from '@/api/types';
import { FINDING_SORT_FIELDS, FINDINGS_DEFAULT_COL_DEF, findingSortParams, preserveFindingResponseOrder } from '../findingsSorting';

const finding = (id: number, severity: string): Finding => ({
  id, project_uuid: 'project-a', url: 'https://example.invalid/finding', hostname: 'example.invalid',
  http_record_uuids: [], module_id: 'fixture', module_name: 'Fixture', severity, confidence: 'tentative',
  finding_hash: `fixture-${id}`, found_at: '', created_at: '',
});

// Server severity order is deliberately neither lexical nor ordered by finding ID.
const serverRows = [
  finding(42, 'critical'),
  finding(7, 'high'),
  finding(81, 'high'),
  finding(3, 'medium'),
  finding(90, 'low'),
  finding(15, 'info'),
];

describe('findingSortParams', () => {
  it('only advertises fields supported by the server', () => {
    expect([...FINDING_SORT_FIELDS]).toEqual([
      'severity', 'confidence', 'module_name', 'found_at', 'id', 'module_type', 'finding_source', 'status', 'url', 'scan_uuid', 'repo_name', 'source_file',
    ]);
  });

  for (const field of ['severity', 'confidence', 'module_name', 'found_at', 'id', 'module_type', 'finding_source', 'status', 'url', 'scan_uuid', 'repo_name', 'source_file']) {
    it.each(['asc', 'desc'] as const)(`maps ${field} %s to server query parameters`, (order) => {
      expect(findingSortParams([{ colId: field, sort: order }])).toEqual({ sort: field, order });
    });
  }

  it('clears query parameters when no column is sorted', () => {
    expect(findingSortParams([])).toEqual({ sort: undefined, order: undefined });
    expect(findingSortParams([
      { colId: 'severity', sort: null },
      { colId: 'confidence', sort: undefined },
    ])).toEqual({ sort: undefined, order: undefined });
  });

  it('ignores cleared columns before the active supported sort', () => {
    expect(findingSortParams([
      { colId: 'severity', sort: null },
      { colId: 'module_name', sort: 'asc' },
    ])).toEqual({ sort: 'module_name', order: 'asc' });
  });

  it.each(['hostname', 'record_kind', 'matched_at', 'tags', 'unsupported'])(
    'does not send unsupported field %s to the server',
    (field) => {
      expect(findingSortParams([{ colId: field, sort: 'asc' }])).toEqual({ sort: undefined, order: undefined });
      expect(findingSortParams([{ colId: field, sort: 'desc' }])).toEqual({ sort: undefined, order: undefined });
    },
  );
});

describe('server-driven findings grid sorting', () => {
  it('disables default page-local sorting and uses a neutral comparator', () => {
    expect(FINDINGS_DEFAULT_COL_DEF.sortable).toBe(false);
    expect(FINDINGS_DEFAULT_COL_DEF.sortingOrder).toEqual(['desc', 'asc', null]);
    const comparator = FINDINGS_DEFAULT_COL_DEF.comparator;
    if (typeof comparator !== 'function') throw new Error('Expected a neutral comparator function');
    const node = {} as PostSortRowsParams<Finding>['nodes'][number];
    expect(comparator('critical', 'info', node, node, false)).toBe(0);
    expect(comparator('info', 'critical', node, node, true)).toBe(0);
    expect(comparator('high', 'high', node, node, false)).toBe(0);
  });

  it('restores the exact nonlexical server severity order, including ties', () => {
    const nodes = [serverRows[5], serverRows[4], serverRows[3], serverRows[2], serverRows[1], serverRows[0]]
      .map((data) => ({ data }));
    const originalRows = [...serverRows];
    const postSortRows = preserveFindingResponseOrder(serverRows);

    postSortRows({ nodes } as unknown as PostSortRowsParams<Finding>);

    expect(nodes.map((node) => node.data)).toEqual(serverRows);
    expect(nodes.map((node) => node.data.id)).toEqual([42, 7, 81, 3, 90, 15]);
    expect(nodes.map((node) => node.data.severity)).toEqual(['critical', 'high', 'high', 'medium', 'low', 'info']);
    nodes.forEach((node, index) => expect(node.data).toBe(serverRows[index]));
    expect(serverRows).toEqual(originalRows);
  });

  it('keeps missing data and unknown IDs after known rows without changing their relative order', () => {
    const missingData = { data: undefined };
    const unknownFinding = { data: finding(999, 'critical') };
    const noData = {};
    const nodes = [missingData, { data: serverRows[2] }, unknownFinding, { data: serverRows[0] }, noData, { data: serverRows[1] }];

    preserveFindingResponseOrder(serverRows)({ nodes } as unknown as PostSortRowsParams<Finding>);

    expect(nodes).toEqual([
      { data: serverRows[0] }, { data: serverRows[1] }, { data: serverRows[2] },
      missingData, unknownFinding, noData,
    ]);
    expect(nodes[3]).toBe(missingData);
    expect(nodes[4]).toBe(unknownFinding);
    expect(nodes[5]).toBe(noData);
  });

  it('handles an empty response or empty node list without inventing an order', () => {
    const nodes = [{ data: serverRows[1] }, {}, { data: serverRows[0] }];
    const originalNodes = [...nodes];
    preserveFindingResponseOrder([])({ nodes } as unknown as PostSortRowsParams<Finding>);
    expect(nodes).toEqual(originalNodes);

    const emptyNodes: PostSortRowsParams<Finding>['nodes'] = [];
    preserveFindingResponseOrder(serverRows)({ nodes: emptyNodes } as PostSortRowsParams<Finding>);
    expect(emptyNodes).toEqual([]);
  });
});
