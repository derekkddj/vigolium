import { describe, expect, it } from 'vitest';
import type { Scan, ScanLog } from '@/api/types';
import { nativeScanCoverage, nativeScanErrorCounts, nativeScanParentHref, normalizeNativeScanLogs } from '../nativeScan';

const scan: Scan = { uuid: 'native', status: 'completed', total_findings: 0, processed_count: 8, started_at: '', created_at: '' };
const log: ScanLog = { id: 1, scan_uuid: 'native', level: 'info', message: 'visible', created_at: '' };

describe('Native REST log envelopes', () => {
  it.each(['logs', 'data', 'items'] as const)('normalizes %s and retains total, pagination, and source', (key) => {
    const result = normalizeNativeScanLogs({ [key]: [log], total: 401, offset: 200, limit: 200, has_more: true, source: 'legacy' });
    expect(result).toMatchObject({ logs: [log], total: 401, offset: 200, limit: 200, has_more: true, source: 'legacy' });
  });
  it('prefers logs over data over items, including an explicit empty logs page', () => {
    expect(normalizeNativeScanLogs({ logs: [], data: [log], items: [log] }).logs).toEqual([]);
    expect(normalizeNativeScanLogs({ data: [log], items: [] }).logs).toEqual([log]);
  });
  it('derives v1 paging from the request, without manufacturing a total', () => {
    expect(normalizeNativeScanLogs({ logs: [log], total: 201 }, { offset: 200, limit: 200 })).toMatchObject({ offset: 200, limit: 200, has_more: false });
    expect(normalizeNativeScanLogs({ logs: [] }).total).toBeUndefined();
  });
  it.each(['runtime text', ''])('text %j is a tail with unknown total and truncation', (text) => {
    expect(normalizeNativeScanLogs(text)).toEqual({ logs: [], source: 'runtime.log', text });
  });
});

describe('Native coverage and attribution', () => {
  it('a completed partial run remains partial', () => {
    expect(nativeScanCoverage({ ...scan, completeness: 'partial' }).label).toBe('Partial');
  });
  it.each([undefined, '', 'future-value'])('legacy/unknown verdict %j is not complete', (completeness) => {
    expect(nativeScanCoverage({ ...scan, completeness }).label).toBe('Unknown');
  });
  it('recorded complete is bounded to the supplied plan', () => {
    expect(nativeScanCoverage({ ...scan, completeness: 'complete' }).explanation).toContain('not coverage of every possible module');
  });
  it('keeps phase errors separate from module failures', () => {
    expect(nativeScanErrorCounts({ ...scan, phase_outcomes: [{ phase: 'assessment', state: 'failed', errors: 2, duration_ms: 20 }], module_errors: { one: 3, two: 4 }, extensions_failed: ['bad.js'] })).toEqual({ phaseErrors: 2, moduleErrors: 7, extensionsFailed: 1 });
  });
  it('links only the stored parent agent session', () => {
    expect(nativeScanParentHref(scan)).toBeNull();
    expect(nativeScanParentHref({ ...scan, agentic_scan_uuid: 'parent?x=1' })).toBe('/agentic-scan?session=parent%3Fx%3D1');
  });
});
