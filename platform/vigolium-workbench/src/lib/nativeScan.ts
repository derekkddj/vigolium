import type { Scan, ScanLogsQueryParams, ScanLogsResponse } from '@/api/types';

export const NATIVE_SCAN_LOG_PAGE_SIZE = 200;
export const NATIVE_SCAN_LOG_TAIL_BYTES = 256 * 1024;

export function isNativeScanActive(status?: string): boolean {
  return status === 'running' || status === 'pending' || status === 'paused';
}

/** Normalize both REST envelopes without discarding pagination or source metadata. */
export function normalizeNativeScanLogs(
  response: string | Partial<ScanLogsResponse>, params?: ScanLogsQueryParams,
): ScanLogsResponse {
  if (typeof response === 'string') return { logs: [], text: response, source: 'runtime.log' };
  const logs = response.logs ?? response.data ?? response.items ?? [];
  const offset = response.offset ?? params?.offset ?? 0;
  return {
    ...response, logs, offset, limit: response.limit ?? params?.limit,
    has_more: response.has_more ?? (response.total !== undefined ? offset + logs.length < response.total : undefined),
  };
}

export function nativeScanCoverage(scan: Scan): { label: string; explanation: string } {
  if (scan.completeness === 'partial') return {
    label: 'Partial', explanation: 'The recorded scan did not cover everything it was given.',
  };
  if (scan.completeness === 'complete') return {
    label: 'Complete (recorded plan)', explanation: 'The backend recorded completion of the supplied plan, not coverage of every possible module or vulnerability.',
  };
  return {
    label: 'Unknown', explanation: 'No completeness verdict was recorded. Status alone does not establish coverage.',
  };
}

export function nativeScanErrorCounts(scan: Scan) {
  return {
    phaseErrors: (scan.phase_outcomes ?? []).reduce((sum, phase) => sum + (phase.errors ?? 0), 0),
    moduleErrors: Object.values(scan.module_errors ?? {}).reduce((sum, count) => sum + count, 0),
    extensionsFailed: scan.extensions_failed?.length ?? 0,
  };
}

export function nativeScanParentHref(scan: Scan): string | null {
  return scan.agentic_scan_uuid ? `/agentic-scan?session=${encodeURIComponent(scan.agentic_scan_uuid)}` : null;
}
