import { apiErrorFromBody, buildApiUrl, buildAuthHeaders } from '@/api/client';
import type { Scan, ScanLogsQueryParams, ScanLogsResponse } from '@/api/types';
import { NATIVE_SCAN_LOG_TAIL_BYTES, normalizeNativeScanLogs } from './nativeScan';

/** Isolated Native detail reads: cancellable, pinned to the query's project, no fallback to another project. */
async function nativeScanResponse(path: string, project: string | null, signal: AbortSignal): Promise<Response> {
  const headers = buildAuthHeaders({ path });
  delete headers['X-Project-UUID'];
  if (project) headers['X-Project-UUID'] = project;
  const response = await fetch(buildApiUrl(path), { headers, signal });
  if (!response.ok) {
    const body = await response.json().catch(() => undefined);
    throw apiErrorFromBody(body, response.status, response.statusText || 'Native scan request failed');
  }
  return response;
}

export async function fetchNativeScan(uuid: string, project: string | null, signal: AbortSignal): Promise<Scan> {
  const response = await nativeScanResponse(`/api/scans/${encodeURIComponent(uuid)}`, project, signal);
  return response.json();
}

export async function fetchNativeScanLogs(
  uuid: string, project: string | null, signal: AbortSignal, params?: ScanLogsQueryParams,
): Promise<ScanLogsResponse> {
  const query = new URLSearchParams({ strip: '1', max_bytes: String(NATIVE_SCAN_LOG_TAIL_BYTES) });
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== '') query.set(key, String(value));
  }
  const response = await nativeScanResponse(`/api/scans/${encodeURIComponent(uuid)}/logs?${query}`, project, signal);
  if ((response.headers.get('Content-Type') ?? '').startsWith('text/plain')) {
    const result = normalizeNativeScanLogs(await response.text());
    const size = response.headers.get('X-Log-Size');
    const truncated = response.headers.get('X-Log-Truncated');
    if (size !== null && size.trim() !== '' && Number.isFinite(Number(size)) && Number(size) >= 0) result.log_size = Number(size);
    if (truncated === 'true' || truncated === 'false') result.truncated = truncated === 'true';
    return result;
  }
  return normalizeNativeScanLogs(await response.json(), params);
}
