import { apiErrorFromBody, buildApiUrl, buildAuthHeaders } from '@/api/client';
import type { HTTPRecord } from '@/api/types';

function checkAbort(signal: AbortSignal) {
  if (signal.aborted) throw new DOMException('HTTP record request cancelled.', 'AbortError');
}

/** Full selected-record read, pinned to the query's scope; never recover into another project. */
export async function fetchSelectedHttpRecord(uuid: string, project: string | null, signal: AbortSignal): Promise<HTTPRecord> {
  checkAbort(signal);
  const path = `/api/http-records/${encodeURIComponent(uuid)}`;
  const headers = buildAuthHeaders({ path });
  // Null explicitly means the server's default scope, not mutable localStorage.
  // A failed explicit project is never retried in that default scope.
  delete headers['X-Project-UUID'];
  if (project) headers['X-Project-UUID'] = project;
  const response = await fetch(buildApiUrl(path), { headers, signal });
  if (signal.aborted) {
    try { await response.body?.cancel(); } catch { /* transport already cancelled */ }
    checkAbort(signal);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => undefined);
    checkAbort(signal);
    throw apiErrorFromBody(body, response.status, response.statusText || 'HTTP record request failed');
  }
  const record: HTTPRecord = await response.json();
  checkAbort(signal);
  return record;
}
