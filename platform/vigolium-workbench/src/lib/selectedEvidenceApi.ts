import { apiErrorFromBody, buildApiUrl, buildAuthHeaders } from '@/api/client';
import type { EvidenceExchange } from '@/api/types';

/** Read only this finding's selected receipt in the captured project. No scope recovery. */
export async function fetchSelectedEvidence(findingID: number, exchangeID: string, project: string, signal: AbortSignal): Promise<EvidenceExchange> {
  if (!project) throw new Error('Finding project is missing; evidence cannot be loaded safely.');
  signal.throwIfAborted();
  const path = `/api/findings/${findingID}/evidence/${encodeURIComponent(exchangeID)}`;
  const headers = buildAuthHeaders({ path });
  headers['X-Project-UUID'] = project;
  const response = await fetch(buildApiUrl(path), { headers, signal });
  signal.throwIfAborted();
  if (!response.ok) {
    const body = await response.json().catch(() => undefined);
    signal.throwIfAborted();
    throw apiErrorFromBody(body, response.status, response.statusText || 'Evidence exchange request failed');
  }
  const exchange: EvidenceExchange = await response.json();
  signal.throwIfAborted();
  if (exchange.id !== exchangeID) throw new Error('Evidence exchange identity mismatch.');
  return exchange;
}
