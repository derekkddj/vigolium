import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchSelectedEvidence } from '../selectedEvidenceApi';

vi.mock('@/api/client', () => ({ buildApiUrl: (path: string) => path, buildAuthHeaders: () => ({ Authorization: 'Bearer fixture', 'X-Project-UUID': 'mutable-project' }), apiErrorFromBody: (_body: unknown, status: number) => ({ status }) }));
afterEach(() => vi.unstubAllGlobals());

describe('exact selected evidence API scope', () => {
  it('pins the finding association and captured project, never localStorage scope', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ id: 'exchange-id' }), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    const signal = new AbortController().signal;
    await fetchSelectedEvidence(7, 'exchange-id', 'captured-project', signal);
    expect(fetch).toHaveBeenCalledWith('/api/findings/7/evidence/exchange-id', { headers: { Authorization: 'Bearer fixture', 'X-Project-UUID': 'captured-project' }, signal });
  });
  it('does not retry an unavailable receipt in default/other scope', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 404 }));
    vi.stubGlobal('fetch', fetch);
    await expect(fetchSelectedEvidence(7, 'missing', 'captured-project', new AbortController().signal)).rejects.toEqual({ status: 404 });
    expect(fetch).toHaveBeenCalledTimes(1);
    await expect(fetchSelectedEvidence(7, 'missing', '', new AbortController().signal)).rejects.toThrow('Finding project is missing');
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('rejects identity substitution and already-aborted requests', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"id":"other"}', { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    await expect(fetchSelectedEvidence(7, 'expected', 'captured-project', new AbortController().signal)).rejects.toThrow('identity mismatch');
    const controller = new AbortController(); controller.abort();
    await expect(fetchSelectedEvidence(7, 'expected', 'captured-project', controller.signal)).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
