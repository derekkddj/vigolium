import { describe, expect, it } from 'vitest';
import type { EvidenceEntry, Finding } from '@/api/types';
import { ambiguousPrimaryOccurrences, boundedPreview, decodeHTTPBase64, hasExchangeIdentity, HTTP_PREVIEW_LIMIT, linkedRecordReferences, parseInlineEvidence, primaryEvidence, primaryEvidenceDeclarations, recordLoadMessage, recordURLRelation } from '../findingEvidence';

const base64 = (text: string) => btoa(String.fromCharCode(...new TextEncoder().encode(text)));

describe('finding evidence helpers', () => {
  it('requires a nonempty exchange identity without dropping malformed declarations', () => {
    const malformed = [undefined, '', ' \t\r\n'].map((exchange_id) => ({ exchange_id, role: 'attack', primary: true, finding_url: 'https://app.test/proof' } as EvidenceEntry));
    const valid: EvidenceEntry = { exchange_id: ' exact-id ', role: 'confirmation', primary: true, label: 'producer text' };
    const baseline: EvidenceEntry = { exchange_id: 'baseline', role: 'baseline', primary: true, label: 'confirmed attack proof' };
    const unknown: EvidenceEntry = { exchange_id: 'unknown', role: 'unknown', primary: true };
    const contextual: EvidenceEntry = { exchange_id: 'context', role: 'attack', label: 'confirmed attack proof' };
    const entries = [...malformed, valid, baseline, unknown, contextual];
    expect(malformed.every((entry) => !hasExchangeIdentity(entry))).toBe(true);
    expect(primaryEvidenceDeclarations(entries)).toEqual([...malformed, valid]);
    expect(primaryEvidence(entries)).toEqual([valid]);
    expect(primaryEvidence(entries)[0].exchange_id).toBe(' exact-id ');
    expect(primaryEvidence()).toEqual([]);
  });

  it('retains malformed competing declarations in same-occurrence ambiguity', () => {
    const malformed: EvidenceEntry = { exchange_id: '', role: 'attack', primary: true, occurrence_id: 'same' };
    const valid: EvidenceEntry = { exchange_id: 'valid', role: 'confirmation', primary: true, occurrence_id: 'same' };
    expect(primaryEvidence([malformed, valid])).toEqual([valid]);
    expect(ambiguousPrimaryOccurrences([malformed, valid])).toEqual(['same']);
    expect(ambiguousPrimaryOccurrences([malformed, { ...valid, occurrence_id: 'later' }])).toEqual([]);
  });

  it('distinguishes same-occurrence ambiguity from independently selected historical occurrences', () => {
    const one = { exchange_id: 'one', role: 'attack' as const, primary: true };
    const two = { exchange_id: 'two', role: 'confirmation' as const, primary: true };
    expect(ambiguousPrimaryOccurrences([one, two])).toEqual(['legacy / unspecified occurrence']);
    expect(ambiguousPrimaryOccurrences([{ ...one, occurrence_id: 'same' }, { ...two, occurrence_id: 'same' }])).toEqual(['same']);
    expect(ambiguousPrimaryOccurrences([{ ...one, occurrence_id: 'first' }, { ...two, occurrence_id: 'later' }])).toEqual([]);
  });
  it('preserves a long response including every separator after the first', () => {
    const response = `HTTP/1.1 200 OK\n\n${'safe fixture '.repeat(10000)}\n---------\nresponse tail`;
    const result = parseInlineEvidence(`# [baseline]\nGET /fixture HTTP/1.1\n---------\n${response}`);
    expect(result.label).toBe('baseline');
    expect(result.request).toBe('GET /fixture HTTP/1.1');
    expect(result.response).toBe(response);
    expect(boundedPreview(result.response).text.length).toBe(HTTP_PREVIEW_LIMIT);
    expect(boundedPreview(result.response).truncated).toBe(true);
  });

  it('handles CRLF framing without changing response bytes represented by the text', () => {
    const result = parseInlineEvidence('# [confirm]\r\nrequest\r\n---------\r\nresponse\r\n---------\r\ntail');
    expect(result).toEqual({ label: 'confirm', request: 'request', response: 'response\r\n---------\r\ntail', hasSeparator: true });
    expect(parseInlineEvidence('opaque evidence').hasSeparator).toBe(false);
  });

  it('decodes base64 bytes as UTF-8, not Latin-1', () => {
    const text = 'HTTP/1.1 200 OK\r\n\r\ncafé — 日本語 🔎';
    const decoded = decodeHTTPBase64(base64(text));
    expect(decoded.text).toBe(text);
    expect(decoded.bytes).toEqual(new TextEncoder().encode(text));
    expect(decoded.error).toBeUndefined();
  });

  it('reports invalid base64 instead of pretending encoded data is HTTP', () => {
    expect(decodeHTTPBase64('%%%bad%%%')).toEqual({ error: expect.stringContaining('Invalid base64') });
  });

  it('retains exact binary bytes with an explicit invalid UTF-8 warning', () => {
    const result = decodeHTTPBase64(btoa(String.fromCharCode(0xff, 0xfe, 0, 65)));
    expect(result.bytes).toEqual(Uint8Array.from([0xff, 0xfe, 0, 65]));
    expect(result.error).toContain('Invalid UTF-8');
    expect(result.text).toContain('\ufffd');
  });

  it('does not cut a surrogate pair at the preview boundary', () => {
    expect(boundedPreview('ab🔎z', 3)).toEqual({ text: 'ab', truncated: true });
  });

  it('uses an explicit origin field, never invents proof roles for generic references', () => {
    const refs = linkedRecordReferences({ origin_record_uuid: 'baseline', http_record_uuids: ['related', 'baseline', 'related'] } as Finding);
    expect(refs).toEqual([{ uuid: 'baseline', role: 'Origin / baseline record' }, { uuid: 'related', role: 'Linked HTTP reference (role unspecified)' }]);
  });

  it('reports mismatches and missing URLs without a verdict about validity', () => {
    expect(recordURLRelation('https://example.invalid/a', 'https://example.invalid/b')).toBe('different');
    expect(recordURLRelation('https://example.invalid/a', 'https://example.invalid/a')).toBe('same');
    expect(recordURLRelation(undefined, 'https://example.invalid/b')).toBe('unknown');
    expect(recordLoadMessage({ status: 404 })).toContain('Missing HTTP record in the active project');
    expect(recordLoadMessage({ status: 403 })).toContain('access denied');
    expect(recordLoadMessage(new Error('network'))).toContain('Failed to load');
  });
});
