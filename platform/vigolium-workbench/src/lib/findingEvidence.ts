import type { EvidenceEntry, Finding } from '@/api/types';

/** Validate presence without rewriting the exact stored exchange identity. */
export function hasExchangeIdentity(entry: EvidenceEntry) {
  return typeof entry.exchange_id === 'string' && entry.exchange_id.trim().length > 0;
}

/** Declarations are metadata, not a verdict; retain malformed ones for ambiguity checks. */
export function primaryEvidenceDeclarations(entries: EvidenceEntry[] = []) {
  return entries.filter((entry) => entry.primary && ['attack', 'confirmation', 'observation'].includes(entry.role));
}

/** Inspectable selection is explicit: never infer identity from URLs or other metadata. */
export function primaryEvidence(entries: EvidenceEntry[] = []) {
  return primaryEvidenceDeclarations(entries).filter(hasExchangeIdentity);
}

export function ambiguousPrimaryOccurrences(entries: EvidenceEntry[] = []) {
  const counts = new Map<string, number>();
  for (const entry of primaryEvidenceDeclarations(entries)) {
    const key = entry.occurrence_id || '';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].filter(([, count]) => count > 1).map(([key]) => key || 'legacy / unspecified occurrence');
}

export function evidenceLoadMessage(error: unknown) {
  const status = error && typeof error === 'object' && 'status' in error ? error.status : undefined;
  if (status === 404) return 'Selected exchange missing or unavailable for this finding in its captured project. No fallback evidence is substituted.';
  if (status === 401 || status === 403) return 'Selected exchange unavailable: access denied. No other scope will be tried.';
  return 'Selected exchange unavailable. No evidence conclusion can be drawn.';
}

export const HTTP_PREVIEW_LIMIT = 64 * 1024;
const EVIDENCE_SEPARATOR = '\n---------\n';

/** Split once: separator-like text in a response body is still response data. */
export function parseInlineEvidence(evidence: string) {
  const marker = evidence.match(/^# \[([^\]\r\n]+)\](?:\r?\n|$)/);
  const content = marker ? evidence.slice(marker[0].length) : evidence;
  const separator = /\r?\n---------\r?\n/.exec(content);
  const index = separator?.index ?? -1;
  return {
    label: marker?.[1],
    request: index < 0 ? content : content.slice(0, index),
    response: index < 0 ? '' : content.slice(index + (separator?.[0].length ?? EVIDENCE_SEPARATOR.length)),
    hasSeparator: index >= 0,
  };
}

export function boundedPreview(text: string, limit = HTTP_PREVIEW_LIMIT) {
  // Avoid displaying half of a surrogate pair at the preview boundary.
  let end = Math.min(text.length, limit);
  if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1] ?? '')) end--;
  return { text: text.slice(0, end), truncated: end < text.length };
}

export interface DecodedHTTP {
  bytes?: Uint8Array<ArrayBuffer>;
  text?: string;
  error?: string;
}

/** Go []byte JSON fields are base64 bytes, not Latin-1 strings or fallback text. */
export function decodeHTTPBase64(encoded: string): DecodedHTTP {
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    const binary = atob(encoded);
    bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return { error: 'Invalid base64 encoding; raw bytes are unavailable.' };
  }
  try {
    return { bytes, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
  } catch {
    return {
      bytes,
      text: new TextDecoder('utf-8').decode(bytes),
      error: 'Invalid UTF-8 or binary content; preview uses replacement characters. Download exact bytes for inspection.',
    };
  }
}

export function linkedRecordReferences(finding: Finding) {
  const uuids = Array.from(new Set([finding.origin_record_uuid, ...(finding.http_record_uuids ?? [])].filter((uuid): uuid is string => !!uuid)));
  return uuids.map((uuid) => ({
    uuid,
    role: uuid === finding.origin_record_uuid ? 'Origin / baseline record' : 'Linked HTTP reference (role unspecified)',
  }));
}

/** Compare the stored URLs exactly; do not normalize away potentially meaningful differences. */
export function recordURLRelation(findingURL?: string, recordURL?: string) {
  if (!findingURL || !recordURL) return 'unknown';
  return findingURL === recordURL ? 'same' : 'different';
}

export function recordLoadMessage(error: unknown) {
  const status = error && typeof error === 'object' && 'status' in error ? error.status : undefined;
  if (status === 404) return 'Missing HTTP record in the active project. The reference may be stale or unavailable in this project.';
  if (status === 401 || status === 403) return 'HTTP record unavailable: access denied in the active project.';
  return 'Failed to load HTTP record. It is currently unavailable; no evidence conclusion can be drawn.';
}
