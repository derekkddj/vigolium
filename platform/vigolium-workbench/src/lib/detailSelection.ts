import { withDemoKey } from '@/api/client';

export type DetailSelectionKind = 'finding' | 'http-record';
export interface DetailSelectionValues {
  finding: number;
  'http-record': string;
}

export const DETAIL_LINK_CONTEXT = 'Detail links use the active project. Select the same project before opening a shared link; links do not switch projects.';

export const DETAIL_ROUTES = {
  finding: { path: '/findings/', parameter: 'id' },
  'http-record': { path: '/http-records/', parameter: 'uuid' },
} as const;

/** No coercion of whitespace, exponent/hex notation, fractions or rounded IDs. */
export function parseFindingId(value: unknown): number | null {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? value : null;
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) return null;
  const id = Number(value);
  return Number.isSafeInteger(id) && String(id) === value ? id : null;
}

/** Preserve opaque record identities, including legacy non-RFC UUIDs, exactly. */
export function parseHttpRecordUUID(value: unknown): string | null {
  // A record identity is one bounded API path segment, never a URL/path or an
  // encoded segment. Do not trim/lowercase it into a different database key.
  return typeof value === 'string' && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value) ? value : null;
}

export function parseDetailId<K extends DetailSelectionKind>(kind: K, value: unknown): DetailSelectionValues[K] | null {
  return (kind === 'finding' ? parseFindingId(value) : parseHttpRecordUUID(value)) as DetailSelectionValues[K] | null;
}

export function parseLegacyDetailId<K extends DetailSelectionKind>(kind: K, segments: unknown): DetailSelectionValues[K] | null {
  return Array.isArray(segments) && segments.length === 1 && typeof segments[0] === 'string'
    ? parseDetailId(kind, segments[0])
    : null;
}

export function legacyDetailIdFromPath<K extends DetailSelectionKind>(kind: K, pathname: string): DetailSelectionValues[K] | null {
  const { path } = DETAIL_ROUTES[kind];
  if (!pathname.startsWith(path)) return null;
  const suffix = pathname.slice(path.length).replace(/\/$/, '');
  if (!suffix || suffix.includes('/')) return null;
  try {
    return parseDetailId(kind, decodeURIComponent(suffix));
  } catch {
    return null;
  }
}

/** An explicit invalid/duplicate query must not fall back to a legacy ID. */
export function detailIdFromSearch<K extends DetailSelectionKind>(kind: K, search: string, legacyId?: unknown): DetailSelectionValues[K] | null {
  const values = new URLSearchParams(search).getAll(DETAIL_ROUTES[kind].parameter);
  if (values.length === 0) return parseDetailId(kind, legacyId);
  return values.length === 1 ? parseDetailId(kind, values[0]) : null;
}

/** Only exported list pages are reloadable. Never put credentials in links. */
export function detailSelectionHref<K extends DetailSelectionKind>(kind: K, value: DetailSelectionValues[K] | null): string {
  const { path, parameter } = DETAIL_ROUTES[kind];
  const id = parseDetailId(kind, value);
  const query = new URLSearchParams();
  if (id !== null) query.set(parameter, String(id));
  return withDemoKey(query.size ? `${path}?${query}` : path);
}
