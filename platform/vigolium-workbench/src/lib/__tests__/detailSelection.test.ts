import { afterEach, describe, expect, it } from 'vitest';
import {
  detailIdFromSearch, detailSelectionHref, legacyDetailIdFromPath,
  parseFindingId, parseHttpRecordUUID, parseLegacyDetailId,
} from '@/lib/detailSelection';

afterEach(() => window.history.replaceState({}, '', '/'));

describe('Static-safe detail identities and links', () => {
  it.each(['', '0', '-1', '+1', '01', '1.0', '1e3', '0x10', ' 1', '1 ', 'NaN', 'Infinity', '9007199254740992', '1/2'])('rejects non-exact finding ID %j', (value) => {
    expect(parseFindingId(value)).toBeNull();
    expect(detailIdFromSearch('finding', `?id=${encodeURIComponent(value)}`, 1105)).toBeNull();
  });

  it('accepts only positive safe integer numbers and exact decimal strings', () => {
    expect(parseFindingId('1105')).toBe(1105);
    expect(parseFindingId(String(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
    for (const value of [NaN, Infinity, 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, undefined, null]) expect(parseFindingId(value)).toBeNull();
    expect(detailIdFromSearch('finding', '?id=%31%31%30%35')).toBe(1105);
  });

  it('rejects ambiguous queries instead of falling back to a legacy ID', () => {
    expect(detailIdFromSearch('finding', '?id=1105&id=1106', 1105)).toBeNull();
    expect(detailIdFromSearch('http-record', '?uuid=one&uuid=two', 'legacy')).toBeNull();
    expect(detailIdFromSearch('finding', '', 1105)).toBe(1105);
  });

  it('preserves record identity, including safe legacy opaque IDs and case', () => {
    expect(parseHttpRecordUUID('A3b2-47df_legacy')).toBe('A3b2-47df_legacy');
    expect(parseHttpRecordUUID('550E8400-e29b-41d4-a716-446655440000')).toBe('550E8400-e29b-41d4-a716-446655440000');
    expect(detailIdFromSearch('http-record', '?uuid=%41%33b2%2D47df_legacy')).toBe('A3b2-47df_legacy');
  });

  it.each(['', '.', '..', '../other', 'one/two', 'one\\two', ' uuid', 'uuid ', 'one?x=1', 'one#two', '%2F', '%252F', '\u0000', 'a'.repeat(129)])('rejects unsafe record identity %j', (value) => {
    expect(parseHttpRecordUUID(value)).toBeNull();
    expect(detailIdFromSearch('http-record', `?uuid=${encodeURIComponent(value)}`)).toBeNull();
  });

  it('accepts exactly one validated legacy segment, never an arbitrary first segment', () => {
    expect(parseLegacyDetailId('finding', ['1105'])).toBe(1105);
    expect(parseLegacyDetailId('http-record', ['record-A'])).toBe('record-A');
    for (const segments of [undefined, [], ['1105', 'extra'], '1105', ['NaN'], ['01']]) expect(parseLegacyDetailId('finding', segments)).toBeNull();
    expect(parseLegacyDetailId('http-record', ['record-A', 'extra'])).toBeNull();
    expect(legacyDetailIdFromPath('finding', '/findings/1105/')).toBe(1105);
    expect(legacyDetailIdFromPath('finding', '/findings/1105/extra/')).toBeNull();
    expect(legacyDetailIdFromPath('http-record', '/http-records/one%2Ftwo/')).toBeNull();
    expect(legacyDetailIdFromPath('http-record', '/http-records/%ZZ/')).toBeNull();
  });

  it('emits only exported list URLs and excludes tokens, while preserving the demo key', () => {
    window.history.replaceState({}, '', '/findings/1105/?token=secret&api_key=secret&demo_key=public%20demo%26key');
    expect(detailSelectionHref('finding', 1105)).toBe('/findings/?id=1105&demo_key=public+demo%26key');
    expect(detailSelectionHref('http-record', 'record-A')).toBe('/http-records/?uuid=record-A&demo_key=public+demo%26key');
    expect(detailSelectionHref('finding', null)).toBe('/findings/?demo_key=public+demo%26key');
    expect(detailSelectionHref('finding', NaN)).toBe('/findings/?demo_key=public+demo%26key');
  });
});
