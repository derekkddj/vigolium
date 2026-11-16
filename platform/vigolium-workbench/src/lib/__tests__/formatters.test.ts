import { describe, expect, it } from 'vitest';
import { formatDate, formatDuration } from '../formatters';

describe('formatDate', () => {
  it.each([null, undefined, '', 'not a timestamp'])('keeps missing or invalid timestamp %s unknown', (value) => {
    expect(formatDate(value as string)).toBe('—');
  });

  it('keeps the Go zero-time sentinel unknown instead of rendering a misleading Dec 31 date', () => {
    expect(formatDate('0001-01-01T00:00:00Z')).toBe('—');
  });

  it('preserves formatting for a valid timestamp', () => {
    const timestamp = '2026-11-10T12:34:00Z';
    expect(formatDate(timestamp)).toBe(new Date(timestamp).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    }));
  });
});

describe('formatDuration', () => {
  it.each([undefined, null])('keeps missing duration %s unknown', (value) => {
    expect(formatDuration(value as unknown as number)).toBe('unknown');
  });

  it.each([NaN, Infinity, -Infinity, -1, '33', {}, true])('rejects an invalid duration %s without NaN output', (value) => {
    expect(formatDuration(value as number)).toBe('unavailable');
  });

  it.each([
    [0, '0ms'], [33, '33ms'], [999, '999ms'], [1000, '1.0s'],
    [59999, '60.0s'], [60000, '1m 0s'], [123000, '2m 3s'],
  ])('preserves measured duration %s', (value, expected) => {
    expect(formatDuration(value as number)).toBe(expected);
  });
});
