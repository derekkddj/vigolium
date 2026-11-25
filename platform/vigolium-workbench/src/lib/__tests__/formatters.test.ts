import { describe, expect, it } from 'vitest';
import { formatDuration } from '../formatters';

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
