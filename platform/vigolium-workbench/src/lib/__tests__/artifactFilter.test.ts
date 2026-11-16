import { describe, expect, it } from 'vitest';
import { filterArtifacts } from '../artifactFilter';

const artifacts = ['auth-config.yaml', 'commands/RESULTS.jsonl', 'runtime.log'].map(name => ({ name, kind: 'text', size: 4 }));
describe('artifact filename filter', () => {
  it('matches case-insensitive substrings across the whole listing without changing names', () => {
    expect(filterArtifacts(artifacts, '  results.JSON  ')).toEqual([artifacts[1]]);
    expect(filterArtifacts(artifacts, '')).toEqual(artifacts);
    expect(filterArtifacts(artifacts, '  ')).toEqual(artifacts);
    expect(filterArtifacts(artifacts, 'missing')).toEqual([]);
    expect(artifacts[1].name).toBe('commands/RESULTS.jsonl');
  });
});
