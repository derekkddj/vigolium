import type { RunArtifact } from './runArtifacts';

/** Shared filename-only substring filter; never changes names used for API reads. */
export function filterArtifacts(artifacts: RunArtifact[], query: string): RunArtifact[] {
  const needle = query.trim().toLowerCase();
  return artifacts.filter(artifact => artifact.name.toLowerCase().includes(needle));
}
