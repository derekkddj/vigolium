'use client';

import { useEffect, useState } from 'react';
import { useProjectContext } from '@/contexts/ProjectContext';
import { listRunArtifacts, type RunArtifactList, type RunArtifactScope } from '@/lib/runArtifacts';
import { evidencePalette, type EvidenceTheme } from './HttpMessage';
import AgentArtifactWorkspace from './AgentArtifactWorkspace';
import { filterArtifacts } from '@/lib/artifactFilter';

const ARTIFACT_INLINE_ROWS = 12;

export interface AgentArtifactsPanelProps {
  runUUID: string; theme: EvidenceTheme;
  selectedArtifact?: string | null; onSelectArtifact?: (name: string | null) => void;
}
const errorText = (error: unknown) => error instanceof Error ? error.message : 'Artifact request failed.';
const formatSize = (size: number | null) => size === null ? 'size unknown' : `${size.toLocaleString()} bytes`;

/** Mountable in either theme; all selections, reads and downloads are scoped to this identity. */
export default function AgentArtifactsPanel({ runUUID, theme, selectedArtifact, onSelectArtifact }: AgentArtifactsPanelProps) {
  const { projectUUID } = useProjectContext();
  const colors = evidencePalette[theme];
  if (!projectUUID || !runUUID) return <section aria-label="Run artifacts" className="border p-3 text-xs" style={{ borderColor: colors.border, color: colors.muted }}>
    <h3 className="font-semibold">Run artifacts</h3>
    <p>Artifact access disabled: {!projectUUID ? 'select an active project' : 'select a run'}.</p>
  </section>;
  return <ArtifactsContent key={JSON.stringify([projectUUID, runUUID])} scope={{ projectUUID, runUUID }} theme={theme} selectedArtifact={selectedArtifact} onSelectArtifact={onSelectArtifact} />;
}

function ArtifactsContent({ scope, theme, selectedArtifact, onSelectArtifact }: Omit<AgentArtifactsPanelProps, 'runUUID'> & { scope: RunArtifactScope }) {
  const colors = evidencePalette[theme];
  const [listing, setListing] = useState<RunArtifactList | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reload, setReload] = useState(0);
  const [localSelection, setLocalSelection] = useState<string | null>(null);
  const selection = selectedArtifact === undefined ? localSelection : selectedArtifact;
  const setSelection = (name: string | null) => {
    if (selectedArtifact === undefined) setLocalSelection(name);
    onSelectArtifact?.(name);
  };
  const [expanded, setExpanded] = useState(false);
  const [filter, setFilter] = useState('');
  const { projectUUID, runUUID } = scope;

  useEffect(() => {
    const controller = new AbortController();
    void listRunArtifacts({ projectUUID, runUUID }, controller.signal).then((result) => {
      if (!controller.signal.aborted) { setListing(result); setLoading(false); }
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) { setError(errorText(failure)); setLoading(false); }
    });
    return () => controller.abort();
  }, [projectUUID, runUUID, reload]);

  const filtered = filterArtifacts(listing?.artifacts ?? [], filter);
  const visible = expanded ? filtered : filtered.slice(0, ARTIFACT_INLINE_ROWS);
  const selected = listing?.artifacts.find((artifact) => artifact.name === selection);
  const buttonStyle = { borderColor: colors.border, color: colors.accent };
  return <section aria-label="Run artifacts" className="border p-3 space-y-3 text-xs" style={{ borderColor: colors.border, background: colors.background, color: colors.text }}>
    <div className="flex flex-wrap gap-2 items-center">
      <h3 className="font-semibold">Run artifacts{listing ? ` (${listing.artifacts.length})` : ''}</h3>
      <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading} onClick={() => { setSelection(null); setListing(null); setError(''); setLoading(true); setReload((value) => value + 1); }}>Refresh artifacts</button>
    </div>
    <p style={{ color: colors.muted }}>Stored run files: inspect commands, tool results and other evidence beyond summaries. Files load only when selected. runtime.log is console output, not a guaranteed complete command/result transcript. Active files may change; prefer finished runs when archiving.</p>
    {loading && <p role="status">Loading artifact listing…</p>}
    {error && <p role="alert" style={{ color: colors.warning }}>{error} The active project has not been changed.</p>}
    {listing?.truncated && <p role="status" style={{ color: colors.warning }}>Artifact listing truncated at 500 files; this is not a complete inventory. Listing pagination is not available on this endpoint.</p>}
    {listing && selection && !selected && <p role="status" style={{ color: colors.warning }}>Artifact not found in this run.</p>}
    {listing && listing.artifacts.length === 0 && <p style={{ color: colors.muted }}>No artifact files stored for this run.</p>}
    {!!listing?.artifacts.length && <>
      {listing.artifacts.length > ARTIFACT_INLINE_ROWS && <label className="block">Filter artifact files<input type="search" className="block border p-2 w-full" style={{ borderColor: colors.border, background: colors.background }} value={filter} onChange={event => setFilter(event.target.value)} /></label>}
      <div className="border" style={{ borderColor: colors.border }}>
        <table className="w-full text-left" aria-label="Artifact files">
          <thead style={{ color: colors.muted }}><tr><th className="p-2">Filename</th><th className="p-2">Kind</th><th className="p-2">Size</th></tr></thead>
          <tbody>{visible.map((artifact) => <tr key={artifact.name}>
            <td className="p-2"><button className="underline text-left break-all" style={{ color: colors.accent, fontWeight: artifact.name === selection ? 'bold' : 'normal' }} aria-pressed={artifact.name === selection} onClick={() => setSelection(artifact.name)}>{artifact.name}</button></td>
            <td className="p-2">{artifact.kind}</td><td className="p-2 whitespace-nowrap">{formatSize(artifact.size)}</td>
          </tr>)}</tbody>
        </table>
      </div>
      {!filtered.length && <p role="status">No artifact files match this filter.</p>}
      {filtered.length > ARTIFACT_INLINE_ROWS && <button className="border px-2 py-1" style={buttonStyle} onClick={() => setExpanded(value => !value)}>{expanded ? 'Show fewer files' : `Show all ${filtered.length} files`}</button>}
      {!selected && <p style={{ color: colors.muted }}>Select one file to preview or download its exact bytes.</p>}
    </>}
    {selected && listing && <AgentArtifactWorkspace scope={scope} artifacts={listing.artifacts} truncated={listing.truncated} selected={selected.name} onSelect={setSelection} onClose={() => setSelection(null)} theme={theme} />}
  </section>;
}
