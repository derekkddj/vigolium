'use client';

import { useEffect, useRef, useState } from 'react';
import { useProjectContext } from '@/contexts/ProjectContext';
import {
  ARTIFACT_PREVIEW_BYTES, artifactCurlTemplate, artifactSavePicker, downloadRunArtifact, listRunArtifacts,
  loadArtifactPage, requiresStreamingDownload, type ArtifactPage, type RunArtifact, type RunArtifactList, type RunArtifactScope,
} from '@/lib/runArtifacts';
import { evidencePalette, type EvidenceTheme } from './HttpMessage';

export interface AgentArtifactsPanelProps { runUUID: string; theme: 'dark' | 'light' }
const errorText = (error: unknown) => error instanceof Error ? error.message : 'Artifact request failed.';
const formatSize = (size: number | null) => size === null ? 'size unknown' : `${size.toLocaleString()} bytes`;

/** Mountable in either theme; all selections, reads and downloads are scoped to this identity. */
export default function AgentArtifactsPanel({ runUUID, theme }: AgentArtifactsPanelProps) {
  const { projectUUID } = useProjectContext();
  const colors = evidencePalette[theme];
  if (!projectUUID || !runUUID) return <section aria-label="Run artifacts" className="border p-3 text-xs" style={{ borderColor: colors.border, color: colors.muted }}>
    <h3 className="font-semibold">Run artifacts</h3>
    <p>Artifact access disabled: {!projectUUID ? 'select an active project' : 'select a run'}.</p>
  </section>;
  return <ArtifactsContent key={JSON.stringify([projectUUID, runUUID])} scope={{ projectUUID, runUUID }} theme={theme} />;
}

function ArtifactsContent({ scope, theme }: { scope: RunArtifactScope; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const [listing, setListing] = useState<RunArtifactList | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reload, setReload] = useState(0);
  const [selection, setSelection] = useState<string | null>(null);
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
    {listing && listing.artifacts.length === 0 && <p style={{ color: colors.muted }}>No artifact files stored for this run.</p>}
    {!!listing?.artifacts.length && <>
      <div className="max-h-64 overflow-auto border" style={{ borderColor: colors.border }}>
        <table className="w-full text-left" aria-label="Artifact files">
          <thead style={{ color: colors.muted }}><tr><th className="p-2">Filename</th><th className="p-2">Kind</th><th className="p-2">Size</th></tr></thead>
          <tbody>{listing.artifacts.map((artifact) => <tr key={artifact.name}>
            <td className="p-2"><button className="underline text-left break-all" style={{ color: colors.accent, fontWeight: artifact.name === selection ? 'bold' : 'normal' }} aria-pressed={artifact.name === selection} onClick={() => setSelection(artifact.name)}>{artifact.name}</button></td>
            <td className="p-2">{artifact.kind}</td><td className="p-2 whitespace-nowrap">{formatSize(artifact.size)}</td>
          </tr>)}</tbody>
        </table>
      </div>
      {!selected && <p style={{ color: colors.muted }}>Select one file to preview or download its exact bytes.</p>}
    </>}
    {selected && <ArtifactViewer key={selected.name} scope={scope} artifact={selected} theme={theme} />}
  </section>;
}

function ArtifactViewer({ scope, artifact, theme }: { scope: RunArtifactScope; artifact: RunArtifact; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const [offset, setOffset] = useState(0);
  const [reload, setReload] = useState(0);
  const [page, setPage] = useState<ArtifactPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [truncated, setTruncated] = useState(false);
  const [copyState, setCopyState] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [downloadState, setDownloadState] = useState('');
  const [downloadError, setDownloadError] = useState('');
  // The viewer mounts only after client-side listing/selection; no SSR capability mismatch.
  const [pickerAvailable] = useState(() => !!artifactSavePicker());
  const lifetime = useRef<AbortController | null>(null);
  const pageController = useRef<AbortController | null>(null);
  const downloadController = useRef<AbortController | null>(null);
  const { projectUUID, runUUID } = scope;
  const { name, size, kind } = artifact;

  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    return () => { controller.abort(); downloadController.current?.abort(); };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    pageController.current = controller;
    void loadArtifactPage({ projectUUID, runUUID }, { name, size, kind }, offset, controller.signal).then((result) => {
      if (controller.signal.aborted) return;
      setPage(result);
      setTruncated((previous) => previous || result.truncated);
      setLoading(false);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) { setError(errorText(failure)); setLoading(false); }
    });
    return () => controller.abort();
  }, [projectUUID, runUUID, name, size, kind, offset, reload]);

  const changePage = (nextOffset: number) => {
    // Invalidate pending reads, downloads and clipboard callbacks before rendering a new page.
    pageController.current?.abort();
    downloadController.current?.abort();
    setDownloading(false);
    setDownloadState('');
    setDownloadError('');
    setCopyState('');
    setPage(null);
    setError('');
    setLoading(true);
    setOffset(nextOffset);
    setReload((value) => value + 1);
  };
  const copyPage = async () => {
    const controller = pageController.current;
    if (!page || page.binary || !controller || controller.signal.aborted) return;
    try {
      await navigator.clipboard.writeText(page.text);
      if (!controller.signal.aborted) setCopyState('Visible page copied (not the full file).');
    } catch { if (!controller.signal.aborted) setCopyState('Copy failed; clipboard access is unavailable.'); }
  };
  const download = async () => {
    if (!lifetime.current || lifetime.current.signal.aborted || downloading) return;
    const controller = new AbortController();
    downloadController.current?.abort();
    downloadController.current = controller;
    setDownloading(true);
    setDownloadState('');
    setDownloadError('');
    try {
      const result = await downloadRunArtifact(scope, artifact, controller.signal, artifactSavePicker());
      if (controller.signal.aborted || lifetime.current.signal.aborted) return;
      if (result.blob) {
        const url = URL.createObjectURL(result.blob);
        try {
          const anchor = document.createElement('a');
          anchor.href = url; // Only a verified, bounded Blob URL; never an unauthenticated API link.
          anchor.download = name.split('/').at(-1)!;
          anchor.click();
        } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
      }
      setDownloadState(`Complete response verified: ${formatSize(result.receivedBytes)}. ${result.blob ? 'Browser download requested.' : 'Saved to file.'}${result.sizeChanged ? ' File size changed since listing.' : ''}`);
    } catch (failure: unknown) {
      if (!controller.signal.aborted && !lifetime.current.signal.aborted) setDownloadError(errorText(failure));
    } finally {
      if (!controller.signal.aborted && !lifetime.current.signal.aborted) setDownloading(false);
    }
  };

  const unsupported = !pickerAvailable && requiresStreamingDownload(page?.totalSize ?? size);
  const buttonStyle = { borderColor: colors.border, color: colors.accent };
  const hasLater = !!page?.offsetSupported && page.totalSize !== null && page.returnedBytes > 0 && page.offset + page.returnedBytes < page.totalSize;
  return <section aria-label="Selected artifact" className="space-y-2">
    <h4 className="font-semibold break-all">{name}</h4>
    <div className="flex flex-wrap gap-2 items-center">
      <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || !page || page.binary} onClick={() => void copyPage()}>Copy visible page</button>
      <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={downloading || unsupported} onClick={() => void download()}>Download exact bytes</button>
      {downloading && <><span role="status">Downloading and verifying full response…</span><button style={buttonStyle} onClick={() => { downloadController.current?.abort(); setDownloading(false); setDownloadState('Download cancelled; completeness was not confirmed.'); }}>Cancel download</button></>}
      <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || downloading} onClick={() => changePage(offset)}>Reload page</button>
    </div>
    {unsupported && <p role="status" style={{ color: colors.warning }}>Streaming download unsupported in this browser. Files above 16 MiB require File System Access (a file save picker). Use the scoped curl template below; no unbounded in-memory download is attempted.</p>}
    {copyState && <p role="status">{copyState}</p>}
    {downloadState && <p role="status">{downloadState}</p>}
    {downloadError && <p role="alert" style={{ color: colors.warning }}>{downloadError}</p>}
    <p style={{ color: colors.muted }}>Preview is bounded to 256 KiB per page. Byte offsets may split UTF-8 characters, lines or JSON records; a page is not a parsed/full transcript. Downloads preserve bytes without text decoding and verify the received size before saving.</p>
    {truncated && <p role="status" style={{ color: colors.warning }}>Partial preview — bytes have been omitted from this view (sticky for this file). This is not a full archive, even on the last page.</p>}
    {loading && <p role="status">Loading artifact page…</p>}
    {error && <p role="alert" style={{ color: colors.warning }}>{error}</p>}
    {page && <>
      <div style={{ color: colors.muted }}>Byte offset {page.offset.toLocaleString()}; returned {formatSize(page.returnedBytes)}; total {formatSize(page.totalSize)}.</div>
      {page.binary && <p role="status" style={{ color: colors.warning }}>Invalid UTF-8 or binary/control bytes. Rendered text is a potentially lossy view (including split UTF-8 boundaries); text copy is disabled. Exact-byte download does not conceal or replace these bytes.</p>}
      {!page.offsetSupported && <p style={{ color: colors.warning }}>Server does not expose offset metadata; paging is unavailable. Upgrade the server for byte-page previews. Completeness cannot be inferred from the visible head.</p>}
      {page.returnedBytes === 0 ? <p style={{ color: colors.muted }}>{page.totalSize === 0 ? 'Empty artifact file.' : 'No bytes returned at this offset.'}</p>
        : <pre className="border p-2 overflow-x-auto whitespace-pre-wrap break-all max-h-96 overflow-y-auto" style={{ borderColor: colors.border, background: colors.background }}>{page.text}</pre>}
    </>}
    <div className="flex gap-2">
      <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || downloading || offset === 0} onClick={() => changePage(Math.max(0, offset - ARTIFACT_PREVIEW_BYTES))}>Earlier bytes</button>
      <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || downloading || !hasLater} onClick={() => page && changePage(page.offset + page.returnedBytes)}>Later bytes</button>
    </div>
    <details className="border p-2" style={{ borderColor: colors.border }}>
      <summary className="cursor-pointer" style={{ color: colors.accent }}>Scoped curl download template (local environment variables, no embedded secrets)</summary>
      <p className="my-2" style={{ color: colors.muted }}>Set VIGOLIUM_PROJECT_UUID to the active project and VIGOLIUM_TOKEN locally. Inspect saved response headers and compare the output byte count to the reported total. A legacy server may ignore download=1 and still truncate; curl alone does not prove completeness.</p>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all">{artifactCurlTemplate(runUUID, name)}</pre>
    </details>
  </section>;
}
