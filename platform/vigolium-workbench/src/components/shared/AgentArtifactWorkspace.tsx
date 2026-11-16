'use client';

import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';
import {
  ARTIFACT_PREVIEW_BYTES, artifactCurlTemplate, artifactSavePicker, downloadRunArtifact, loadArtifactPage,
  requiresStreamingDownload, type ArtifactPage, type RunArtifact, type RunArtifactScope,
} from '@/lib/runArtifacts';
import { evidencePalette, type EvidenceTheme } from './HttpMessage';

interface AgentArtifactWorkspaceProps {
  scope: RunArtifactScope; theme: EvidenceTheme; artifacts: RunArtifact[]; truncated: boolean;
  selected: string; onSelect: (name: string) => void; onClose: () => void;
}
const errorText = (error: unknown) => error instanceof Error ? error.message : 'Artifact request failed.';
const formatSize = (size: number | null) => size === null ? 'size unknown' : `${size.toLocaleString()} bytes`;

/** Portal keeps the two sibling scroll owners outside every page-level scroller. */
export default function AgentArtifactWorkspace({ scope, theme, artifacts, truncated, selected, onSelect, onClose }: AgentArtifactWorkspaceProps) {
  const colors = evidencePalette[theme];
  const closeButton = useRef<HTMLButtonElement>(null);
  const [filter, setFilter] = useState('');
  const artifact = artifacts.find(item => item.name === selected);

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    closeButton.current?.focus();
    return () => {
      document.body.style.overflow = previous;
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  const keyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onClose(); }
    if (event.key !== 'Tab') return;
    const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), input, summary, [tabindex="0"]'))
      .filter(el => !el.closest('details:not([open])') || el.tagName === 'SUMMARY');
    const first = focusable[0]; const last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  };

  return createPortal(<div role="dialog" aria-label="Run artifacts workspace" aria-modal="true" onKeyDown={keyDown}
    className="fixed inset-0 z-50 flex flex-col text-xs" style={{ background: colors.background, color: colors.text }}>
    <header className="shrink-0 border-b p-3 flex items-center gap-3" style={{ borderColor: colors.border }}>
      <div className="min-w-0 flex-1"><p style={{ color: colors.muted }}>Run {scope.runUUID}</p><h3 className="font-semibold break-all">{selected}</h3></div>
      <button ref={closeButton} className="border px-3 py-2" style={{ borderColor: colors.border, color: colors.accent }} aria-label="Close artifacts workspace" onClick={onClose}>Close</button>
    </header>
    <div className="flex-1 min-h-0 grid grid-cols-[minmax(220px,320px)_minmax(0,1fr)]">
      <nav aria-label="Workspace artifact files" className="min-h-0 overflow-y-auto border-r p-3 space-y-2" style={{ borderColor: colors.border }}>
        <label className="block">Filter workspace artifact files<input type="search" className="block border p-2 w-full" style={{ borderColor: colors.border, background: colors.background }} value={filter} onChange={event => setFilter(event.target.value)} /></label>
        {truncated && <p role="status" style={{ color: colors.warning }}>Artifact listing truncated at 500 files; this is not a complete inventory. Listing pagination is not available on this endpoint.</p>}
        <ul className="space-y-1">{artifacts.filter(item => item.name.toLowerCase().includes(filter.toLowerCase())).map(item => <li key={item.name}>
          <button className="w-full text-left break-all border p-2" style={{ borderColor: colors.border, color: colors.accent, fontWeight: item.name === selected ? 'bold' : 'normal' }} aria-pressed={item.name === selected} onClick={() => onSelect(item.name)}>{item.name}</button>
        </li>)}</ul>
      </nav>
      {artifact && <ArtifactViewer key={artifact.name} scope={scope} artifact={artifact} theme={theme} />}
    </div>
  </div>, document.body);
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
    pageController.current?.abort();
    downloadController.current?.abort();
    setDownloading(false); setDownloadState(''); setDownloadError(''); setCopyState('');
    setPage(null); setError(''); setLoading(true);
    setOffset(nextOffset); setReload((value) => value + 1);
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
    downloadController.current?.abort(); downloadController.current = controller;
    setDownloading(true); setDownloadState(''); setDownloadError('');
    try {
      const result = await downloadRunArtifact(scope, artifact, controller.signal, artifactSavePicker());
      if (controller.signal.aborted || lifetime.current.signal.aborted) return;
      if (result.blob) {
        const url = URL.createObjectURL(result.blob);
        try {
          const anchor = document.createElement('a');
          anchor.href = url; // Only a verified, bounded Blob URL; never an unauthenticated API link.
          anchor.download = name.split('/').at(-1)!; anchor.click();
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
  return <section aria-label="Selected artifact" className="min-h-0 min-w-0 flex flex-col">
    <div className="shrink-0 p-3 space-y-2 border-b" style={{ borderColor: colors.border }}>
      <div className="flex flex-wrap gap-2 items-center">
        <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || !page || page.binary} onClick={() => void copyPage()}>Copy visible page</button>
        <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={downloading || unsupported} onClick={() => void download()}>Download exact bytes</button>
        {downloading && <><span role="status">Downloading and verifying full response…</span><button style={buttonStyle} onClick={() => { downloadController.current?.abort(); setDownloading(false); setDownloadState('Download cancelled; completeness was not confirmed.'); }}>Cancel download</button></>}
        <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || downloading} onClick={() => changePage(offset)}>Reload page</button>
        <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || downloading || offset === 0} onClick={() => changePage(Math.max(0, offset - ARTIFACT_PREVIEW_BYTES))}>Earlier bytes</button>
        <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={loading || downloading || !hasLater} onClick={() => page && changePage(page.offset + page.returnedBytes)}>Later bytes</button>
      </div>
      {unsupported && <p role="status" style={{ color: colors.warning }}>Streaming download unsupported in this browser. Files above 16 MiB require File System Access (a file save picker). Use the scoped curl template below; no unbounded in-memory download is attempted.</p>}
      {copyState && <p role="status">{copyState}</p>}
      {downloadState && <p role="status">{downloadState}</p>}
      {downloadError && <p role="alert" style={{ color: colors.warning }}>{downloadError}</p>}
      {truncated && <p role="status" style={{ color: colors.warning }}>Partial preview — bytes have been omitted from this view (sticky for this file). This is not a full archive, even on the last page.</p>}
      {loading && <p role="status">Loading artifact page…</p>}
      {error && <p role="alert" style={{ color: colors.warning }}>{error}</p>}
      {page && <>
        <div style={{ color: colors.muted }}>Byte offset {page.offset.toLocaleString()}; returned {formatSize(page.returnedBytes)}; total {formatSize(page.totalSize)}.</div>
        {page.binary && <p role="status" style={{ color: colors.warning }}>Invalid UTF-8 or binary/control bytes. Rendered text is a potentially lossy view (including split UTF-8 boundaries); text copy is disabled. Exact-byte download does not conceal or replace these bytes.</p>}
        {!page.offsetSupported && <p style={{ color: colors.warning }}>Server does not expose offset metadata; paging is unavailable. Upgrade the server for byte-page previews. Completeness cannot be inferred from the visible head.</p>}
        {page.returnedBytes === 0 && <p style={{ color: colors.muted }}>{page.totalSize === 0 ? 'Empty artifact file.' : 'No bytes returned at this offset.'}</p>}
      </>}
      <details className="border p-2" style={{ borderColor: colors.border }}>
        <summary className="cursor-pointer" style={{ color: colors.accent }}>Preview limits and download notes</summary>
        <p className="my-2" style={{ color: colors.muted }}>Preview is bounded to 256 KiB per page. Byte offsets may split UTF-8 characters, lines or JSON records; a page is not a parsed/full transcript. Downloads preserve bytes without text decoding and verify the received size before saving.</p>
        <p className="my-2" style={{ color: colors.muted }}>Scoped curl download template (local environment variables, no embedded secrets). Set VIGOLIUM_PROJECT_UUID to the active project and VIGOLIUM_TOKEN locally. Inspect saved response headers and compare the output byte count to the reported total. A legacy server may ignore download=1 and still truncate; curl alone does not prove completeness.</p>
        <pre className="whitespace-pre-wrap break-all">{artifactCurlTemplate(runUUID, name)}</pre>
      </details>
    </div>
    {page && page.returnedBytes > 0 && <pre aria-label="Artifact content" tabIndex={0} className="flex-1 min-h-0 overflow-auto overscroll-contain whitespace-pre-wrap break-all p-3" style={{ background: colors.background }}>{page.text}</pre>}
  </section>;
}
