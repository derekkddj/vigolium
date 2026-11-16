'use client';

import { useEffect, useRef, useState } from 'react';
import { useProjectContext } from '@/contexts/ProjectContext';
import {
  ARTIFACT_PREVIEW_BYTES, ArtifactError, artifactCurlTemplate, artifactSavePicker, downloadRunArtifact,
  loadArtifactPage, requiresStreamingDownload, type ArtifactPage, type RunArtifact, type RunArtifactScope,
} from '@/lib/runArtifacts';
import { evidencePalette, type EvidenceTheme } from './HttpMessage';

const UTF8_OVERLAP = 3;
const PAGE_STRIDE = ARTIFACT_PREVIEW_BYTES - UTF8_OVERLAP;
const runtimeArtifact: RunArtifact = { name: 'runtime.log', kind: 'log', size: null };
const failureText = (error: unknown) => error instanceof Error ? error.message : 'Runtime log request failed.';
const bytesText = (size: number | null) => size === null ? 'unknown' : size.toLocaleString();
const hasMoreBytes = (page: ArtifactPage) => page.returnedBytes > 0 && (page.totalSize !== null
  ? page.offset + page.returnedBytes < page.totalSize
  : page.truncated || page.returnedBytes === ARTIFACT_PREVIEW_BYTES);

/** Direct filename access: runtime.log is available even outside the 500-file inventory.
 * The keyed child prevents even one render of another project's/run's old page.
 */
export default function AgentRuntimeLogPanel({ runUUID, theme }: { runUUID: string; theme: EvidenceTheme }) {
  const { projectUUID } = useProjectContext();
  const colors = evidencePalette[theme];
  if (!projectUUID || !runUUID) return <section aria-label="Runtime log" className="border p-3 text-xs" style={{ borderColor: colors.border, color: colors.muted }}>
    <h3 className="font-semibold">runtime.log — full file, paged</h3>
    <p>Runtime log access disabled: {!projectUUID ? 'select an active project' : 'select a session or start a run'}.</p>
  </section>;
  return <RuntimeLogContent key={JSON.stringify([projectUUID, runUUID])} scope={{ projectUUID, runUUID }} theme={theme} />;
}

function RuntimeLogContent({ scope, theme }: { scope: RunArtifactScope; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const [request, setRequest] = useState({ offset: 0, latest: false, version: 0 });
  const [page, setPage] = useState<ArtifactPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copyState, setCopyState] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [downloadState, setDownloadState] = useState('');
  const [downloadError, setDownloadError] = useState('');
  const [pickerAvailable, setPickerAvailable] = useState(false);
  const lifetime = useRef<AbortController | null>(null);
  const pageController = useRef<AbortController | null>(null);
  const downloadController = useRef<AbortController | null>(null);
  const textRef = useRef<HTMLPreElement | null>(null);
  const { projectUUID, runUUID } = scope;

  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    setPickerAvailable(!!artifactSavePicker());
    return () => { controller.abort(); pageController.current?.abort(); downloadController.current?.abort(); };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    pageController.current = controller;
    const load = async () => {
      const capturedScope = { projectUUID, runUUID };
      let result = await loadArtifactPage(capturedScope, runtimeArtifact, request.latest ? 0 : request.offset, controller.signal, { overlapUTF8: true });
      if (request.latest) {
        if (result.totalSize === null) throw new ArtifactError('Latest page unavailable: server does not report the runtime.log total size. Next can still read supported byte offsets.');
        if (!result.offsetSupported && result.totalSize > result.returnedBytes) throw new ArtifactError('Server does not support runtime.log offsets. Upgrade the server to navigate the full log.');
        // Refresh size before jumping: a running log may have grown since the visible page.
        const lastOffset = Math.max(0, result.totalSize - ARTIFACT_PREVIEW_BYTES);
        if (lastOffset > 0) result = await loadArtifactPage(capturedScope, runtimeArtifact, lastOffset, controller.signal, { overlapUTF8: true });
      }
      if (result.offsetSupported && hasMoreBytes(result) && result.returnedBytes <= UTF8_OVERLAP) {
        throw new ArtifactError('Server returned too few bytes for safe overlapping UTF-8 paging. Reload or upgrade the server; no complete-log claim is made.');
      }
      if (controller.signal.aborted) return;
      setPage(result);
      setLoading(false);
      if (textRef.current) { textRef.current.scrollTop = 0; textRef.current.scrollLeft = 0; }
    };
    void load().catch((failure: unknown) => {
      if (!controller.signal.aborted) { setError(failureText(failure)); setLoading(false); }
    });
    return () => controller.abort();
  }, [projectUUID, runUUID, request]);

  const changePage = (offset: number, latest = false) => {
    pageController.current?.abort();
    downloadController.current?.abort();
    setPage(null);
    setError('');
    setCopyState('');
    setDownloadState('');
    setDownloadError('');
    setDownloading(false);
    setLoading(true);
    setRequest((previous) => ({ offset, latest, version: previous.version + 1 }));
  };
  const copyPage = async () => {
    const controller = pageController.current;
    if (!page || page.binary || !controller || controller.signal.aborted) return;
    try {
      await navigator.clipboard.writeText(page.text);
      if (!controller.signal.aborted) setCopyState('Visible page copied, not the full file.');
    } catch { if (!controller.signal.aborted) setCopyState('Copy failed; clipboard access is unavailable.'); }
  };
  const download = async () => {
    const mounted = lifetime.current;
    if (!mounted || mounted.signal.aborted || downloading) return;
    const controller = new AbortController();
    downloadController.current?.abort();
    downloadController.current = controller;
    setDownloading(true);
    setDownloadState('');
    setDownloadError('');
    try {
      const result = await downloadRunArtifact(scope, { ...runtimeArtifact, size: page?.totalSize ?? null }, controller.signal, artifactSavePicker());
      if (controller.signal.aborted || mounted.signal.aborted) return;
      if (result.blob) {
        const url = URL.createObjectURL(result.blob);
        try {
          const anchor = document.createElement('a');
          anchor.href = url; // Verified bounded Blob only, never an unauthenticated API link.
          anchor.download = 'runtime.log';
          anchor.click();
        } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
      }
      setDownloadState(`Complete response verified: ${bytesText(result.receivedBytes)} bytes. ${result.blob ? 'Browser download requested.' : 'Saved to file.'}${result.sizeChanged ? ' File size changed since the page was read.' : ''}`);
    } catch (failure: unknown) {
      if (!controller.signal.aborted && !mounted.signal.aborted) setDownloadError(failureText(failure));
    } finally {
      if (!controller.signal.aborted && !mounted.signal.aborted) setDownloading(false);
    }
  };

  const unsupportedDownload = !pickerAvailable && requiresStreamingDownload(page?.totalSize ?? null);
  const buttonStyle = { borderColor: colors.border, color: colors.accent };
  const buttonClass = 'border px-2 py-1 disabled:opacity-50';
  const offset = page?.offset ?? request.offset;
  const nextEnabled = page !== null && page.offsetSupported && hasMoreBytes(page);
  return <section aria-label="Runtime log" className="p-3 space-y-2 text-xs" style={{ background: colors.background, color: colors.text }}>
    <h3 className="font-semibold">runtime.log — full file, paged</h3>
    <p className="break-all" style={{ color: colors.muted }}>Run {runUUID} · active project {projectUUID}</p>
    <p style={{ color: colors.muted }}>Starts at byte 0. On servers with offset support, all stored bytes are navigable; commands, multiline results and long lines are not shortened or summarized. Older logs may already contain backend summaries: these are displayed as stored, not reconstructed.</p>
    <div className="flex flex-wrap gap-2 items-center" aria-label="Runtime log paging">
      <button className={buttonClass} style={buttonStyle} disabled={loading || offset === 0} onClick={() => changePage(0)}>First</button>
      <button className={buttonClass} style={buttonStyle} disabled={loading || offset === 0} onClick={() => changePage(Math.max(0, offset - PAGE_STRIDE))}>Prev</button>
      <button className={buttonClass} style={buttonStyle} disabled={loading || !nextEnabled} onClick={() => page && changePage(page.offset + page.returnedBytes - UTF8_OVERLAP)}>Next</button>
      <button className={buttonClass} style={buttonStyle} disabled={loading || !page || !page.offsetSupported || page.totalSize === null} onClick={() => changePage(0, true)}>Latest</button>
      <button className={buttonClass} style={buttonStyle} onClick={() => changePage(page?.offset ?? request.offset, request.latest && !page)}>Reload page</button>
      <button className={buttonClass} style={buttonStyle} disabled={loading || !page || page.binary} onClick={() => void copyPage()}>Copy visible page</button>
      <button className={buttonClass} style={buttonStyle} disabled={downloading || unsupportedDownload} onClick={() => void download()}>Download exact bytes</button>
    </div>
    <p style={{ color: colors.muted }}>At most 256 KiB per request, with 3 overlapping bytes between adjacent pages to preserve split UTF-8 characters (a few boundary characters may repeat). Lines/records may span pages; none are filtered. Download preserves the exact bytes. Reload reads the current page again; Latest refreshes the size before jumping. Active files can grow or change, so pages are not a frozen snapshot.</p>
    {loading && <p role="status">Loading runtime.log page…</p>}
    {error && <p role="alert" style={{ color: colors.warning }}>{error} No previous page or console snapshot is substituted; the active project has not been changed.</p>}
    {page && <>
      <p aria-label="Runtime log byte range" style={{ color: colors.muted }}>Bytes [{bytesText(page.offset)}, {bytesText(page.offset + page.returnedBytes)}) of {bytesText(page.totalSize)} · {bytesText(page.returnedBytes)} bytes returned (zero-based, end exclusive).</p>
      {page.utf8BoundaryBytes && (page.utf8BoundaryBytes.leading > 0 || page.utf8BoundaryBytes.trailing > 0) && <p aria-label="Runtime log text alignment" style={{ color: colors.muted }}>Text aligned at the UTF-8 page boundary: {page.utf8BoundaryBytes.leading} leading and {page.utf8BoundaryBytes.trailing} trailing bytes are displayed on adjacent overlapping pages instead. The byte range above describes the unmodified response; exact-byte download does not omit these bytes.</p>}
      {!page.offsetSupported && <p role="status" style={{ color: colors.warning }}>Server does not expose offset metadata; only this head page is available. Upgrade the server for full-log paging. This is not the complete file unless its reported size matches the returned bytes.</p>}
      {page.binary && <p role="status" style={{ color: colors.warning }}>Invalid UTF-8 or binary/control bytes. This text view may contain replacement characters; copy is disabled. Use exact-byte download to preserve binary data.</p>}
      {page.returnedBytes === 0 ? <p style={{ color: colors.muted }}>{page.totalSize === 0 ? 'Empty runtime.log file.' : 'No bytes returned at this offset; the file may have changed. Use First or reload.'}</p>
        : <pre ref={textRef} aria-label="Runtime log text" tabIndex={0} className="border p-2 font-mono whitespace-pre overflow-auto max-h-[32rem]" style={{ borderColor: colors.border, background: colors.background }}>{page.text}</pre>}
    </>}
    {copyState && <p role="status">{copyState}</p>}
    {downloading && <div className="flex gap-2 items-center"><span role="status">Downloading and verifying the full runtime.log…</span><button className={buttonClass} style={buttonStyle} onClick={() => { downloadController.current?.abort(); setDownloading(false); setDownloadState('Download cancelled; no complete-file receipt was confirmed.'); }}>Cancel download</button></div>}
    {downloadState && <p role="status">{downloadState}</p>}
    {downloadError && <p role="alert" style={{ color: colors.warning }}>{downloadError}</p>}
    {unsupportedDownload && <p role="status" style={{ color: colors.warning }}>Streaming download unsupported in this browser. Files above 16 MiB require a file save picker; use the scoped curl template below. Paging remains available without loading the whole file into memory.</p>}
    <details className="border p-2" style={{ borderColor: colors.border }}>
      <summary className="cursor-pointer" style={{ color: colors.accent }}>Scoped curl download template (no embedded secrets)</summary>
      <p className="my-2" style={{ color: colors.muted }}>Set the active project UUID and token locally. Verify the saved byte count and response headers; a legacy server may return a capped head even with download=1.</p>
      <pre className="whitespace-pre overflow-x-auto">{artifactCurlTemplate(runUUID, 'runtime.log')}</pre>
    </details>
  </section>;
}
