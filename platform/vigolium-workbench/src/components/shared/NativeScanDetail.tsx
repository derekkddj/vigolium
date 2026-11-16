'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { useScan, useScanLogs } from '@/api/hooks';
import { useProjectContext } from '@/contexts/ProjectContext';
import { getProjectUUID } from '@/api/client';
import { isNativeScanActive, NATIVE_SCAN_LOG_PAGE_SIZE } from '@/lib/nativeScan';
import { useFollowTail } from '@/lib/useFollowTail';
import NativeScanOverview, { nativeScanPalette, type NativeScanTheme } from './NativeScanOverview';

/** Keep this tiny URL observer inside Suspense; static-export pages need no route redesign. */
export function NativeScanURLSync({ onChange }: { onChange: () => void }) {
  const params = useSearchParams();
  const query = params?.toString();
  useEffect(() => {
    // Read the hydrated browser URL, not a transient empty prerender snapshot.
    onChange();
  }, [query, onChange]);
  return null;
}

interface Props { uuid: string; theme: NativeScanTheme; onClose: () => void }

export default function NativeScanDetail(props: Props) {
  const { projectUUID } = useProjectContext();
  const project = getProjectUUID() ?? projectUUID;
  return <DetailContent key={JSON.stringify([project, props.uuid])} {...props} />;
}

function DetailContent({ uuid, theme, onClose }: Props) {
  const colors = nativeScanPalette[theme];
  const detail = useScan(uuid);
  const [offset, setOffset] = useState(0);
  const logQuery = useScanLogs(uuid, { limit: NATIVE_SCAN_LOG_PAGE_SIZE, offset }, isNativeScanActive(detail.data?.status));
  const data = logQuery.data;
  const logs = data?.logs ?? [];
  const textMode = data?.text !== undefined;
  const shownOffset = data?.offset ?? offset;
  const hasNext = data?.has_more ?? (data?.total !== undefined ? shownOffset + logs.length < data.total : logs.length === NATIVE_SCAN_LOG_PAGE_SIZE);
  const { ref: logRef, onScroll } = useFollowTail<HTMLDivElement>(data?.text ?? data, `${uuid}:${offset}`);
  const buttonStyle = { color: colors.accent, borderColor: colors.border };

  return <aside aria-label="Native scan details" className="border-l flex flex-col h-[640px] max-h-[85vh] min-h-0 text-xs" style={{ borderColor: colors.border, color: colors.text }}>
    <header className="px-3 py-1.5 border-b flex items-center justify-between shrink-0" style={{ borderColor: colors.border }}>
      <strong style={{ color: colors.accent }}>SCAN DETAILS</strong>
      <button onClick={onClose} style={{ color: colors.muted }}>[close]</button>
    </header>
    <div className="border-b shrink-0 max-h-[360px] overflow-y-auto" style={{ borderColor: colors.border }}>
      {!detail.data && <div className="p-3 break-all">uuid: {uuid}</div>}
      {detail.isLoading && <p className="px-3 pb-2" role="status">Loading scan details…</p>}
      {detail.isError && <div className="px-3 py-2" role="alert" style={{ color: colors.error }}>
        Scan details unavailable in the active project: {detail.error.message}
        <button className="underline ml-2" style={buttonStyle} onClick={() => void detail.refetch()}>Retry details</button>
        {detail.data && <p>Showing last fetched scan details; refresh failed.</p>}
      </div>}
      {detail.data && <NativeScanOverview scan={detail.data} theme={theme} />}
      <div className="px-3 pb-2 flex gap-2 items-center">
        <button className="underline" style={buttonStyle} disabled={detail.isFetching} onClick={() => void detail.refetch()}>Refresh details</button>
        {detail.isFetching && !detail.isLoading && <span role="status" style={{ color: colors.muted }}>Refreshing details…</span>}
      </div>
    </div>
    <div className="px-3 py-1.5 border-b shrink-0 space-y-1" style={{ borderColor: colors.border }}>
      <strong style={{ color: colors.accent }}>LOGS</strong>
      {data && (textMode ? <div style={{ color: colors.muted }}>
        Latest 256 KiB runtime.log tail — not a full archive.
        {data.log_size !== undefined && <span> File size: {data.log_size.toLocaleString()} bytes.</span>}
        {data.truncated === true ? <span> Earlier bytes omitted.</span> : data.truncated === false ? <span> Server reports no tail truncation at fetch time.</span> : <span> Truncation headers unavailable; completeness unknown.</span>}
      </div> : <div style={{ color: colors.muted }}>
        Showing {logs.length} / {data.total ?? 'unknown total'} entries{logs.length > 0 ? ` (rows ${shownOffset + 1}–${shownOffset + logs.length})` : ''}{data.source ? ` · ${data.source}` : ' · structured DB logs'}
      </div>)}
      {!textMode && data && <div className="flex gap-3 items-center">
        <button className="underline disabled:opacity-40" style={buttonStyle} disabled={offset === 0 || logQuery.isFetching} onClick={() => setOffset(Math.max(0, offset - NATIVE_SCAN_LOG_PAGE_SIZE))}>Previous logs</button>
        <span>Page {Math.floor(shownOffset / NATIVE_SCAN_LOG_PAGE_SIZE) + 1} · {NATIVE_SCAN_LOG_PAGE_SIZE} per page</span>
        <button className="underline disabled:opacity-40" style={buttonStyle} disabled={!hasNext || logQuery.isFetching} onClick={() => setOffset(offset + NATIVE_SCAN_LOG_PAGE_SIZE)}>Next logs</button>
      </div>}
    </div>
    {logQuery.isLoading && <p className="px-3 py-2 shrink-0" role="status">Loading scan logs…</p>}
    {logQuery.isError && <div className="px-3 py-2 shrink-0" role="alert" style={{ color: colors.error }}>
      Scan logs unavailable: {logQuery.error.message}
      <button className="underline ml-2" style={buttonStyle} onClick={() => void logQuery.refetch()}>Retry logs</button>
      {data && <p>Showing last fetched logs; refresh failed.</p>}
    </div>}
    {logQuery.isFetching && !logQuery.isLoading && <p className="px-3 py-1 shrink-0" style={{ color: colors.muted }}>Refreshing logs…</p>}
    <div ref={logRef} onScroll={onScroll} className="overflow-y-auto font-mono text-[11px] leading-relaxed flex-1 min-h-0" style={{ background: colors.background }}>
      {data && (textMode ? data.text ? <pre className="px-3 py-2 whitespace-pre-wrap break-all">{data.text}</pre> : <p className="p-3" style={{ color: colors.muted }}>The fetched runtime.log tail is empty.</p> : logs.length === 0 ? <p className="p-3" style={{ color: colors.muted }}>No structured logs on this page.</p> : logs.map((log, index) => <div key={`${log.id}-${index}`} className="px-3 py-0.5 flex flex-wrap gap-2">
        <span style={{ color: colors.muted }}>{new Date(log.created_at).toLocaleTimeString()}</span>
        <strong className="uppercase" style={{ color: log.level === 'error' ? colors.error : log.level === 'warn' ? colors.warning : colors.muted }}>{log.level}</strong>
        {log.phase && <span style={{ color: colors.accent }}>[{log.phase}]</span>}
        <span className="whitespace-pre-wrap break-all">{log.message}</span>
        {log.metadata && <span className="whitespace-pre-wrap break-all" style={{ color: colors.muted }}>{log.metadata}</span>}
      </div>))}
    </div>
  </aside>;
}
