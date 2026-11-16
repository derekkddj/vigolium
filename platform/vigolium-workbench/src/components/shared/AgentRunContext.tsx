'use client';

import { useState } from 'react';
import type { AgentSessionDetail } from '@/api/types';
import { useProjectContext } from '@/contexts/ProjectContext';
import HttpMessage, { evidencePalette, type EvidenceTheme } from './HttpMessage';

export interface AgentRunContextProps { session: AgentSessionDetail; theme: EvidenceTheme }
const CHILD_PAGE_SIZE = 50;

/** Legacy/incomplete responses make missing counts distinct from known zero. */
export function formatAgentRunCount(value: unknown): string {
  if (typeof value !== 'number') return 'unknown';
  return Number.isFinite(value) && value >= 0 ? String(value) : 'unavailable';
}

const sessionLink = (uuid: string) => `/agentic-scan?session=${encodeURIComponent(uuid)}`;

/** Never expose signed query strings, URL credentials or executable schemes in metadata. */
function storedReference(value: string | undefined, urlOnly = false): string {
  if (!value) return 'Not stored / unavailable.';
  if (!urlOnly && !/^[a-z][a-z0-9+.-]*:/i.test(value) && !value.startsWith('//')) return value;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return 'Stored reference hidden (unsupported URL scheme).';
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return 'Stored reference hidden (invalid URL).';
  }
}

/** No API reads: this view uses the selected session and only links to direct agent children. */
export default function AgentRunContext({ session, theme }: AgentRunContextProps) {
  const { projectUUID } = useProjectContext();
  // Reset child paging and HttpMessage clipboard feedback on either identity change.
  return <RunContextContent key={JSON.stringify([projectUUID, session.uuid])} session={session} theme={theme} />;
}

function RunContextContent({ session, theme }: AgentRunContextProps) {
  const colors = evidencePalette[theme];
  const [childOffset, setChildOffset] = useState(0);
  const children = session.child_runs ?? [];
  // Clamp locally if a refreshed detail contains fewer children; never render recursively.
  const offset = Math.min(childOffset, Math.max(0, Math.ceil(children.length / CHILD_PAGE_SIZE) - 1) * CHILD_PAGE_SIZE);
  const visibleChildren = children.slice(offset, offset + CHILD_PAGE_SIZE);
  const end = offset + visibleChildren.length;
  const buttonStyle = { borderColor: colors.border, color: colors.accent };

  return <section aria-label="Agent run context" className="border p-3 space-y-3 text-xs" style={{ borderColor: colors.border, background: colors.background, color: colors.text }}>
    <h3 className="font-semibold">Agent run context</h3>
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 break-all">
      <dt style={{ color: colors.muted }}>Run UUID</dt><dd>{session.uuid}</dd>
      <dt style={{ color: colors.muted }}>Source path</dt><dd>{storedReference(session.source_path)}</dd>
      <dt style={{ color: colors.muted }}>Session directory</dt><dd>{storedReference(session.session_dir)}</dd>
      <dt style={{ color: colors.muted }}>Session ID</dt><dd>{session.session_id || 'Not stored / unavailable.'}</dd>
      <dt style={{ color: colors.muted }}>Storage reference</dt><dd>{storedReference(session.storage_url, true)}</dd>
      <dt style={{ color: colors.muted }}>Parent agent run</dt><dd>{session.parent_agentic_scan_uuid
        ? <a className="underline" style={{ color: colors.accent }} href={sessionLink(session.parent_agentic_scan_uuid)}>{session.parent_agentic_scan_uuid}</a>
        : 'Not reported / unavailable.'}</dd>
    </dl>
    <p style={{ color: colors.muted }}>Stored paths and IDs are references, not proof that files remain available. URL credentials, query strings and fragments are hidden; storage references are not external links.</p>
    <div className="flex flex-wrap gap-x-4 gap-y-1" aria-label="Stored run counts">
      <span>Findings: {formatAgentRunCount(session.finding_count)}</span>
      <span>Records: {formatAgentRunCount(session.record_count)}</span>
      <span>Saved: {formatAgentRunCount(session.saved_count)}</span>
    </div>
    <p style={{ color: colors.muted }}>Missing counts are unknown (legacy servers may omit zero); negative counts are unavailable. These are stored summaries, not a completeness verdict.</p>

    <section aria-label="Direct child agent runs" className="space-y-2">
      <h4 className="font-semibold">Direct child agent runs</h4>
      <p style={{ color: colors.muted }}>These are nested agent/audit runs, not native scan history. Only direct child metadata is shown; open a run to inspect it. This is not a full run graph.</p>
      {children.length === 0 ? <p style={{ color: colors.muted }}>No direct child agent runs reported. {session.child_runs == null ? 'Child metadata is absent / unavailable.' : 'The stored child list is empty.'}</p> : <>
        <p>Showing children {offset + 1}–{end} of {children.length} reported. At most {CHILD_PAGE_SIZE} are rendered at a time.</p>
        <div className="max-h-64 overflow-auto border" style={{ borderColor: colors.border }}>
          <table className="w-full text-left" aria-label="Child agent run metadata">
            <thead style={{ color: colors.muted }}><tr><th className="p-2">Run</th><th className="p-2">Mode / agent</th><th className="p-2">Status</th><th className="p-2">Findings</th><th className="p-2">Records</th><th className="p-2">Saved</th></tr></thead>
            <tbody>{visibleChildren.map((child, index) => <tr key={`${offset + index}:${child.uuid}`}>
              <td className="p-2 break-all">{child.uuid ? <a className="underline" style={{ color: colors.accent }} href={sessionLink(child.uuid)}>{child.uuid}</a> : 'Run ID unavailable'}</td>
              <td className="p-2">{child.mode || 'unknown'} / {child.agent_name || 'unknown'}</td>
              <td className="p-2">{child.status || 'unknown'}</td>
              <td className="p-2">{formatAgentRunCount(child.finding_count)}</td>
              <td className="p-2">{formatAgentRunCount(child.record_count)}</td>
              <td className="p-2">{formatAgentRunCount(child.saved_count)}</td>
            </tr>)}</tbody>
          </table>
        </div>
        {children.length > CHILD_PAGE_SIZE && <div className="flex gap-2">
          <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={offset === 0} onClick={() => setChildOffset(Math.max(0, offset - CHILD_PAGE_SIZE))}>Previous children</button>
          <button className="border px-2 py-1 disabled:opacity-50" style={buttonStyle} disabled={end >= children.length} onClick={() => setChildOffset(end)}>More children (next 50)</button>
        </div>}
      </>}
    </section>

    <p style={{ color: colors.muted }}>Stored input and result are independent evidence fields, not a console or command/result transcript. Previews are bounded; copy/download uses only the full text already fetched in this session detail.</p>
    <HttpMessage label="Stored input (input_raw)" value={session.input_raw} encoding="text" theme={theme} />
    <HttpMessage label="Stored result JSON (result_json)" value={session.result_json} encoding="text" theme={theme} />
  </section>;
}
