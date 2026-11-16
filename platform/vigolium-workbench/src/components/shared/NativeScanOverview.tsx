'use client';

import { useState } from 'react';
import type { Scan } from '@/api/types';
import { formatDate } from '@/lib/formatters';
import { nativeScanCoverage, nativeScanErrorCounts, nativeScanParentHref } from '@/lib/nativeScan';

export type NativeScanTheme = 'dark' | 'light';
export const nativeScanPalette = {
  dark: { border: '#2e2b26', background: '#141310', text: '#fce8c3', muted: '#918175', accent: '#7fd962', error: '#ef2f27', warning: '#f2c55c' },
  light: { border: '#bbc3c4', background: '#ede4d1', text: '#005661', muted: '#708e8e', accent: '#0078c8', error: '#e34e1c', warning: '#b8860b' },
};

export default function NativeScanOverview({ scan, theme }: { scan: Scan; theme: NativeScanTheme }) {
  const colors = nativeScanPalette[theme];
  const coverage = nativeScanCoverage(scan);
  const errors = nativeScanErrorCounts(scan);
  const parentHref = nativeScanParentHref(scan);
  const [copyState, setCopyState] = useState('');
  return <section aria-label="Native scan overview" className="px-3 py-2 text-xs space-y-2 break-words" style={{ color: colors.text }}>
    <div className="break-all">uuid: {scan.uuid}</div>
    {scan.project_uuid && <div className="break-all">project_uuid: {scan.project_uuid}</div>}
    <div className="flex flex-wrap gap-x-4 gap-y-1">
      <span>status: <strong className="uppercase">{scan.status}</strong></span>
      <span>name: {scan.name || '—'}</span>
      <span>mode: {scan.scan_mode || '—'}</span>
      <span>source: {scan.scan_source || '—'}</span>
      <span>findings: {scan.total_findings}</span>
      <span>processed: {scan.processed_count}</span>
    </div>
    <div className="break-all">target: {scan.target || 'Not recorded'}</div>
    <div>resolved scope origin: <strong>{scan.scope_origin_mode || 'Unknown (not recorded)'}</strong></div>
    {scan.profile && <div>profile: {scan.profile}</div>}
    {parentHref && <div className="break-all">parent agent session: <a className="underline" style={{ color: colors.accent }} href={parentHref}>{scan.agentic_scan_uuid}</a></div>}
    <div style={{ color: scan.completeness === 'partial' ? colors.warning : colors.text }}>
      <strong>Coverage: {coverage.label}</strong><p style={{ color: colors.muted }}>{coverage.explanation}</p>
    </div>
    {scan.stop_reason && <div>stop reason: {scan.stop_reason}</div>}
    {scan.error_message && <div style={{ color: colors.error }}>scan error: {scan.error_message}</div>}
    <div className="flex flex-wrap gap-x-4 gap-y-1" style={{ color: colors.muted }}>
      <span>phase errors: {scan.phase_outcomes ? errors.phaseErrors : 'Not recorded'}</span>
      <span>module errors: {scan.module_errors ? errors.moduleErrors : 'Not recorded'}</span>
      <span>extensions failed to load: {scan.extensions_failed ? errors.extensionsFailed : 'Not recorded'}</span>
    </div>
    {!!Object.keys(scan.module_errors ?? {}).length && <details><summary>Module error counts (not a module coverage inventory)</summary><ul>{Object.entries(scan.module_errors!).map(([module, count]) => <li key={module}>{module}: {count}</li>)}</ul></details>}
    {!!scan.extensions_failed?.length && <div>Failed extensions: {scan.extensions_failed.join(', ')}</div>}
    <div className="flex flex-wrap gap-x-4 gap-y-1" style={{ color: colors.muted }}>
      <span>started: {scan.started_at ? formatDate(scan.started_at) : '—'}</span>
      <span>finished: {scan.finished_at ? formatDate(scan.finished_at) : '—'}</span>
      <span>created: {scan.created_at ? formatDate(scan.created_at) : '—'}</span>
    </div>
    {(scan.current_phase || scan.heartbeat_at) && <div>current phase: {scan.current_phase || 'Not recorded'} · heartbeat: {scan.heartbeat_at ? formatDate(scan.heartbeat_at) : 'Not recorded'}</div>}
    <div>
      <strong>Recorded phase outcomes</strong>
      {!scan.phase_outcomes?.length ? <p style={{ color: colors.muted }}>No phase outcomes recorded; missing phases are not inferred as completed.</p> : <ul className="space-y-2 mt-1">
        {scan.phase_outcomes.map((phase, index) => <li key={`${phase.phase}-${index}`} className="border p-1.5" style={{ borderColor: colors.border }}>
          <strong>{phase.phase}: {phase.state}</strong> · errors: {phase.errors ?? 0} · unprocessed: {phase.unprocessed ?? 0} · {phase.duration_ms} ms
          {!!phase.reasons?.length && <div>reasons: {phase.reasons.join(', ')}</div>}
          {!!phase.limits?.length && <div>limits: {phase.limits.join(', ')}</div>}
          {phase.message && <div style={{ color: colors.warning }}>{phase.message}</div>}
          {phase.persistence && <div>persistence ({phase.persistence.writer}): accepted {phase.persistence.accepted}, committed {phase.persistence.committed}, failed {phase.persistence.failed ?? 0}, unknown {phase.persistence.unknown ?? 0}{phase.persistence.timed_out ? ', drain timed out' : ''}</div>}
          {phase.targets && <div>targets: requested {phase.targets.requested}, admitted {phase.targets.admitted}, reached {phase.targets.reachability_checked ? phase.targets.reached : 'Unknown (reachability check incomplete)'}</div>}
          {phase.counts && <div>{Object.entries(phase.counts).map(([key, value]) => `${key}: ${value}`).join(' · ')}</div>}
          {!!phase.budget_exhausted_hosts?.length && <div>host budgets exhausted: {phase.budget_exhausted_hosts.join(', ')}</div>}
        </li>)}
      </ul>}
    </div>
    {scan.plan != null && <details><summary>Resolved plan (stored JSON)</summary><pre className="whitespace-pre-wrap break-all max-h-64 overflow-auto">{JSON.stringify(scan.plan, null, 2)}</pre></details>}
    {scan.modules && <details><summary>Configured modules (not proof they all ran)</summary>
      <button className="underline my-1" style={{ color: colors.accent }} onClick={async () => {
        try { await navigator.clipboard.writeText(scan.modules!); setCopyState('Copied'); }
        catch { setCopyState('Copy failed'); }
      }}>Copy modules</button>{copyState && <span role="status" className="ml-2">{copyState}</span>}
      <textarea aria-label="Configured modules" readOnly rows={3} value={scan.modules} className="w-full border p-1.5 resize-none" style={{ background: colors.background, borderColor: colors.border }} />
    </details>}
  </section>;
}
