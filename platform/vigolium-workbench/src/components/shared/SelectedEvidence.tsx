'use client';

import { useEffect, useState } from 'react';
import type { EvidenceEntry, EvidenceExchange, Finding } from '@/api/types';
import { ambiguousPrimaryOccurrences, evidenceLoadMessage, hasExchangeIdentity, primaryEvidence, primaryEvidenceDeclarations } from '@/lib/findingEvidence';
import { fetchSelectedEvidence } from '@/lib/selectedEvidenceApi';
import HttpMessage, { evidencePalette, type EvidenceTheme } from './HttpMessage';

/** Roles and primary flags describe declarations, not confirmation; hydrate one exact selection. */
export default function SelectedEvidence({ finding, theme }: { finding: Finding; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const entries = finding.evidence ?? [];
  const declarations = primaryEvidenceDeclarations(entries);
  const primaries = primaryEvidence(entries);
  const invalidPrimaries = entries.filter((entry) => entry.primary && !hasExchangeIdentity(entry));
  const ambiguous = ambiguousPrimaryOccurrences(entries);
  // A malformed competing declaration must not silently choose the remaining valid exchange.
  const [selectedKey, setSelectedKey] = useState<string | undefined>(() => declarations.length === 1 && primaries.length === 1 ? associationKey(primaries[0]) : undefined);
  const selected = entries.find((entry) => hasExchangeIdentity(entry) && associationKey(entry) === selectedKey);
  const groups = [
    { title: 'Explicit primary selections', entries: primaries },
    { title: 'Invalid / unavailable primary declarations', entries: invalidPrimaries },
    { title: 'Baseline context (not proof)', entries: entries.filter((entry) => entry.role === 'baseline' && !invalidPrimaries.includes(entry)) },
    { title: 'Supporting / unclassified exchanges', entries: entries.filter((entry) => !primaries.includes(entry) && !invalidPrimaries.includes(entry) && entry.role !== 'baseline') },
  ];
  return <section className="space-y-2" aria-label="Selected evidence">
    <h3 className="font-semibold">Selected evidence</h3>
    <p>Stored finding evidence status: {finding.evidence_status || (entries.length ? 'unclassified' : 'missing / unclassified')}</p>
    <p style={{ color: colors.muted }}>Stored status is original finding metadata. Each occurrence keeps its own role and primary flag; later selected evidence does not reclassify historical or legacy evidence.</p>
    <p style={{ color: colors.muted }}>Roles and primary flags are stored declarations, not vulnerability confirmation. Producer labels do not override them. Receipt availability and capture provenance are separate from role.</p>
    {!primaries.length && <p style={{ color: colors.warning }}>No inspectable explicit primary selection. Baseline and unknown legacy data do not establish proof.</p>}
    {ambiguous.length > 0 && <p role="alert" style={{ color: colors.warning }}>Ambiguous primary declarations within one occurrence: {ambiguous.join(', ')}. Inspecting bytes does not resolve the ambiguity or select a proof.</p>}
    {declarations.length > 1 && <p style={{ color: colors.muted }}>Multiple primary declarations; select an available exact exchange to inspect. Ordering does not choose a proof. Separate occurrence IDs retain their own selections.</p>}
    {groups.map((group) => group.entries.length > 0 && <div key={group.title} className="space-y-1">
      <h4 style={{ color: colors.muted }}>{group.title}</h4>
      {group.entries.map((entry, index) => <div key={`${entry.exchange_id}:${entry.occurrence_id}:${index}`}>
        <button className="underline break-all text-left" style={{ color: colors.accent }} disabled={!hasExchangeIdentity(entry)} aria-pressed={selectedKey === associationKey(entry)} onClick={() => setSelectedKey(associationKey(entry))}>
          role: {entry.role || 'unknown'} · primary declaration: {entry.primary ? 'yes' : 'no'} — exchange: {hasExchangeIdentity(entry) ? entry.exchange_id : 'Missing exchange identity'}
        </button>
        {entry.label && <div className="break-all">Producer label: {entry.label}</div>}
        {!hasExchangeIdentity(entry) && <p style={{ color: colors.warning }}>Exchange identity missing or empty; unavailable for inspection. No URL or linked-record fallback is attempted.</p>}
        {entry.occurrence_id && <div className="break-all">occurrence: {entry.occurrence_id}</div>}
        {entry.finding_url && <div className="break-all">occurrence finding URL: {entry.finding_url}</div>}
        {entry.scan_uuid && <div className="break-all">scan: {entry.scan_uuid}</div>}
      </div>)}
    </div>)}
    {selected && <ExchangeInspector key={JSON.stringify([finding.id, finding.project_uuid, selected.exchange_id])} entry={selected} finding={finding} theme={theme} />}
  </section>;
}

// Association identity excludes hydrated bytes and survives metadata refetches.
function associationKey(entry: EvidenceEntry) {
  return JSON.stringify([entry.exchange_id, entry.role, entry.primary, entry.occurrence_id, entry.label, entry.finding_url, entry.scan_uuid]);
}

function ExchangeInspector({ entry, finding, theme }: { entry: EvidenceEntry; finding: Finding; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const [exchange, setExchange] = useState<EvidenceExchange>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(false);
  const [attempt, setAttempt] = useState(0);
  // The project comes from the finding receipt, never localStorage/default recovery.
  const project = finding.project_uuid;
  const hasIdentity = hasExchangeIdentity(entry);
  useEffect(() => {
    if (!project || !hasIdentity) return;
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    setExchange(undefined);
    fetchSelectedEvidence(finding.id, entry.exchange_id, project, controller.signal)
      .then((result) => { if (!controller.signal.aborted) setExchange(result); })
      .catch((failure) => { if (!controller.signal.aborted) setError(failure); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [project, finding.id, entry.exchange_id, hasIdentity, attempt]);
  if (!project) return <p role="alert" style={{ color: colors.warning }}>Finding project is missing; evidence cannot be loaded safely. No scope recovery is attempted.</p>;
  if (!hasIdentity) return <p role="alert">Selected exchange identity missing.</p>;
  if (loading) return <p role="status">Loading selected exchange…</p>;
  if (error) return <div role="alert" style={{ color: colors.warning }}>{evidenceLoadMessage(error)} <button onClick={() => setAttempt((n) => n + 1)}>Retry exact exchange</button></div>;
  if (!exchange) return <p>Selected exchange unavailable.</p>;
  return <div className="border p-2 space-y-1" style={{ borderColor: colors.border }}>
    <div className="font-semibold">role: {entry.role || 'unknown'} · primary declaration: {entry.primary ? 'yes' : 'no'}</div>
    <div className="break-all">exchange: {exchange.id}</div>
    <div className="break-all">exchange URL: {exchange.url || 'not stored'}</div>
    <div className="break-all">service: {exchange.service || 'not stored'}</div>
    <div>provenance: {exchange.provenance} · captured: {exchange.captured_at}</div>
    {exchange.provenance === 'producer_supplied' && <p style={{ color: colors.warning }}>Producer-supplied capture: provenance alone does not establish a newly sent exchange, capture fidelity, or vulnerability confirmation. Role and primary declarations are separate from capture provenance.</p>}
    {exchange.provenance === 'cached_observation' && <p style={{ color: colors.warning }}>Cached observation: not a newly sent exchange. Explicit role and primary selection are separate from byte fidelity; unknown states do not establish completeness.</p>}
    {exchange.provenance === 'legacy_unknown' && <p style={{ color: colors.warning }}>Legacy capture with unknown provenance; an explicit role does not establish capture fidelity.</p>}
    <div className="break-all">content hash: {exchange.content_hash}</div>
    <p style={{ color: colors.muted }}>Text previews are non-authoritative. Downloads preserve exact captured bytes; complete means complete at the capture boundary, not vulnerability confirmation.</p>
    <div>request state: {exchange.request_state} · response state: {exchange.response_state}</div>
    <HttpMessage theme={theme} label="Selected request" encoding="base64" value={exchange.request} requestURLs={exchange.url ? [exchange.url] : undefined} />
    <HttpMessage theme={theme} label="Selected response" encoding="base64" value={exchange.response} />
  </div>;
}
