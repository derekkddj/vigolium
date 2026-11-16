'use client';

import { useEffect, useState } from 'react';
import type { EvidenceEntry, EvidenceExchange, Finding, FindingOccurrence } from '@/api/types';
import { ambiguousPrimaryOccurrences, evidenceLoadMessage, hasExchangeIdentity, primaryEvidence, primaryEvidenceDeclarations } from '@/lib/findingEvidence';
import { fetchSelectedEvidence } from '@/lib/selectedEvidenceApi';
import HttpMessage, { evidencePalette, type EvidenceTheme } from './HttpMessage';

const SCAN_INPUT_CONTEXT_LABEL = 'Scan input / context';

type EvidenceOccurrenceGroup = Pick<FindingOccurrence, 'occurrence_id' | 'scan_uuid' | 'evidence_status'> & { entries: EvidenceEntry[] };

/** Roles and primary flags describe declarations, not confirmation; hydrate one exact selection. */
export default function SelectedEvidence({ finding, theme }: { finding: Finding; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const occurrences = evidenceOccurrences(finding);
  const entries = occurrences.flatMap((occurrence) => occurrence.entries);
  const declarations = occurrences.flatMap((occurrence) => primaryEvidenceDeclarations(occurrence.entries));
  const primaries = occurrences.flatMap((occurrence) => primaryEvidence(occurrence.entries));
  const [selectedKey, setSelectedKey] = useState<string | undefined>(() => defaultSelection(occurrences[0]?.entries ?? []));
  const selected = entries.find((entry) => hasExchangeIdentity(entry) && associationKey(entry) === selectedKey);
  return <section className="space-y-2" aria-label="Selected evidence">
    <h3 className="font-semibold">Selected evidence</h3>
    <p>Stored finding evidence status: {finding.evidence_status || (entries.length ? 'unclassified' : 'missing / unclassified')}</p>
    <p style={{ color: colors.muted }}>Stored status is latest finding-level metadata. Each occurrence keeps its own role and primary flag; later selected evidence does not reclassify historical or legacy occurrence states.</p>
    <p style={{ color: colors.muted }}>Roles and primary flags are stored declarations, not vulnerability confirmation. Producer labels do not override them. Receipt availability and capture provenance are separate from role.</p>
    {!primaries.length && occurrences.length === 0 && <p style={{ color: colors.warning }}>No inspectable explicit primary selection. Baseline and unknown legacy data do not establish proof.</p>}
    {declarations.length > 1 && <p style={{ color: colors.muted }}>Multiple primary declarations; occurrence groups retain their own selections. The latest unambiguous occurrence is preselected when available.</p>}
    {occurrences.map((occurrence) => {
      const occurrenceDeclarations = primaryEvidenceDeclarations(occurrence.entries);
      const occurrencePrimaries = primaryEvidence(occurrence.entries);
      const invalidPrimaries = occurrence.entries.filter((entry) => entry.primary && !hasExchangeIdentity(entry));
      const scanInputContexts = occurrence.entries.filter((entry) => entry.role === 'baseline' && entry.label === SCAN_INPUT_CONTEXT_LABEL && !invalidPrimaries.includes(entry));
      const ambiguous = ambiguousPrimaryOccurrences(occurrence.entries);
      const roleGroups = [
        { title: 'Explicit primary selections', entries: occurrencePrimaries },
        { title: 'Invalid / unavailable primary declarations', entries: invalidPrimaries },
        { title: 'Confirmations', entries: occurrence.entries.filter((entry) => entry.role === 'confirmation' && !occurrencePrimaries.includes(entry) && !invalidPrimaries.includes(entry)) },
        { title: 'Controls', entries: occurrence.entries.filter((entry) => entry.role === 'control' && !invalidPrimaries.includes(entry)) },
        { title: 'Baseline context (not proof)', entries: occurrence.entries.filter((entry) => entry.role === 'baseline' && entry.label !== SCAN_INPUT_CONTEXT_LABEL && !invalidPrimaries.includes(entry)) },
        { title: 'Supporting / unclassified exchanges', entries: occurrence.entries.filter((entry) => !occurrencePrimaries.includes(entry) && !invalidPrimaries.includes(entry) && entry.role !== 'confirmation' && entry.role !== 'control' && entry.role !== 'baseline') },
      ];
      const renderEntry = (entry: EvidenceEntry, index: number) => <div key={`${entry.exchange_id}:${entry.occurrence_id}:${index}`}>
        <button className="underline break-all text-left" style={{ color: colors.accent }} disabled={!hasExchangeIdentity(entry)} aria-pressed={selectedKey === associationKey(entry)} onClick={() => setSelectedKey(associationKey(entry))}>
          role: {entry.role || 'unknown'} · primary declaration: {entry.primary ? 'yes' : 'no'} — exchange: {hasExchangeIdentity(entry) ? entry.exchange_id : 'Missing exchange identity'}
        </button>
        {entry.label && <div className="break-all">Producer label: {entry.label}</div>}
        {!hasExchangeIdentity(entry) && <p style={{ color: colors.warning }}>Exchange identity missing or empty; unavailable for inspection. No URL or linked-record fallback is attempted.</p>}
        {entry.occurrence_id && <div className="break-all">occurrence: {entry.occurrence_id}</div>}
        {entry.finding_url && <div className="break-all">occurrence finding URL: {entry.finding_url}</div>}
        {entry.scan_uuid && <div className="break-all">scan: {entry.scan_uuid}</div>}
      </div>;
      const label = `Finding occurrence ${occurrence.scan_uuid || 'scan unavailable'} ${occurrence.occurrence_id}`;
      return <div key={occurrence.occurrence_id} role="group" aria-label={label} className="space-y-1 border p-2">
        <h4 className="font-semibold">Occurrence · scan: {occurrence.scan_uuid || 'not stored'} · id: {occurrence.occurrence_id}</h4>
        {occurrence.evidence_status && <p>Occurrence evidence status: {occurrence.evidence_status}</p>}
        {occurrence.entries.length === 0 && <p style={{ color: colors.warning }}>No typed evidence associations are available for this occurrence.</p>}
        {occurrenceDeclarations.length === 0 && occurrence.entries.length > 0 && <p style={{ color: colors.warning }}>No inspectable explicit primary selection in this occurrence.</p>}
        {ambiguous.length > 0 && <p role="alert" style={{ color: colors.warning }}>Ambiguous primary declarations within occurrence {occurrence.occurrence_id}: {ambiguous.join(', ')}. Inspecting bytes does not resolve the ambiguity or select a proof.</p>}
        {roleGroups.map((group) => (group.entries.length > 0 || group.title === 'Baseline context (not proof)' && scanInputContexts.length > 0) && <div key={group.title} className="space-y-1">
          <h5 style={{ color: colors.muted }}>{group.title}</h5>
          {group.entries.map(renderEntry)}
          {group.title === 'Baseline context (not proof)' && scanInputContexts.length > 0 && <details className="ml-3 border-l pl-2">
            <summary className="cursor-pointer">{SCAN_INPUT_CONTEXT_LABEL} (context only)</summary>
            <p style={{ color: colors.muted }}>Retained scan input is folded separately from the module baseline; it is context, not vulnerability proof.</p>
            {scanInputContexts.map(renderEntry)}
          </details>}
        </div>)}
      </div>;
    })}
    {selected && <ExchangeInspector key={JSON.stringify([finding.id, finding.project_uuid, selected.exchange_id])} entry={selected} finding={finding} theme={theme} />}
  </section>;
}

// The API orders occurrence groups by their first finding_evidence.id (oldest
// first); reversing presents the most recent group first without URL inference.
function evidenceOccurrences(finding: Finding): EvidenceOccurrenceGroup[] {
  const source = finding.occurrences?.length ? finding.occurrences : groupEvidenceEntries(finding.evidence ?? []);
  return source.map((occurrence) => ({
    occurrence_id: occurrence.occurrence_id,
    scan_uuid: occurrence.scan_uuid,
    evidence_status: occurrence.evidence_status,
    entries: occurrence.entries.map((entry) => ({
      ...entry,
      occurrence_id: occurrence.occurrence_id,
      scan_uuid: entry.scan_uuid || occurrence.scan_uuid,
    })),
  })).reverse();
}

function groupEvidenceEntries(entries: EvidenceEntry[]): EvidenceOccurrenceGroup[] {
  const groups = new Map<string, EvidenceOccurrenceGroup>();
  for (const entry of entries) {
    const occurrenceID = entry.occurrence_id || 'legacy / unspecified occurrence';
    let group = groups.get(occurrenceID);
    if (!group) {
      group = { occurrence_id: occurrenceID, scan_uuid: entry.scan_uuid, evidence_status: '', entries: [] };
      groups.set(occurrenceID, group);
    }
    group.entries.push({ ...entry, occurrence_id: occurrenceID });
    if (!group.scan_uuid) group.scan_uuid = entry.scan_uuid;
  }
  return [...groups.values()];
}

function defaultSelection(entries: EvidenceEntry[]) {
  const declarations = primaryEvidenceDeclarations(entries);
  const primaries = primaryEvidence(entries);
  // A malformed competing declaration must not silently choose the remaining valid exchange.
  return declarations.length === 1 && primaries.length === 1 ? associationKey(primaries[0]) : undefined;
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
