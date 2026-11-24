'use client';

import { useEffect, useState } from 'react';
import type { EvidenceEntry, EvidenceExchange, Finding, FindingOccurrence } from '@/api/types';
import { ambiguousPrimaryOccurrences, decodeHTTPBase64, evidenceLoadMessage, hasExchangeIdentity, primaryEvidence, primaryEvidenceDeclarations } from '@/lib/findingEvidence';
import { fetchSelectedEvidence } from '@/lib/selectedEvidenceApi';
import HttpMessage, { evidencePalette, type EvidenceTheme } from './HttpMessage';
import EvidenceWorkspace from './EvidenceWorkspace';

const SCAN_INPUT_CONTEXT_LABEL = 'Scan input / context';

type EvidenceOccurrenceGroup = Pick<FindingOccurrence, 'occurrence_id' | 'scan_uuid' | 'evidence_status'> & { entries: EvidenceEntry[] };

/** Roles and primary flags describe declarations, not confirmation; hydrate one exact selection. */
export default function SelectedEvidence({ finding, theme }: { finding: Finding; theme: EvidenceTheme }) {
  const colors = evidencePalette[theme];
  const occurrences = evidenceOccurrences(finding);
  const entries = occurrences.flatMap((occurrence) => occurrence.entries);
  const scanCount = new Set(occurrences.map((occurrence) => occurrence.scan_uuid).filter(Boolean)).size;
  const [selectedKey, setSelectedKey] = useState<string | undefined>(() => defaultSelection(occurrences[0]?.entries ?? []));
  const selected = entries.find((entry) => hasExchangeIdentity(entry) && associationKey(entry) === selectedKey);
  const selectedIndex = occurrences.findIndex((occurrence) => occurrence.entries.includes(selected!));
  // Keep the exact load above the portal boundary: expanding must not reload bytes or lose ownership.
  const load = useExchangeLoad(finding, selected);
  const hasAmbiguity = occurrences.some((occurrence) => ambiguousPrimaryOccurrences(occurrence.entries).length > 0);
  return <section className="space-y-2" aria-label="Selected evidence">
    <h3 className="font-semibold">Selected evidence</h3>
    <p>{occurrences.length} {occurrences.length === 1 ? 'detection' : 'detections'} · {scanCount} {scanCount === 1 ? 'scan' : 'scans'}</p>
    <p style={{ color: colors.muted }}>Each detection keeps its own main selection, even within the same scan. Selected evidence is not a verified vulnerability.</p>
    <details className="border p-2" style={{ borderColor: colors.border }}>
      <summary className="cursor-pointer" style={{ color: colors.accent }}>How to read this evidence</summary>
      <p>Scan = execution. Detection (occurrence) = one module result. Exchange = one stored request/response.</p>
      <p>Main selections are producer-chosen receipts. Repeat checks test reproducibility, not whether access was privileged. Controls are comparisons. Original context is not proof of a working login.</p>
      <p>Stored finding evidence status: {finding.evidence_status || (entries.length ? 'unclassified' : 'missing / unclassified')}</p>
      <p>Stored status is latest finding-level metadata. Each occurrence keeps its own role and primary flag; later selected evidence does not reclassify historical or legacy occurrence states.</p>
      <p>Roles and primary flags are stored declarations, not vulnerability confirmation. Producer labels do not override them. Receipt availability and capture provenance are separate from role.</p>
    </details>
    {occurrences.length === 0 && <p style={{ color: colors.warning }}>No inspectable explicit primary selection. Baseline and unknown legacy data do not establish proof.</p>}
    {hasAmbiguity && <p style={{ color: colors.warning }}>Multiple primary declarations within a detection require inspection; independent detections are not an ambiguity.</p>}
    <EvidenceWorkspace findingID={finding.id} theme={theme} inspector={<>
      <div className="shrink-0 border-b p-2" style={{ borderColor: colors.border }}>
        <h4 className="font-semibold">{selected ? `Detection ${occurrences.length - selectedIndex} · ${entryTitle(selected)}` : 'Select an exchange to inspect'}</h4>
        {selected && <p style={{ color: colors.muted }}>Inspecting this receipt does not confirm the finding.</p>}
      </div>
      <div key={selectedKey} role="region" aria-label="Selected exchange content" tabIndex={0} className="flex-1 min-h-0 min-w-0 overflow-y-auto overscroll-contain p-2">
        {selected ? <ExchangeInspector entry={selected} finding={finding} theme={theme} load={load} /> : <p>Select a main request, repeat check, control or context from the list.</p>}
      </div>
    </>} list={occurrences.map((occurrence, occurrenceIndex) => {
      const occurrenceDeclarations = primaryEvidenceDeclarations(occurrence.entries);
      const occurrencePrimaries = primaryEvidence(occurrence.entries);
      const invalidPrimaries = occurrence.entries.filter((entry) => entry.primary && !hasExchangeIdentity(entry));
      const scanInputContexts = occurrence.entries.filter((entry) => entry.role === 'baseline' && entry.label === SCAN_INPUT_CONTEXT_LABEL && !invalidPrimaries.includes(entry));
      const ambiguous = ambiguousPrimaryOccurrences(occurrence.entries);
      const roleGroups = [
        { title: 'Main selections', entries: occurrencePrimaries },
        { title: 'Invalid / unavailable primary declarations', entries: invalidPrimaries },
        { title: 'Repeat checks (not a verdict)', entries: occurrence.entries.filter((entry) => entry.role === 'confirmation' && !occurrencePrimaries.includes(entry) && !invalidPrimaries.includes(entry)) },
        { title: 'Comparison controls', entries: occurrence.entries.filter((entry) => entry.role === 'control' && !invalidPrimaries.includes(entry)) },
        { title: 'Original context (not proof)', entries: occurrence.entries.filter((entry) => entry.role === 'baseline' && entry.label !== SCAN_INPUT_CONTEXT_LABEL && !invalidPrimaries.includes(entry)) },
        { title: 'Other / unclassified exchanges', entries: occurrence.entries.filter((entry) => !occurrencePrimaries.includes(entry) && !invalidPrimaries.includes(entry) && entry.role !== 'confirmation' && entry.role !== 'control' && entry.role !== 'baseline') },
      ];
      const renderEntry = (entry: EvidenceEntry, index: number) => <div key={`${entry.exchange_id}:${entry.occurrence_id}:${index}`} className="space-y-1">
        <button className="w-full border p-2 text-left break-words disabled:opacity-50" style={{ borderColor: selectedKey === associationKey(entry) ? colors.accent : colors.border, color: colors.accent }}
          disabled={!hasExchangeIdentity(entry)} aria-pressed={selectedKey === associationKey(entry)} data-evidence-key={associationKey(entry)}
          aria-label={`${entryTitle(entry)} ${index + 1} — role: ${entry.role || 'unknown'} · primary declaration: ${entry.primary ? 'yes' : 'no'} — exchange: ${hasExchangeIdentity(entry) ? entry.exchange_id : 'Missing exchange identity'}`}
          onClick={() => setSelectedKey(associationKey(entry))}>
          <span className="font-semibold">{entryTitle(entry)} {index + 1}</span>
          <span className="block text-[10px]" style={{ color: colors.muted }}>{entry.role || 'unknown'}{entry.primary ? ' · primary declaration' : ''} · {hasExchangeIdentity(entry) ? shortID(entry.exchange_id) : 'Missing exchange identity'}</span>
        </button>
        {!hasExchangeIdentity(entry) && <p style={{ color: colors.warning }}>Exchange identity missing or empty; unavailable for inspection. No URL or linked-record fallback is attempted.</p>}
        <details data-evidence-details={JSON.stringify(['exchange', associationKey(entry)])} className="ml-2" style={{ color: colors.muted }}>
          <summary className="cursor-pointer">Exchange technical details</summary>
          <div className="break-all">role: {entry.role || 'unknown'} · primary declaration: {entry.primary ? 'yes' : 'no'}</div>
          <div className="break-all">exchange: {hasExchangeIdentity(entry) ? entry.exchange_id : 'Missing exchange identity'}</div>
          {entry.label && <div className="break-all">Producer label: {entry.label}</div>}
          {entry.occurrence_id && <div className="break-all">occurrence: {entry.occurrence_id}</div>}
          {entry.finding_url && <div className="break-all">occurrence finding URL: {entry.finding_url}</div>}
          {entry.scan_uuid && <div className="break-all">scan: {entry.scan_uuid}</div>}
        </details>
      </div>;
      const label = `Finding occurrence ${occurrence.scan_uuid || 'scan unavailable'} ${occurrence.occurrence_id}`;
      return <div key={occurrence.occurrence_id} role="group" aria-label={label} className="space-y-2 border p-2" style={{ borderColor: colors.border }}>
        <h4 className="font-semibold">Detection {occurrences.length - occurrenceIndex}{occurrenceIndex === 0 ? ' · latest' : ''}</h4>
        <p style={{ color: colors.muted }}>Scan: {occurrence.scan_uuid ? shortID(occurrence.scan_uuid) : 'not stored'} · {occurrence.entries.length} evidence items</p>
        {occurrence.evidence_status && <p>Evidence selection: {occurrence.evidence_status}{occurrence.evidence_status === 'selected' ? ' (not verification)' : ''}</p>}
        <details data-evidence-details={JSON.stringify(['detection', occurrence.occurrence_id])} style={{ color: colors.muted }}>
          <summary className="cursor-pointer">Detection technical details</summary>
          <div className="break-all">occurrence: {occurrence.occurrence_id}</div>
          <div className="break-all">scan: {occurrence.scan_uuid || 'not stored'}</div>
          <div>Occurrence evidence status: {occurrence.evidence_status || 'not stored'}</div>
        </details>
        {occurrence.entries.length === 0 && <p style={{ color: colors.warning }}>No typed evidence associations are available for this occurrence.</p>}
        {occurrenceDeclarations.length === 0 && occurrence.entries.length > 0 && <p style={{ color: colors.warning }}>No inspectable explicit primary selection in this occurrence.</p>}
        {ambiguous.length > 0 && <p role="alert" style={{ color: colors.warning }}>Ambiguous primary declarations within occurrence {occurrence.occurrence_id}: {ambiguous.join(', ')}. Inspecting bytes does not resolve the ambiguity or select a proof.</p>}
        {roleGroups.map((group) => (group.entries.length > 0 || group.title === 'Original context (not proof)' && scanInputContexts.length > 0) && <div key={group.title} className="space-y-1">
          <h5 style={{ color: colors.muted }}>{group.title}</h5>
          {group.entries.map(renderEntry)}
          {group.title === 'Original context (not proof)' && scanInputContexts.length > 0 && <details data-evidence-details={JSON.stringify(['context', occurrence.occurrence_id])} className="ml-3 border-l pl-2">
            <summary className="cursor-pointer">{SCAN_INPUT_CONTEXT_LABEL} (context only)</summary>
            <p style={{ color: colors.muted }}>Retained scan input is folded separately from the module baseline; it is context, not vulnerability proof.</p>
            {scanInputContexts.map(renderEntry)}
          </details>}
        </div>)}
      </div>;
    })} />
  </section>;
}

function shortID(id: string) {
  return id.length > 12 ? `${id.slice(0, 8)}…` : id;
}

function entryTitle(entry: EvidenceEntry) {
  // Labels can claim "privileged" or "confirmed"; derive presentation only from the stored role.
  switch (entry.role) {
    case 'attack': return 'Probe request';
    case 'confirmation': return 'Repeat check';
    case 'observation': return 'Observation';
    case 'control': return 'Comparison control';
    case 'baseline': return 'Original context';
    default: return 'Unclassified exchange';
  }
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

interface ExchangeLoad {
  key: string;
  exchange?: EvidenceExchange;
  error?: unknown;
  loading: boolean;
}

function useExchangeLoad(finding: Finding, entry?: EvidenceEntry) {
  // The project comes from the finding receipt, never localStorage/default recovery.
  const project = finding.project_uuid;
  const exchangeID = entry && hasExchangeIdentity(entry) ? entry.exchange_id : undefined;
  const key = JSON.stringify([finding.id, project, exchangeID]);
  const [snapshot, setSnapshot] = useState<ExchangeLoad>({ key, loading: !!(project && exchangeID) });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!project || !exchangeID) return;
    const controller = new AbortController();
    fetchSelectedEvidence(finding.id, exchangeID, project, controller.signal)
      .then((exchange) => { if (!controller.signal.aborted) setSnapshot({ key, exchange, loading: false }); })
      .catch((error: unknown) => { if (!controller.signal.aborted) setSnapshot({ key, error, loading: false }); });
    return () => controller.abort();
  }, [project, finding.id, exchangeID, key, attempt]);
  const retry = () => { setSnapshot({ key, loading: true }); setAttempt((n) => n + 1); };
  // Never render the preceding receipt during the render-before-effect gap.
  return { ...(snapshot.key === key ? snapshot : { key, loading: !!(project && exchangeID) }), retry };
}

function ExchangeInspector({ entry, finding, theme, load }: { entry: EvidenceEntry; finding: Finding; theme: EvidenceTheme; load: ReturnType<typeof useExchangeLoad> }) {
  const colors = evidencePalette[theme];
  const { exchange, error, loading, retry } = load;
  if (!finding.project_uuid) return <p role="alert" style={{ color: colors.warning }}>Finding project is missing; evidence cannot be loaded safely. No scope recovery is attempted.</p>;
  if (!hasExchangeIdentity(entry)) return <p role="alert">Selected exchange identity missing.</p>;
  if (loading) return <p role="status">Loading selected exchange…</p>;
  if (error) return <div role="alert" style={{ color: colors.warning }}>{evidenceLoadMessage(error)} <button onClick={retry}>Retry exact exchange</button></div>;
  if (!exchange) return <p>Selected exchange unavailable.</p>;
  return <div className="space-y-2">
    <div className="font-semibold break-all">{httpStartLine(exchange.request) || 'Request start line unavailable'}</div>
    <div className="break-all">{httpStartLine(exchange.response) || 'Response start line unavailable'}</div>
    <div className="break-all">URL: {exchange.url || 'not stored'}</div>
    <details data-evidence-details={JSON.stringify(['capture', associationKey(entry)])} className="border p-2" style={{ borderColor: colors.border }}>
      <summary className="cursor-pointer" style={{ color: colors.accent }}>Capture technical details</summary>
      <div className="font-semibold">role: {entry.role || 'unknown'} · primary declaration: {entry.primary ? 'yes' : 'no'}</div>
      <div className="break-all">exchange: {exchange.id}</div>
      <div className="break-all">exchange URL: {exchange.url || 'not stored'}</div>
      <div className="break-all">service: {exchange.service || 'not stored'}</div>
      <div>provenance: {exchange.provenance} · captured: {exchange.captured_at}</div>
      <div className="break-all">content hash: {exchange.content_hash}</div>
    </details>
    {exchange.provenance === 'producer_supplied' && <p style={{ color: colors.warning }}>Producer-supplied capture: provenance alone does not establish a newly sent exchange, capture fidelity, or vulnerability confirmation. Role and primary declarations are separate from capture provenance.</p>}
    {exchange.provenance === 'cached_observation' && <p style={{ color: colors.warning }}>Cached observation: not a newly sent exchange. Explicit role and primary selection are separate from byte fidelity; unknown states do not establish completeness.</p>}
    {exchange.provenance === 'legacy_unknown' && <p style={{ color: colors.warning }}>Legacy capture with unknown provenance; an explicit role does not establish capture fidelity.</p>}
    <p style={{ color: colors.muted }}>Text previews are non-authoritative. Downloads preserve exact captured bytes; complete means complete at the capture boundary, not vulnerability confirmation.</p>
    <div>request state: {exchange.request_state} · response state: {exchange.response_state}</div>
    <HttpMessage theme={theme} label="Selected request" encoding="base64" value={exchange.request} requestURLs={exchange.url ? [exchange.url] : undefined} />
    <HttpMessage theme={theme} label="Selected response" encoding="base64" value={exchange.response} />
  </div>;
}

/** Decode only a bounded prefix for navigation; do not infer methods from labels or URLs. */
function httpStartLine(encoded?: string) {
  return encoded ? decodeHTTPBase64(encoded.slice(0, 1024)).text?.split(/\r?\n/, 1)[0] : undefined;
}
