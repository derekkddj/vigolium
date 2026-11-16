'use client';

import { useState, type ComponentType } from 'react';
import type { Finding } from '@/api/types';
import { useProjectContext } from '@/contexts/ProjectContext';
import { linkedRecordReferences, parseInlineEvidence } from '@/lib/findingEvidence';
import HttpMessage, { evidencePalette, type EvidenceTheme } from './HttpMessage';
import SelectedEvidence from './SelectedEvidence';

interface RecordInspectorProps {
  uuid: string;
  onClose: () => void;
  findingURL?: string;
  referenceRole?: string;
}
interface Props {
  finding: Finding;
  theme: EvidenceTheme;
  RecordInspector: ComponentType<RecordInspectorProps>;
}

export function FindingIdentity({ finding, theme }: Pick<Props, 'finding' | 'theme'>) {
  const colors = evidencePalette[theme];
  const [copyState, setCopyState] = useState('');
  return (
    <section className="border p-2 space-y-1" style={{ borderColor: colors.border, background: colors.background, color: colors.text }} aria-label="Finding target and provenance">
      <div className="flex items-center gap-2 font-semibold">
        <span>Finding URL</span>
        {finding.url && <button style={{ color: colors.accent }} onClick={async () => {
          try { await navigator.clipboard.writeText(finding.url!); setCopyState('Copied'); }
          catch { setCopyState('Copy failed'); }
        }}>Copy URL</button>}
        {copyState && <span role="status">{copyState}</span>}
      </div>
      <div className="break-all font-semibold">{finding.url || 'Not stored (not inferred from linked records)'}</div>
      {finding.hostname && <div className="break-all">hostname: {finding.hostname}</div>}
      <div style={{ color: colors.muted }}>Provenance (stored fields)</div>
      <div>finding_source: {finding.finding_source || 'not stored'}</div>
      {finding.scan_uuid && <div className="break-all">scan_uuid: <a className="underline" style={{ color: colors.accent }} href={`/scan?uuid=${encodeURIComponent(finding.scan_uuid)}`}>{finding.scan_uuid}</a></div>}
      {finding.agentic_scan_uuid && <div className="break-all">agentic_scan_uuid: <a className="underline" style={{ color: colors.accent }} href={`/agentic-scan?session=${encodeURIComponent(finding.agentic_scan_uuid)}`}>{finding.agentic_scan_uuid}</a></div>}
      {!finding.scan_uuid && !finding.agentic_scan_uuid && <div style={{ color: colors.muted }}>No scan / agent session reference stored.</div>}
      {finding.record_kind && <div>record_kind: {finding.record_kind}</div>}
      {finding.evidence_grade && <div>evidence_grade: {finding.evidence_grade}</div>}
    </section>
  );
}

/** Remount before rendering on either identity change; never carry selections across projects. */
export default function FindingEvidence(props: Props) {
  const { projectUUID } = useProjectContext();
  if (projectUUID && props.finding.project_uuid && projectUUID !== props.finding.project_uuid) {
    return <p role="alert" style={{ color: evidencePalette[props.theme].warning }}>Finding belongs to a different captured project. Reload the finding in the selected project; no evidence scope recovery is attempted.</p>;
  }
  const occurrenceKey = props.finding.occurrences?.length
    ? props.finding.occurrences.map((occurrence) => [occurrence.occurrence_id, occurrence.scan_uuid, occurrence.evidence_status, occurrence.entries.map(evidenceEntryKey)])
    : (props.finding.evidence ?? []).map(evidenceEntryKey);
  return <EvidenceContent key={JSON.stringify([projectUUID, props.finding.project_uuid, props.finding.id, occurrenceKey])} {...props} />;
}

function evidenceEntryKey(entry: NonNullable<Finding['evidence']>[number]) {
  return [entry.exchange_id, entry.role, entry.primary, entry.occurrence_id, entry.label, entry.finding_url, entry.scan_uuid];
}

function EvidenceContent({ finding, theme, RecordInspector }: Props) {
  const colors = evidencePalette[theme];
  const [selectedUUID, setSelectedUUID] = useState<string | null>(null);
  const [evidenceTab, setEvidenceTab] = useState(0);
  const [visibleCount, setVisibleCount] = useState(20);
  const [visibleReferences, setVisibleReferences] = useState(20);
  const items = finding.additional_evidence ?? [];
  const selectedEvidence = items[Math.min(evidenceTab, Math.max(0, items.length - 1))];
  const parsed = selectedEvidence == null ? undefined : parseInlineEvidence(selectedEvidence);
  const references = linkedRecordReferences(finding);
  const selectedReference = references.find((reference) => reference.uuid === selectedUUID);
  const hasInline = !!(finding.request || finding.response || items.some(Boolean));
  const buttonStyle = { borderColor: colors.border, color: colors.accent };

  return (
    <div className="space-y-3" style={{ color: colors.text }}>
      <SelectedEvidence finding={finding} theme={theme} />
      <section className="space-y-2" aria-label="Inline finding evidence">
        <h3 className="font-semibold">Legacy inline evidence — role unknown (not proof)</h3>
        <p style={{ color: colors.muted }}>Legacy strings and producer labels have no classified role. They never substitute for a selected exchange; text downloads are not authoritative captured bytes.</p>
        {finding.inline_evidence_scan_uuid && <p style={{ color: colors.muted }}>Inline request/response source: first observed scan {finding.inline_evidence_scan_uuid}{finding.scan_uuid && finding.scan_uuid !== finding.inline_evidence_scan_uuid ? ` (latest finding scan: ${finding.scan_uuid})` : ''}.</p>}
        {!hasInline && <p style={{ color: colors.muted }}>No inline request, response, or additional evidence stored. Linked references below are separate; they do not by themselves establish direct proof.</p>}
        {hasInline && <>
          <HttpMessage theme={theme} label="Inline request" value={finding.request} requestURLs={finding.url ? [finding.url] : undefined} />
          <HttpMessage theme={theme} label="Inline response" value={finding.response} />
        </>}
        {items.length > 0 && <div className="space-y-2">
          <div style={{ color: colors.muted }}>Additional inline evidence ({items.length}); labels are supplied by the producer.</div>
          <div className="flex flex-wrap gap-1" role="group" aria-label="Additional evidence selection">
            {items.slice(0, visibleCount).map((item, index) => <button key={index} aria-pressed={evidenceTab === index} className="border px-1.5 py-0.5" style={{ ...buttonStyle, fontWeight: evidenceTab === index ? 'bold' : 'normal' }} onClick={() => setEvidenceTab(index)}>{parseInlineEvidence(item).label || `Entry ${index + 1}`}</button>)}
            {items.length > visibleCount && <button style={buttonStyle} onClick={() => setVisibleCount((count) => count + 20)}>Show next 20</button>}
          </div>
          {parsed && <>
            <HttpMessage key={`${evidenceTab}-request`} theme={theme} label={parsed.hasSeparator ? 'Additional request' : 'Additional evidence text'} value={parsed.request} />
            {parsed.hasSeparator && <HttpMessage key={`${evidenceTab}-response`} theme={theme} label="Additional response" value={parsed.response} />}
          </>}
        </div>}
      </section>
      <section className="space-y-2" aria-label="Linked HTTP records">
        <h3 className="font-semibold">Linked HTTP records ({references.length})</h3>
        <p style={{ color: colors.muted }}>Loaded only when selected, in the active project. Generic references have no assumed proof role.</p>
        {references.length === 0 && <p style={{ color: colors.muted }}>No linked HTTP record references stored.</p>}
        <ul className="space-y-1">
          {references.slice(0, visibleReferences).map(({ uuid, role }) => <li key={uuid}>
            <div style={{ color: colors.muted }}>{role}</div>
            <button className="text-left break-all underline" style={{ color: colors.accent }} aria-pressed={selectedUUID === uuid} onClick={() => setSelectedUUID(uuid)}>Inspect {uuid}</button>
          </li>)}
        </ul>
        {references.length > visibleReferences && <button style={buttonStyle} onClick={() => setVisibleReferences((count) => count + 20)}>Show next 20 references</button>}
        {!selectedReference && references.length > 0 && <p style={{ color: colors.muted }}>Select one reference to inspect its request and result.</p>}
        {selectedReference && <RecordInspector key={selectedReference.uuid} uuid={selectedReference.uuid} findingURL={finding.url} referenceRole={selectedReference.role} onClose={() => setSelectedUUID(null)} />}
      </section>
    </div>
  );
}
