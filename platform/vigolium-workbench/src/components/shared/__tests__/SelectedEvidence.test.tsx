import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceEntry, EvidenceExchange, Finding } from '@/api/types';
import FindingEvidence from '../FindingEvidence';

const state = vi.hoisted(() => ({ project: 'project-a', fetchEvidence: vi.fn() }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: state.project }) }));
vi.mock('@/lib/selectedEvidenceApi', () => ({ fetchSelectedEvidence: state.fetchEvidence }));
const exchange: EvidenceExchange = { id: 'proof-id', url: 'https://app.test/proof', request: btoa('GET /proof HTTP/1.1\r\n\r\n'), response: btoa('HTTP/1.1 200 OK\r\n\r\nproof bytes'), request_state: 'complete', response_state: 'complete', provenance: 'captured', content_hash: 'hash', captured_at: 'now' };
const finding: Finding = { id: 7, project_uuid: 'project-a', url: 'https://app.test/finding', http_record_uuids: ['first-linked'], module_id: 'test', module_name: 'Test', finding_hash: 'fixture', severity: 'info', confidence: 'tentative', created_at: '', found_at: '' };
const entries: EvidenceEntry[] = [{ exchange_id: 'baseline-id', role: 'baseline', label: 'Baseline' }, { exchange_id: 'unknown-id', role: 'unknown', primary: true, label: 'Unknown' }, { exchange_id: 'proof-id', role: 'observation', primary: true, label: 'Observation' }];
const Inspector = () => <div>Linked inspector</div>;

beforeEach(() => { state.project = 'project-a'; state.fetchEvidence.mockReset().mockResolvedValue(exchange); });
for (const theme of ['dark', 'light'] as const) describe(`${theme} selected evidence`, () => {
  const view = (value: Finding) => <FindingEvidence finding={value} theme={theme} RecordInspector={Inspector} />;
  it('selects only the explicit primary observation regardless of baseline/unknown order or URLs', async () => {
    render(view({ ...finding, evidence: entries, evidence_status: 'selected' }));
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'proof-id', 'project-a', expect.any(AbortSignal));
    expect(screen.getByText('Original context (not proof)')).toBeInTheDocument();
    expect(screen.getByText(/Legacy inline evidence — role unknown/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /role: baseline · primary declaration: no — exchange: baseline-id$/ }));
    await waitFor(() => expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'baseline-id', 'project-a', expect.any(AbortSignal)));
    expect(screen.getAllByText(/role: baseline/).length).toBeGreaterThan(0);
  });
  it('keeps the module baseline visible and folds the duplicate scan input into context', async () => {
    const entries: EvidenceEntry[] = [
      { exchange_id: 'module-baseline', role: 'baseline', label: 'Module baseline', occurrence_id: 'scan-occurrence', scan_uuid: 'scan-a' },
      { exchange_id: 'scan-input', role: 'baseline', label: 'Scan input / context', occurrence_id: 'scan-occurrence', scan_uuid: 'scan-a' },
    ];
    const occurrences = [{ occurrence_id: 'scan-occurrence', scan_uuid: 'scan-a', evidence_status: 'unclassified', entries }];
    render(view({ ...finding, evidence: entries, occurrences }));

    const occurrence = screen.getByRole('group', { name: /scan-a.*scan-occurrence/ });
    expect(within(occurrence).getByRole('button', { name: /exchange: module-baseline/ })).toBeVisible();
    const details = within(occurrence).getByText('Scan input / context (context only)').closest('details');
    expect(details).not.toBeNull();
    expect(details).not.toHaveAttribute('open');
    expect(within(details!).getByRole('button', { name: /exchange: scan-input/ })).not.toBeVisible();

    fireEvent.click(within(details!).getByText('Scan input / context (context only)'));
    expect(within(details!).getByRole('button', { name: /exchange: scan-input/ })).toBeVisible();
    expect(state.fetchEvidence).not.toHaveBeenCalled();
  });
  it('groups each scan occurrence and auto-selects the newest unambiguous primary', async () => {
    const occurrences = [
      {
        occurrence_id: 'occurrence-old', scan_uuid: 'scan-a', evidence_status: 'selected', entries: [
          { exchange_id: 'old-primary', role: 'attack', primary: true, occurrence_id: 'occurrence-old', scan_uuid: 'scan-a' },
          { exchange_id: 'old-control', role: 'control', occurrence_id: 'occurrence-old', scan_uuid: 'scan-a' },
          { exchange_id: 'old-baseline', role: 'baseline', occurrence_id: 'occurrence-old', scan_uuid: 'scan-a' },
        ],
      },
      {
        occurrence_id: 'occurrence-new', scan_uuid: 'scan-b', evidence_status: 'selected', entries: [
          { exchange_id: 'new-primary', role: 'attack', primary: true, occurrence_id: 'occurrence-new', scan_uuid: 'scan-b' },
          { exchange_id: 'new-confirmation', role: 'confirmation', occurrence_id: 'occurrence-new', scan_uuid: 'scan-b' },
          { exchange_id: 'new-control', role: 'control', occurrence_id: 'occurrence-new', scan_uuid: 'scan-b' },
          { exchange_id: 'new-baseline', role: 'baseline', occurrence_id: 'occurrence-new', scan_uuid: 'scan-b' },
        ],
      },
    ] as NonNullable<Finding['occurrences']>;
    render(view({ ...finding, evidence: occurrences.flatMap((occurrence) => occurrence.entries), occurrences }));

    const groups = screen.getAllByRole('group', { name: /Finding occurrence/ });
    expect(groups).toHaveLength(2);
    expect(groups[0]).toHaveAccessibleName(/scan-b.*occurrence-new/);
    expect(groups[1]).toHaveAccessibleName(/scan-a.*occurrence-old/);
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'new-primary', 'project-a', expect.any(AbortSignal));
    expect(within(groups[0]).getByRole('button', { name: /new-primary/ })).toHaveAttribute('aria-pressed', 'true');
    expect(within(groups[1]).getByRole('button', { name: /old-primary/ })).toHaveAttribute('aria-pressed', 'false');

    const headings = within(groups[0]).getAllByRole('heading').map((heading) => heading.textContent);
    expect(headings).toEqual(['Detection 2 · latest', 'Main selections', 'Repeat checks (not a verdict)', 'Comparison controls', 'Original context (not proof)']);
  });
  it('labels inline request/response bytes with their first-observation scan', () => {
    render(view({ ...finding, scan_uuid: 'scan-b', inline_evidence_scan_uuid: 'scan-a', request: 'first request', response: 'first response' }));
    expect(screen.getByText('Inline request/response source: first observed scan scan-a (latest finding scan: scan-b).')).toBeInTheDocument();
  });
  it('does not auto-select an older primary when the newest occurrence is ambiguous', () => {
    const occurrences = [
      { occurrence_id: 'occurrence-old', scan_uuid: 'scan-a', evidence_status: 'selected', entries: [
        { exchange_id: 'old-primary', role: 'attack', primary: true, occurrence_id: 'occurrence-old', scan_uuid: 'scan-a' },
      ] },
      { occurrence_id: 'occurrence-new', scan_uuid: 'scan-b', evidence_status: 'missing', entries: [
        { exchange_id: 'new-primary-a', role: 'attack', primary: true, occurrence_id: 'occurrence-new', scan_uuid: 'scan-b' },
        { exchange_id: 'new-primary-b', role: 'confirmation', primary: true, occurrence_id: 'occurrence-new', scan_uuid: 'scan-b' },
      ] },
    ] as NonNullable<Finding['occurrences']>;
    render(view({ ...finding, evidence: occurrences.flatMap((occurrence) => occurrence.entries), occurrences }));

    expect(screen.getByRole('group', { name: /scan-b.*occurrence-new/ })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/Ambiguous primary declarations.*occurrence-new/);
    expect(screen.getByRole('button', { name: /old-primary/ })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: /new-primary-a/ })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: /new-primary-b/ })).toHaveAttribute('aria-pressed', 'false');
    expect(state.fetchEvidence).not.toHaveBeenCalled();
  });
  it('keeps an explicit primary cached observation distinct from sent capture and legacy fidelity', async () => {
    state.fetchEvidence.mockResolvedValue({ ...exchange, provenance: 'cached_observation', request_state: 'unknown', response_state: 'unknown' });
    render(view({ ...finding, evidence: [entries[2]], evidence_status: 'selected' }));
    expect(await screen.findByText(/Cached observation: not a newly sent exchange/)).toBeInTheDocument();
    expect(screen.getByText(/provenance: cached_observation/)).toBeInTheDocument();
    expect(screen.getByText('request state: unknown · response state: unknown')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByText(/Legacy capture with unknown provenance/)).not.toBeInTheDocument();
    expect(screen.getByText(/proof bytes/)).toBeInTheDocument();
  });
  it.each([undefined, '', ' \t '])('keeps malformed primary identity %j visible and unavailable without auto-fetch or URL fallback', (exchange_id) => {
    const malformed = { exchange_id, role: 'attack', primary: true, label: 'claimed proof', occurrence_id: 'malformed', finding_url: exchange.url, exchange } as EvidenceEntry;
    render(view({ ...finding, url: exchange.url, evidence: [malformed], request: 'legacy bytes', evidence_status: 'selected' }));
    const invalidGroup = screen.getByRole('heading', { name: 'Invalid / unavailable primary declarations' }).parentElement!;
    const button = within(invalidGroup).getByRole('button', { name: /role: attack · primary declaration: yes — exchange: Missing exchange identity$/ });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('aria-pressed', 'false');
    expect(within(invalidGroup).getByText('Producer label: claimed proof')).toBeInTheDocument();
    expect(within(invalidGroup).getByText(/No URL or linked-record fallback is attempted/)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Main selections' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Selected primary proof/ })).not.toBeInTheDocument();
    fireEvent.click(button);
    expect(state.fetchEvidence).not.toHaveBeenCalled();
    expect(screen.queryByText(/proof bytes/)).not.toBeInTheDocument();
    expect(screen.queryByText('Linked inspector')).not.toBeInTheDocument();
  });
  it.each(['same', 'later'])('blocks fallback within an ambiguous occurrence and selects a distinct newer one (%s)', async (occurrence_id) => {
    const malformed: EvidenceEntry = { exchange_id: '', role: 'attack', primary: true, occurrence_id: 'same' };
    const valid = { ...entries[2], occurrence_id };
    render(view({ ...finding, evidence: [malformed, valid], evidence_status: 'missing' }));
    expect(screen.getByRole('heading', { name: 'Invalid / unavailable primary declarations' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Main selections' })).toBeInTheDocument();
    if (occurrence_id === 'same') {
      expect(screen.getByRole('alert')).toHaveTextContent(/Ambiguous primary declarations/);
      expect(state.fetchEvidence).not.toHaveBeenCalled();
      fireEvent.click(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ }));
    } else {
      expect(screen.queryByText(/Ambiguous primary declarations/)).not.toBeInTheDocument();
      expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ })).toHaveAttribute('aria-pressed', 'true');
    }
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'proof-id', 'project-a', expect.any(AbortSignal));
  });
  it('keeps a malicious producer label on a primary-flagged baseline in context, not primary selections', async () => {
    const baseline = { ...entries[0], primary: true, label: 'confirmed attack proof' };
    render(view({ ...finding, evidence: [baseline], evidence_status: 'selected' }));
    const baselineGroup = screen.getByRole('heading', { name: 'Original context (not proof)' }).parentElement!;
    expect(within(baselineGroup).getByText('Producer label: confirmed attack proof')).toBeInTheDocument();
    const button = within(baselineGroup).getByRole('button', { name: /role: baseline · primary declaration: yes — exchange: baseline-id$/ });
    expect(button).toHaveAttribute('aria-pressed', 'false');
    expect(screen.queryByRole('button', { name: /confirmed attack proof/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Main selections' })).not.toBeInTheDocument();
    expect(state.fetchEvidence).not.toHaveBeenCalled();
    fireEvent.click(button);
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'baseline-id', 'project-a', expect.any(AbortSignal));
    expect(button).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByRole('heading', { name: 'Main selections' })).not.toBeInTheDocument();
  });
  it.each(['attack', 'confirmation'] as const)('keeps primary %s declarations distinct from producer-supplied capture and confirmation', async (role) => {
    state.fetchEvidence.mockResolvedValue({ ...exchange, provenance: 'producer_supplied' });
    render(view({ ...finding, evidence: [{ ...entries[2], role, label: 'confirmed attack proof' }], evidence_status: 'selected' }));
    expect(await screen.findByText(/Producer-supplied capture: provenance alone does not establish a newly sent exchange, capture fidelity, or vulnerability confirmation/)).toBeInTheDocument();
    expect(screen.getByText(/provenance: producer_supplied/)).toBeInTheDocument();
    expect(screen.getByText(/Roles and primary flags are stored declarations, not vulnerability confirmation/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Main selections' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Selected primary proof/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: new RegExp(`role: ${role} · primary declaration: yes — exchange: proof-id$`) })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText('Producer label: confirmed attack proof')).toBeInTheDocument();
    expect(screen.getByText('request state: complete · response state: complete')).toBeInTheDocument();
    expect(screen.getByText(/proof bytes/)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Download exact bytes' })).toHaveLength(2);
    expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'proof-id', 'project-a', expect.any(AbortSignal));
  });
  it.each(['unclassified', 'missing'])('retains historical %s status while inspecting the later classified occurrence', async (status) => {
    const historical = { ...entries[1], primary: status === 'unclassified', occurrence_id: 'historic-occurrence', label: 'Historical unknown', scan_uuid: 'scan-a' };
    const later = { ...entries[2], occurrence_id: 'later-occurrence', scan_uuid: 'scan-b' };
    const occurrences = [
      { occurrence_id: 'historic-occurrence', scan_uuid: 'scan-a', evidence_status: status, entries: [historical] },
      { occurrence_id: 'later-occurrence', scan_uuid: 'scan-b', evidence_status: 'selected', entries: [later] },
    ] as NonNullable<Finding['occurrences']>;
    const value = { ...finding, evidence_status: status, evidence: [historical, later], occurrences, request: 'legacy historical bytes' };
    const { rerender } = render(view(value));
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    expect(screen.getByText(`Stored finding evidence status: ${status}`)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: new RegExp(`role: unknown · primary declaration: ${status === 'unclassified' ? 'yes' : 'no'} — exchange: unknown-id$`) })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText(/later selected evidence does not reclassify historical/)).toBeInTheDocument();
    expect(screen.getByText('legacy historical bytes')).toBeInTheDocument();
    rerender(view({ ...value, evidence: value.evidence.map((entry) => ({ ...entry })) }));
    expect(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ })).toHaveAttribute('aria-pressed', 'true');
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    rerender(view({ ...value, evidence: [later, historical] }));
    expect(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ })).toHaveAttribute('aria-pressed', 'true');
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    expect(screen.getByText(`Stored finding evidence status: ${status}`)).toBeInTheDocument();
  });
  it('never infers proof from inline legacy bytes or first link, and does not pick among multiple primary occurrences', () => {
    const { rerender } = render(view({ ...finding, request: 'legacy attack?', response: 'legacy response', evidence: [{ exchange_id: 'unknown-id', role: 'unknown', primary: true }] }));
    expect(screen.getByText(/No inspectable explicit primary selection/)).toBeInTheDocument();
    expect(state.fetchEvidence).not.toHaveBeenCalled();
    rerender(view({ ...finding, evidence: [entries[2], { exchange_id: 'other-proof', role: 'confirmation', primary: true }] }));
    expect(screen.getByText(/Multiple primary declarations/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/Ambiguous primary declarations within occurrence/);
    expect(state.fetchEvidence).not.toHaveBeenCalled();
  });
  it('keeps independent historical primaries distinct and preselects the newest occurrence', async () => {
    render(view({ ...finding, evidence_status: 'unclassified', evidence: [{ ...entries[2], occurrence_id: 'first' }, { exchange_id: 'other', role: 'confirmation', primary: true, occurrence_id: 'later' }] }));
    expect(screen.queryByText(/Multiple primary declarations/)).not.toBeInTheDocument();
    expect(screen.getByText(/Each detection keeps its own main selection/)).toBeInTheDocument();
    expect(screen.queryByText(/Ambiguous primary declarations/)).not.toBeInTheDocument();
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    expect(state.fetchEvidence).toHaveBeenCalledWith(7, 'other', 'project-a', expect.any(AbortSignal));
    expect(screen.getByRole('button', { name: /exchange: other/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /exchange: proof-id/ })).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByText('Stored finding evidence status: unclassified')).toBeInTheDocument();
  });
  it('shows missing receipt/state without substituting legacy evidence or recovering scope', async () => {
    state.fetchEvidence.mockRejectedValue({ status: 404 });
    const { rerender } = render(view({ ...finding, evidence: entries, request: 'legacy' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/No fallback evidence is substituted/);
    expect(screen.getByRole('heading', { name: 'Main selections' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Selected primary proof/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /role: observation · primary declaration: yes — exchange: proof-id$/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.queryByText(/proof bytes/)).not.toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    state.fetchEvidence.mockResolvedValue({ ...exchange, response: undefined, response_state: 'missing' });
    fireEvent.click(screen.getByRole('button', { name: 'Retry exact exchange' }));
    expect(await screen.findByText(/response state: missing/)).toBeInTheDocument();
    state.fetchEvidence.mockClear();
    rerender(view({ ...finding, project_uuid: undefined, evidence: entries }));
    expect(screen.getByRole('alert')).toHaveTextContent(/Finding project is missing/);
    expect(state.fetchEvidence).not.toHaveBeenCalled();
  });
  it('does not load a stale finding whose captured project differs from the selected project', () => {
    state.project = 'project-b';
    render(view({ ...finding, evidence: entries }));
    expect(screen.getByRole('alert')).toHaveTextContent(/different captured project/);
    expect(state.fetchEvidence).not.toHaveBeenCalled();
  });
  it('aborts stale loads on project changes and keeps the new captured project', async () => {
    let resolveOld!: (x: EvidenceExchange) => void;
    state.fetchEvidence.mockImplementationOnce(() => new Promise<EvidenceExchange>((resolve) => { resolveOld = resolve; }));
    const { rerender } = render(view({ ...finding, evidence: entries }));
    const oldSignal = state.fetchEvidence.mock.calls[0][3] as AbortSignal;
    state.project = 'project-b';
    rerender(view({ ...finding, project_uuid: 'project-b', evidence: entries }));
    expect(oldSignal.aborted).toBe(true);
    expect(await screen.findByText(/proof bytes/)).toBeInTheDocument();
    resolveOld({ ...exchange, response: btoa('stale secret') });
    await waitFor(() => expect(screen.queryByText('stale secret')).not.toBeInTheDocument());
    expect(state.fetchEvidence).toHaveBeenLastCalledWith(7, 'proof-id', 'project-b', expect.any(AbortSignal));
  });
});
