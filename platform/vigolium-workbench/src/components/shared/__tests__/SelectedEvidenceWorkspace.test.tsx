import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceExchange, Finding } from '@/api/types';
import FindingEvidence from '../FindingEvidence';

const state = vi.hoisted(() => ({ fetchEvidence: vi.fn() }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: 'project-a' }) }));
vi.mock('@/lib/selectedEvidenceApi', () => ({ fetchSelectedEvidence: state.fetchEvidence }));
const Inspector = () => <div>Linked inspector</div>;
const receipt = (id: string): EvidenceExchange => ({
  id, url: 'https://example.test/admin.php', request: btoa(`${id === 'post-main' ? 'POST' : 'GET'} /admin.php HTTP/1.1\r\n\r\n`),
  response: btoa(`HTTP/1.1 200 OK\r\n\r\n${id} login page`), request_state: 'complete', response_state: 'complete',
  provenance: 'captured', content_hash: 'fixture-hash', captured_at: '2026-11-17T17:57:42Z',
});
const finding: Finding = {
  id: 19928, project_uuid: 'project-a', url: 'https://example.test/admin.php', http_record_uuids: [], module_id: 'bfla-detection',
  module_name: 'BFLA', severity: 'high', confidence: 'tentative', finding_hash: 'fixture', created_at: '', found_at: '', evidence_status: 'selected',
  occurrences: [
    { occurrence_id: 'get-occurrence', scan_uuid: 'same-scan', evidence_status: 'selected', entries: [
      { exchange_id: 'get-main', role: 'attack', primary: true, label: 'selected probe' },
      { exchange_id: 'shared-context', role: 'baseline', label: 'original-auth' },
    ] },
    { occurrence_id: 'post-occurrence', scan_uuid: 'same-scan', evidence_status: 'selected', entries: [
      { exchange_id: 'post-main', role: 'attack', primary: true, label: 'selected probe' },
      { exchange_id: 'post-repeat', role: 'confirmation', label: 'privileged response replay' },
      { exchange_id: 'post-control', role: 'control', label: 'random same-method path' },
      { exchange_id: 'shared-context', role: 'baseline', label: 'original-auth' },
    ] },
  ],
};

beforeEach(() => {
  state.fetchEvidence.mockReset().mockImplementation((_finding: number, id: string) => Promise.resolve(receipt(id)));
});
for (const theme of ['dark', 'light'] as const) describe(`${theme} evidence workspace`, () => {
  const view = (value = finding) => <FindingEvidence finding={value} theme={theme} RecordInspector={Inspector} />;

  it('distinguishes two detections in one scan without an ambiguity warning and hides repetitive UUID metadata', async () => {
    render(view());
    expect(screen.getByText('2 detections · 1 scan')).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: 'Evidence list' })).getByRole('heading', { name: /^Detection 2/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /^Detection 1/ })).toBeInTheDocument();
    expect(screen.queryByText(/Multiple primary declarations/)).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText(/Each detection keeps its own main selection/)).toBeInTheDocument();
    expect(screen.getByText(/Selected evidence is not a verified vulnerability/)).toBeInTheDocument();
    const latest = screen.getByRole('group', { name: /same-scan.*post-occurrence/ });
    const details = within(latest).getByText('Detection technical details').closest('details')!;
    expect(details).not.toHaveAttribute('open');
    expect(within(details).getByText('occurrence: post-occurrence')).not.toBeVisible();
    fireEvent.click(within(details).getByText('Detection technical details'));
    expect(within(details).getByText('occurrence: post-occurrence')).toBeVisible();
    expect(await screen.findByText(/post-main login page/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
  });

  it('keeps shared-exchange associations separate and includes visible labels in accessible names', async () => {
    render(view({ ...finding, occurrences: [{ occurrence_id: 'shared-occurrence', scan_uuid: 'same-scan', evidence_status: 'selected', entries: [
      { exchange_id: 'shared-exchange', role: 'attack', primary: true },
      { exchange_id: 'shared-exchange', role: 'control' },
    ] }] }));
    expect(await screen.findByText(/shared-exchange login page/)).toBeInTheDocument();
    const group = screen.getByRole('group', { name: /shared-occurrence/ });
    expect(within(group).getByText('Scan: same-scan · 2 evidence items')).toBeInTheDocument();
    const probe = within(group).getByRole('button', { name: /role: attack.*exchange: shared-exchange/ });
    const control = within(group).getByRole('button', { name: /role: control.*exchange: shared-exchange/ });
    expect(probe).toHaveAccessibleName(/^Probe request 1 — role: attack/);
    expect(control).toHaveAccessibleName(/^Comparison control 1 — role: control/);
    fireEvent.click(control);
    expect(probe).toHaveAttribute('aria-pressed', 'false');
    expect(control).toHaveAttribute('aria-pressed', 'true');
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('complementary', { name: 'Evidence inspector' })).toHaveTextContent('Detection 1 · Comparison control');
  });

  it('keeps the inspector beside the scrollable list and replaces its content without moving the list', async () => {
    render(view());
    const list = screen.getByRole('region', { name: 'Evidence list' });
    const inspector = screen.getByRole('complementary', { name: 'Evidence inspector' });
    expect(list.parentElement).toBe(inspector.parentElement);
    expect(await within(inspector).findByText(/post-main login page/)).toBeInTheDocument();
    list.scrollTop = 150;
    fireEvent.click(within(list).getByRole('button', { name: /exchange: post-control/ }));
    expect(await within(inspector).findByText(/post-control login page/)).toBeInTheDocument();
    expect(within(inspector).queryByText(/post-main login page/)).not.toBeInTheDocument();
    expect(list.scrollTop).toBe(150);
    expect(state.fetchEvidence).toHaveBeenLastCalledWith(19928, 'post-control', 'project-a', expect.any(AbortSignal));
  });

  it('expands the same selection without refetching and restores the opener and list scroll on Escape', async () => {
    render(view());
    expect(await screen.findByText(/post-main login page/)).toBeInTheDocument();
    const list = screen.getByRole('region', { name: 'Evidence list' });
    list.scrollTop = 120;
    const expand = screen.getByRole('button', { name: 'Expand evidence workspace' });
    expand.focus();
    fireEvent.click(expand);
    const modal = screen.getByRole('dialog', { name: 'Finding evidence workspace' });
    expect(modal).toHaveAttribute('aria-modal', 'true');
    expect(modal.parentElement).toBe(document.body);
    const close = within(modal).getByRole('button', { name: 'Close evidence workspace' });
    expect(close).toHaveFocus();
    expect(document.body.style.overflow).toBe('hidden');
    expect(within(modal).getByText(/post-main login page/)).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Expand evidence workspace' })).toHaveFocus();
    expect(screen.getByRole('region', { name: 'Evidence list' }).scrollTop).toBe(120);
    expect(document.body.style.overflow).toBe('');
    expect(state.fetchEvidence).toHaveBeenCalledTimes(1);
  });

  it('opens the fullscreen inspector from a narrow-screen evidence click and keeps Tab inside it', async () => {
    const media = vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: true } as MediaQueryList);
    render(view());
    expect(await screen.findByText(/post-main login page/)).toBeInTheDocument();
    const opener = screen.getByRole('button', { name: /exchange: get-main/ });
    opener.focus();
    fireEvent.click(opener);
    const modal = screen.getByRole('dialog', { name: 'Finding evidence workspace' });
    expect(await within(modal).findByText(/get-main login page/)).toBeInTheDocument();
    const close = within(modal).getByRole('button', { name: 'Close evidence workspace' });
    close.focus();
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
    expect(modal.contains(document.activeElement)).toBe(true);
    expect(close).not.toHaveFocus();
    fireEvent.click(close);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /exchange: get-main/ })).toHaveFocus();
    media.mockRestore();
  });

  it('restores folded context and focus after a narrow-screen selection closes', async () => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: true } as MediaQueryList);
    render(view({ ...finding, occurrences: [{ occurrence_id: 'context-occurrence', scan_uuid: 'same-scan', evidence_status: 'unclassified', entries: [
      { exchange_id: 'folded-context', role: 'baseline', label: 'Scan input / context' },
    ] }] }));
    const summary = screen.getByText('Scan input / context (context only)');
    fireEvent.click(summary);
    const opener = screen.getByRole('button', { name: /exchange: folded-context/ });
    opener.focus();
    fireEvent.click(opener);
    const modal = screen.getByRole('dialog', { name: 'Finding evidence workspace' });
    expect(await within(modal).findByText(/folded-context login page/)).toBeInTheDocument();
    expect(within(modal).getByText('Scan input / context (context only)').closest('details')).toHaveAttribute('open');
    fireEvent.keyDown(document, { key: 'Escape' });
    const restored = screen.getByRole('button', { name: /exchange: folded-context/ });
    expect(restored).toBeVisible();
    expect(restored).toHaveFocus();
    expect(screen.getByText('Scan input / context (context only)').closest('details')).toHaveAttribute('open');
  });

  it('returns focus to the visible context summary when it was closed inside the modal', async () => {
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: true } as MediaQueryList);
    render(view({ ...finding, occurrences: [{ occurrence_id: 'context-occurrence', scan_uuid: 'same-scan', evidence_status: 'unclassified', entries: [
      { exchange_id: 'folded-context', role: 'baseline', label: 'Scan input / context' },
    ] }] }));
    fireEvent.click(screen.getByText('Scan input / context (context only)'));
    fireEvent.click(screen.getByRole('button', { name: /exchange: folded-context/ }));
    const modal = screen.getByRole('dialog', { name: 'Finding evidence workspace' });
    expect(await within(modal).findByText(/folded-context login page/)).toBeInTheDocument();
    fireEvent.click(within(modal).getByText('Scan input / context (context only)'));
    fireEvent.keyDown(document, { key: 'Escape' });
    const summary = screen.getByText('Scan input / context (context only)');
    expect(summary.closest('details')).not.toHaveAttribute('open');
    expect(summary).toBeVisible();
    expect(summary).toHaveFocus();
  });

  it('discards a late response when a different exact exchange is selected', async () => {
    let resolveOld!: (value: EvidenceExchange) => void;
    state.fetchEvidence.mockImplementationOnce(() => new Promise<EvidenceExchange>((resolve) => { resolveOld = resolve; }));
    render(view());
    const oldSignal = state.fetchEvidence.mock.calls[0][3] as AbortSignal;
    fireEvent.click(screen.getByRole('button', { name: /exchange: get-main/ }));
    expect(oldSignal.aborted).toBe(true);
    const inspector = screen.getByRole('complementary', { name: 'Evidence inspector' });
    expect(await within(inspector).findByText(/get-main login page/)).toBeInTheDocument();
    resolveOld(receipt('post-main'));
    await waitFor(() => expect(within(inspector).queryByText(/post-main login page/)).not.toBeInTheDocument());
  });

  it('clears the fullscreen workspace and aborts outstanding loads when the finding changes', async () => {
    state.fetchEvidence.mockImplementationOnce(() => new Promise(() => {}));
    const { rerender } = render(view());
    const signal = state.fetchEvidence.mock.calls[0][3] as AbortSignal;
    fireEvent.click(screen.getByRole('button', { name: 'Expand evidence workspace' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    rerender(view({ ...finding, id: 19929 }));
    expect(signal.aborted).toBe(true);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.body.style.overflow).toBe('');
    expect(await screen.findByText(/post-main login page/)).toBeInTheDocument();
    expect(state.fetchEvidence).toHaveBeenLastCalledWith(19929, 'post-main', 'project-a', expect.any(AbortSignal));
  });
});
