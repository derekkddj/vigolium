import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentSessionDetail } from '@/api/types';
import { HTTP_PREVIEW_LIMIT } from '@/lib/findingEvidence';
import AgentRunContext, { formatAgentRunCount } from '../AgentRunContext';

const context = vi.hoisted(() => ({ projectUUID: 'project-a' as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => context }));
const session = (fields: Partial<AgentSessionDetail> = {}): AgentSessionDetail => ({
  uuid: 'run-a', mode: 'swarm', status: 'completed', agent_name: 'audit-agent',
  duration_ms: 0, started_at: '2026-10-27T00:00:00Z', created_at: '2026-10-27T00:00:00Z', ...fields,
});
const children = (count: number) => Array.from({ length: count }, (_, index) => session({ uuid: `child-${index}`, mode: 'audit' }));
const view = (fields: Partial<AgentSessionDetail> = {}, theme: 'dark' | 'light' = 'dark') => <AgentRunContext session={session(fields)} theme={theme} />;

beforeEach(() => {
  context.projectUUID = 'project-a';
  vi.stubGlobal('fetch', vi.fn());
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } });
});

for (const theme of ['dark', 'light'] as const) {
  describe(`${theme} run context`, () => {
    it('links the parent and direct agent children internally without eager reads or recursive rendering', () => {
      const parent = 'parent/?session=other&x=1 #';
      const child = 'child/?secret=not-a-query';
      const { container } = render(view({
        parent_agentic_scan_uuid: parent, source_path: '/workspace/source', session_dir: '/runs/a', session_id: 'stored-session-id',
        storage_url: 'https://user:password@storage.example.invalid/run?signature=secret#token',
        child_runs: [session({ uuid: child, mode: 'audit', finding_count: 0, record_count: null, saved_count: -1,
          result_json: 'child-result-must-not-render', input_raw: 'child-input-must-not-render',
          child_runs: [session({ uuid: 'grandchild-must-not-render' })],
        })],
      }, theme));
      expect(screen.getByRole('link', { name: parent })).toHaveAttribute('href', `/agentic-scan?session=${encodeURIComponent(parent)}`);
      expect(screen.getByRole('link', { name: child })).toHaveAttribute('href', `/agentic-scan?session=${encodeURIComponent(child)}`);
      expect(screen.getByText('/workspace/source')).toBeInTheDocument();
      expect(screen.getByText('/runs/a')).toBeInTheDocument();
      expect(screen.getByText('stored-session-id')).toBeInTheDocument();
      expect(screen.getByText('https://storage.example.invalid/run')).toBeInTheDocument();
      expect(container.textContent).not.toMatch(/password|signature=secret|#token|child-result-must|child-input-must|grandchild-must/);
      expect(container.querySelectorAll('a')).toHaveLength(2);
      const row = within(screen.getByRole('table', { name: 'Child agent run metadata' })).getAllByRole('row')[1];
      expect(within(row).getByText('0', { exact: true })).toBeInTheDocument();
      expect(within(row).getByText('unknown', { exact: true })).toBeInTheDocument();
      expect(within(row).getByText('unavailable', { exact: true })).toBeInTheDocument();
      expect(screen.getByText(/nested agent\/audit runs, not native scan history/)).toBeInTheDocument();
      expect(fetch).not.toHaveBeenCalled();
    });

    it('renders only 50 children per explicit page and never accumulates the full list', () => {
      render(view({ child_runs: children(123) }, theme));
      expect(screen.getAllByRole('link')).toHaveLength(50);
      expect(screen.getByText(/Showing children 1–50 of 123/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Previous children' })).toBeDisabled();
      expect(screen.queryByRole('link', { name: 'child-50' })).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'More children (next 50)' }));
      expect(screen.getAllByRole('link')).toHaveLength(50);
      expect(screen.getByText(/Showing children 51–100 of 123/)).toBeInTheDocument();
      expect(screen.queryByRole('link', { name: 'child-0' })).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'More children (next 50)' }));
      expect(screen.getAllByRole('link')).toHaveLength(23);
      expect(screen.getByText(/Showing children 101–123 of 123/)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'More children (next 50)' })).toBeDisabled();
      fireEvent.click(screen.getByRole('button', { name: 'Previous children' }));
      expect(screen.getByRole('link', { name: 'child-50' })).toBeInTheDocument();
      expect(fetch).not.toHaveBeenCalled();
    });

    it('distinguishes known zero, null/missing unknown and negative unavailable counts', () => {
      render(view({ finding_count: 0, record_count: null, saved_count: -1 }, theme));
      const counts = screen.getByLabelText('Stored run counts');
      expect(counts).toHaveTextContent('Findings: 0');
      expect(counts).toHaveTextContent('Records: unknown');
      expect(counts).toHaveTextContent('Saved: unavailable');
      expect(counts).not.toHaveTextContent('-1');
    });

    it('makes absent legacy metadata and an empty child list explicit', () => {
      const { rerender } = render(view({}, theme));
      expect(screen.getByText(/No direct child agent runs reported.*Child metadata is absent/)).toBeInTheDocument();
      expect(screen.getByText('Not reported / unavailable.')).toBeInTheDocument();
      const counts = screen.getByLabelText('Stored run counts');
      expect(counts).toHaveTextContent('Findings: unknown');
      expect(counts).toHaveTextContent('Records: unknown');
      expect(counts).toHaveTextContent('Saved: unknown');
      expect(within(screen.getByRole('region', { name: 'Stored input (input_raw)' })).getByText('Not stored / unavailable.')).toBeInTheDocument();
      expect(within(screen.getByRole('region', { name: 'Stored result JSON (result_json)' })).getByText('Not stored / unavailable.')).toBeInTheDocument();
      expect(screen.queryByRole('link')).not.toBeInTheDocument();
      rerender(view({ child_runs: [] }, theme));
      expect(screen.getByText(/No direct child agent runs reported.*stored child list is empty/)).toBeInTheDocument();
      expect(fetch).not.toHaveBeenCalled();
    });

    it.each(['input_raw', 'result_json'] as const)('renders %s independently when the other field is absent', (field) => {
      const value = field === 'input_raw' ? 'stored request input' : '{"result":"stored raw JSON"}';
      render(view({ [field]: value }, theme));
      const label = field === 'input_raw' ? 'Stored input (input_raw)' : 'Stored result JSON (result_json)';
      expect(screen.getByRole('region', { name: label }).querySelector('pre')?.textContent).toBe(value);
      expect(screen.getByText(/not a console or command\/result transcript/)).toBeInTheDocument();
      expect(fetch).not.toHaveBeenCalled();
    });
  });
}

describe('bounded previews and identity', () => {
  it('renders raw large JSON and input previews within 64 Ki characters and downloads complete fetched UTF-8 text only on demand', async () => {
    const result = '{"value":"' + 'x'.repeat(HTTP_PREVIEW_LIMIT * 3) + '🙂result-tail"}';
    const input = 'y'.repeat(HTTP_PREVIEW_LIMIT + 3) + 'input-tail';
    const createObjectURL = vi.fn().mockReturnValue('blob:fixture');
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    render(view({ result_json: result, input_raw: input }));
    const resultRegion = screen.getByRole('region', { name: 'Stored result JSON (result_json)' });
    const inputRegion = screen.getByRole('region', { name: 'Stored input (input_raw)' });
    expect(resultRegion.querySelector('pre')?.textContent).toBe(result.slice(0, HTTP_PREVIEW_LIMIT));
    expect(inputRegion.querySelector('pre')?.textContent).toBe(input.slice(0, HTTP_PREVIEW_LIMIT));
    expect(within(resultRegion).getByText(/Preview truncated to 64 Ki characters/)).toBeInTheDocument();
    expect(resultRegion.textContent).not.toContain('result-tail');
    expect(createObjectURL).not.toHaveBeenCalled();
    fireEvent.click(within(resultRegion).getByRole('button', { name: 'Download full UTF-8 text' }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blob = createObjectURL.mock.calls[0][0] as Blob;
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(new TextEncoder().encode(result));
    expect(anchorClick).toHaveBeenCalledOnce();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('resets paging and clipboard status on project/session changes, including late old copy callbacks', async () => {
    const childRuns = children(75);
    let resolveCopy!: () => void;
    vi.mocked(navigator.clipboard.writeText).mockReturnValue(new Promise<void>((resolve) => { resolveCopy = resolve; }));
    const { rerender } = render(view({ child_runs: childRuns, result_json: 'old-result' }));
    fireEvent.click(screen.getByRole('button', { name: 'More children (next 50)' }));
    fireEvent.click(screen.getByRole('button', { name: 'Copy full text' }));
    context.projectUUID = 'project-b';
    rerender(view({ child_runs: childRuns, result_json: 'new-project-result' }));
    expect(screen.getByText(/Showing children 1–50/)).toBeInTheDocument();
    await act(async () => { resolveCopy(); });
    expect(screen.queryByText('Copied', { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByText('old-result', { exact: true })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'More children (next 50)' }));
    rerender(view({ uuid: 'run-b', child_runs: childRuns }));
    expect(screen.getByText(/Showing children 1–50/)).toBeInTheDocument();
    expect(screen.queryByText('new-project-result', { exact: true })).not.toBeInTheDocument();
  });

  it('clamps a shortened child list to a bounded valid page after refresh', () => {
    const { rerender } = render(view({ child_runs: children(110) }));
    fireEvent.click(screen.getByRole('button', { name: 'More children (next 50)' }));
    fireEvent.click(screen.getByRole('button', { name: 'More children (next 50)' }));
    rerender(view({ child_runs: children(4) }));
    expect(screen.getAllByRole('link')).toHaveLength(4);
    expect(screen.getByText(/Showing children 1–4 of 4/)).toBeInTheDocument();
  });

  it.each(['javascript:alert(1)', 'data:text/html,secret', '//host.example/path', 'not-a-url'])('never links unsafe storage URL %s', (storage_url) => {
    const { container } = render(view({ storage_url }));
    expect(screen.getByText(/Stored reference hidden/)).toBeInTheDocument();
    expect(container.querySelectorAll('a')).toHaveLength(0);
    expect(container.textContent).not.toContain(storage_url);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([undefined, null, '0'])('treats nonnumeric count %s as unknown', (value) => {
    expect(formatAgentRunCount(value)).toBe('unknown');
  });
  it.each([-1, NaN, Infinity])('treats invalid numeric count %s as unavailable', (value) => {
    expect(formatAgentRunCount(value)).toBe('unavailable');
  });
});
