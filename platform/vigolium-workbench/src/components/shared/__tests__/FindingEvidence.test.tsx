import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Finding, HTTPRecord } from '@/api/types';
import FindingEvidence, { FindingIdentity } from '../FindingEvidence';
import HttpMessage from '../HttpMessage';
import DarkRecordInspector from '@/designs/dark/HttpRecordDetailPanel';
import LightRecordInspector from '@/designs/light/HttpRecordDetailPanel';

const state = vi.hoisted(() => ({
  projectUUID: 'project-a',
  records: {} as Record<string, HTTPRecord>,
  loading: false,
  error: null as null | { status: number },
  readRecord: vi.fn(),
  refetch: vi.fn(),
}));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => ({ projectUUID: state.projectUUID }) }));
vi.mock('@/api/hooks', () => ({ useHttpRecord: (uuid: string) => {
  state.readRecord(uuid);
  return { data: state.records[uuid], isLoading: state.loading, isError: !!state.error, error: state.error, refetch: state.refetch };
} }));

const finding: Finding = {
  id: 1105, project_uuid: 'project-a', url: 'https://example.invalid/finding', hostname: 'example.invalid',
  http_record_uuids: ['related-one', 'related-two'], module_id: 'fixture', module_name: 'Fixture',
  severity: 'info', confidence: 'tentative', finding_hash: 'safe-fixture', found_at: '', created_at: '',
};
const record: HTTPRecord = {
  uuid: 'related-one', url: 'https://example.invalid/related', method: 'GET', status_code: 200, status_phrase: 'OK',
  scheme: 'https', hostname: 'example.invalid', port: 443, path: '/related', http_version: 'HTTP/1.1',
  request_content_length: 0, request_hash: '', response_content_length: 0, response_time_ms: 1,
  response_words: 0, has_response: true, sent_at: '', created_at: '', risk_score: 0,
  raw_request: btoa('GET /related HTTP/1.1\r\nHost: example.invalid\r\n\r\n'),
  raw_response: btoa('HTTP/1.1 200 OK\r\n\r\nSafe fixture body'),
};

beforeEach(() => {
  state.projectUUID = 'project-a';
  state.records = { 'related-one': record };
  state.loading = false;
  state.error = null;
  state.readRecord.mockClear();
});

for (const [theme, Inspector] of [['dark', DarkRecordInspector], ['light', LightRecordInspector]] as const) {
  describe(`${theme} finding evidence`, () => {
    const view = (value = finding) => <FindingEvidence finding={value} theme={theme} RecordInspector={Inspector} />;

    it('shows linked-only findings without implying inline proof and hydrates only the clicked record', () => {
      render(view());
      expect(screen.getByText(/No inline request, response, or additional evidence stored/)).toBeInTheDocument();
      expect(state.readRecord).not.toHaveBeenCalled();
      fireEvent.click(screen.getByRole('button', { name: 'Inspect related-one' }));
      expect(state.readRecord).toHaveBeenCalledWith('related-one');
      expect(state.readRecord).not.toHaveBeenCalledWith('related-two');
      expect(screen.getByText(/Related exchange — URL differs/)).toHaveTextContent(/mismatch does not establish that the finding is false/);
      expect(screen.getByText('https://example.invalid/related')).toBeInTheDocument();
      expect(screen.getByText('GET', { exact: true })).toBeInTheDocument();
      expect(screen.getAllByText(/200 OK/).length).toBeGreaterThan(0);
      expect(screen.getByText(/Safe fixture body/)).toBeInTheDocument();
    });

    it('resets linked selection and the additional evidence tab on project and finding changes', () => {
      const value = { ...finding, additional_evidence: ['first entry', 'second entry'] };
      const { rerender } = render(view(value));
      fireEvent.click(screen.getByRole('button', { name: 'Entry 2' }));
      fireEvent.click(screen.getByRole('button', { name: 'Inspect related-one' }));
      expect(screen.getByText('second entry')).toBeInTheDocument();
      state.readRecord.mockClear();
      state.projectUUID = 'project-b';
      rerender(view({ ...value, project_uuid: 'project-b' }));
      expect(screen.getByText('first entry')).toBeInTheDocument();
      expect(screen.queryByText('second entry')).not.toBeInTheDocument();
      expect(screen.queryByText(/RECORD related-one/)).not.toBeInTheDocument();
      expect(state.readRecord).not.toHaveBeenCalled();
      fireEvent.click(screen.getByRole('button', { name: 'Entry 2' }));
      rerender(view({ ...value, id: 1106, project_uuid: 'project-b' }));
      expect(screen.getByText('first entry')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Entry 1' })).toHaveAttribute('aria-pressed', 'true');
    });

    it('shows explicit loading, missing, denied, error and empty-result states', () => {
      state.loading = true;
      state.records = {};
      const { rerender } = render(view());
      fireEvent.click(screen.getByRole('button', { name: 'Inspect related-one' }));
      expect(screen.getByText('loading...')).toBeInTheDocument();
      state.loading = false;
      state.error = { status: 404 };
      rerender(view());
      expect(screen.getByRole('alert')).toHaveTextContent('Missing HTTP record in the active project');
      fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
      expect(state.refetch).toHaveBeenCalled();
      state.error = { status: 403 };
      rerender(view());
      expect(screen.getByRole('alert')).toHaveTextContent('access denied');
      state.error = { status: 503 };
      rerender(view());
      expect(screen.getByRole('alert')).toHaveTextContent('Failed to load HTTP record');
      state.error = null;
      rerender(view());
      expect(screen.getByText(/HTTP record unavailable: no record returned/)).toBeInTheDocument();
    });

    it('distinguishes missing raw request/response from missing record and explicit baseline from generic references', () => {
      state.records['related-one'] = { ...record, raw_request: undefined, raw_response: undefined, status_code: 0 };
      render(view({ ...finding, origin_record_uuid: 'related-one' }));
      expect(screen.getByText('Origin / baseline record')).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Inspect related-one' }));
      expect(within(screen.getByRole('region', { name: 'Raw request' })).getByText('Not stored / unavailable.')).toBeInTheDocument();
      expect(within(screen.getByRole('region', { name: 'Raw response' })).getByText('Not stored / unavailable.')).toBeInTheDocument();
      expect(screen.getByText('Status unavailable / no HTTP response')).toBeInTheDocument();
    });

    it('shows exact provenance fields and copies the finding URL without deriving it from records', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
      render(<FindingIdentity finding={{ ...finding, finding_source: 'agent', scan_uuid: 'native-fixture', agentic_scan_uuid: 'agent-fixture' }} theme={theme} />);
      expect(screen.getByText(finding.url!)).toBeInTheDocument();
      expect(screen.getByText('finding_source: agent')).toBeInTheDocument();
      expect(screen.getByRole('link', { name: 'native-fixture' })).toHaveAttribute('href', '/scan?uuid=native-fixture');
      expect(screen.getByRole('link', { name: 'agent-fixture' })).toHaveAttribute('href', '/agentic-scan?session=agent-fixture');
      fireEvent.click(screen.getByRole('button', { name: 'Copy URL' }));
      expect(writeText).toHaveBeenCalledWith(finding.url);
      expect(await screen.findByText('Copied')).toBeInTheDocument();
    });
  });

  describe(`${theme} HTTP record saved capture fidelity`, () => {
    const view = () => <Inspector uuid="related-one" onClose={() => {}} />;

    it.each([
      ['missing', 'truncated'],
      ['truncated', 'missing'],
      ['unknown', 'complete'],
      ['complete', 'unknown'],
    ] as const)('shows saved request %s and response %s despite populated raw messages and HTTP status', (requestState, responseState) => {
      state.records['related-one'] = {
        ...record, request_content_length: 100, response_content_length: 100,
        capture_request_state: requestState, capture_response_state: responseState,
      };
      render(view());
      const notice = screen.getByRole('note', { name: 'Saved capture fidelity' });
      expect(notice).toHaveTextContent(`Saved request state: ${requestState}`);
      expect(notice).toHaveTextContent(`Saved response state: ${responseState}`);
      expect(notice).not.toHaveTextContent('not recorded');
    });

    it.each([
      ['populated', {}],
      ['unavailable', { raw_request: undefined, raw_response: undefined, status_code: 0, has_response: false }],
    ] as const)('leaves absent legacy states not recorded / unknown with %s messages', (_label, fields) => {
      state.records['related-one'] = { ...record, ...fields };
      render(view());
      const notice = screen.getByRole('note', { name: 'Saved capture fidelity' });
      expect(notice).toHaveTextContent('Saved request state: not recorded / unknown');
      expect(notice).toHaveTextContent('Saved response state: not recorded / unknown');
      expect(notice).not.toHaveTextContent('complete');
    });

    it('distinguishes explicit unknown from a state that was not recorded', () => {
      state.records['related-one'] = { ...record, capture_request_state: 'unknown' };
      render(view());
      const notice = screen.getByRole('note', { name: 'Saved capture fidelity' });
      expect(within(notice).getByText('Saved request state: unknown', { exact: true })).toBeInTheDocument();
      expect(within(notice).getByText('Saved response state: not recorded / unknown', { exact: true })).toBeInTheDocument();
    });

    it('keeps a saved complete state separate from UI preview truncation', () => {
      state.records['related-one'] = {
        ...record, capture_request_state: 'complete', capture_response_state: 'complete',
        raw_response: btoa(`HTTP/1.1 200 OK\r\n\r\n${'x'.repeat(70000)}`),
      };
      render(view());
      const notice = screen.getByRole('note', { name: 'Saved capture fidelity' });
      expect(notice).toHaveTextContent('Saved request state: complete');
      expect(notice).toHaveTextContent('Saved response state: complete');
      expect(notice).not.toHaveTextContent('truncated');
      expect(within(screen.getByRole('region', { name: 'Raw response' })).getByText(/Preview truncated/)).toBeInTheDocument();
    });
  });
}

describe('HTTP message preview and download', () => {
  it('bounds a long preview while copying the complete response, including later separators', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    const fullText = `${'x'.repeat(70000)}\n---------\ncomplete tail`;
    const { container } = render(<HttpMessage theme="dark" label="Response fixture" value={fullText} />);
    expect(container.querySelector('pre')?.textContent?.length).toBe(65536);
    expect(screen.getByText(/Preview truncated/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Copy full text' }));
    expect(writeText).toHaveBeenCalledWith(fullText);
    expect(await screen.findByText('Copied')).toBeInTheDocument();
  });

  it('downloads fetched binary bytes unchanged, with an explicit invalid UTF-8 warning', async () => {
    const bytes = Uint8Array.from([0xff, 0xfe, 0, 65]);
    const createObjectURL = vi.fn().mockReturnValue('blob:safe-fixture');
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    render(<HttpMessage theme="light" label="Binary fixture" value={btoa(String.fromCharCode(...bytes))} encoding="base64" />);
    expect(screen.getByText(/Invalid UTF-8 or binary content/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Copy full text' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    const blob = createObjectURL.mock.calls[0][0] as Blob;
    expect(new Uint8Array(await blob.arrayBuffer())).toEqual(bytes);
  });
});
