import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setBaseUrl, setProjectUUID, setToken } from '@/api/client';
import { ARTIFACT_BLOB_LIMIT, ARTIFACT_PREVIEW_BYTES } from '@/lib/runArtifacts';
import AgentArtifactsPanel from '../AgentArtifactsPanel';
import { scrollOwners } from './scrollContract';

const context = vi.hoisted(() => ({ projectUUID: 'project-a' as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => context }));
const item = { name: 'commands/results.jsonl', kind: 'jsonl', size: 4 };
function list(items = [item], truncated = false, v2 = false) { return new Response(JSON.stringify(v2 ? { ok: true, items, truncated } : { artifacts: items, truncated })); }
function page(text: string, total = text.length, offset = 0, truncated = offset > 0 || text.length < total) {
  return new Response(text, { headers: { 'X-Artifact-Total-Size': String(total), 'X-Artifact-Offset': String(offset), 'X-Artifact-Returned-Bytes': String(text.length), 'X-Artifact-Truncated': truncated ? '1' : '0' } });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { resolve, promise };
}
const view = (runUUID = 'run-a', theme: 'dark' | 'light' = 'dark') => <AgentArtifactsPanel runUUID={runUUID} theme={theme} />;

beforeEach(() => {
  context.projectUUID = 'project-a';
  setBaseUrl('https://api.example.invalid');
  setProjectUUID('different-local-storage-project');
  setToken('test-secret');
  vi.stubGlobal('fetch', vi.fn());
  Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, writable: true, value: undefined });
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } });
});

for (const theme of ['dark', 'light'] as const) {
  describe(`${theme} artifacts`, () => {
    it('lists filenames, kinds and sizes; loads only the selected file in the explicit project', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(list([item, { name: 'runtime.log', kind: 'log', size: 4 }], true, theme === 'light')).mockResolvedValueOnce(page('head'));
      render(view('run-a', theme));
      expect(await screen.findByRole('button', { name: item.name })).toBeInTheDocument();
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(screen.getAllByText('4 bytes')).toHaveLength(2);
      expect(screen.getByText('jsonl')).toBeInTheDocument();
      expect(screen.getByText(/Artifact listing truncated at 500/)).toBeInTheDocument();
      expect(screen.getByText(/runtime.log is console output, not a guaranteed complete/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: item.name }));
      expect(await screen.findByText('head', { exact: true })).toBeInTheDocument();
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(vi.mocked(fetch).mock.calls[1][1]?.headers).toMatchObject({ 'X-Project-UUID': 'project-a', Authorization: 'Bearer test-secret' });
      expect(vi.mocked(fetch).mock.calls[1][0]).toContain('?max_bytes=262144&offset=0');
    });
    it('pages by returned byte counts, keeps partial warning on last page and copies only visible text', async () => {
      const size = ARTIFACT_PREVIEW_BYTES + 4;
      const head = 'x'.repeat(ARTIFACT_PREVIEW_BYTES);
      vi.mocked(fetch).mockResolvedValueOnce(list([{ ...item, size }])).mockResolvedValueOnce(page(head, size)).mockResolvedValueOnce(page('tail', size, ARTIFACT_PREVIEW_BYTES)).mockResolvedValueOnce(page(head, size));
      render(view('run-a', theme));
      fireEvent.click(await screen.findByRole('button', { name: item.name }));
      await waitFor(() => expect(screen.getByLabelText('Artifact content').textContent).toBe(head));
      fireEvent.click(screen.getByRole('button', { name: 'Later bytes' }));
      expect(await screen.findByText('tail', { exact: true })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Later bytes' })).toBeDisabled();
      expect(screen.getByText(/Partial preview — bytes have been omitted/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Copy visible page' }));
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith('tail');
      expect(await screen.findByText('Visible page copied (not the full file).')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Copy full/ })).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Earlier bytes' }));
      await waitFor(() => expect(screen.getByLabelText('Artifact content').textContent).toBe(head));
      expect(screen.getByText(/Partial preview — bytes have been omitted/)).toBeInTheDocument();
    });
    it('reports unsupported large downloads with a scoped secret-free template and no API anchor', async () => {
      const size = ARTIFACT_BLOB_LIMIT + 1;
      vi.mocked(fetch).mockResolvedValueOnce(list([{ ...item, size }])).mockResolvedValueOnce(page('head', size));
      render(view('run-a', theme));
      fireEvent.click(await screen.findByRole('button', { name: item.name }));
      expect(await screen.findByText('head', { exact: true })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Download exact bytes' })).toBeDisabled();
      expect(screen.getByText(/Streaming download unsupported in this browser/)).toBeInTheDocument();
      expect(screen.getByRole('dialog', { name: 'Run artifacts workspace' }).querySelectorAll('a')).toHaveLength(0);
      expect(screen.getByRole('dialog', { name: 'Run artifacts workspace' }).textContent).toContain('${VIGOLIUM_TOKEN:?Set token locally}');
      expect(screen.getByRole('dialog', { name: 'Run artifacts workspace' }).textContent).toContain('${VIGOLIUM_PROJECT_UUID:?Set active project UUID}');
      expect(screen.getByRole('dialog', { name: 'Run artifacts workspace' }).textContent).not.toContain('test-secret');
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });
}

for (const theme of ['dark', 'light'] as const) {
  describe(`${theme} compact inline artifact list`, () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ name: `file-${i}.TXT`, kind: 'text', size: 4 }));
    it('shows 12 files initially, expands to 30 and collapses without an inline scroll owner', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(list(many, true));
      render(view('run-a', theme));
      const table = await screen.findByRole('table', { name: 'Artifact files' });
      expect(within(table).getAllByRole('button')).toHaveLength(12);
      expect(scrollOwners(table)).toEqual([]);
      expect(screen.getByText(/Artifact listing truncated at 500/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Show all 30 files' }));
      expect(within(table).getAllByRole('button')).toHaveLength(30);
      fireEvent.click(screen.getByRole('button', { name: 'Show fewer files' }));
      expect(within(table).getAllByRole('button')).toHaveLength(12);
      expect(fetch).toHaveBeenCalledTimes(1);
    });
    it.each([1, 12])('omits the filter and expansion controls for %s files', async (count) => {
      vi.mocked(fetch).mockResolvedValueOnce(list(many.slice(0, count)));
      render(view('run-a', theme));
      const table = await screen.findByRole('table', { name: 'Artifact files' });
      expect(within(table).getAllByRole('button')).toHaveLength(count);
      expect(scrollOwners(table)).toEqual([]);
      expect(screen.queryByRole('searchbox', { name: 'Filter artifact files' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Show all|Show fewer/ })).not.toBeInTheDocument();
    });
    it('filters the entire listing case-insensitively and reuses the filter in the workspace', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(list(many)).mockResolvedValueOnce(page('head'));
      render(view('run-a', theme));
      await screen.findByRole('table', { name: 'Artifact files' });
      const filter = screen.getByRole('searchbox', { name: 'Filter artifact files' });
      fireEvent.change(filter, { target: { value: 'FILE-29.txt' } });
      fireEvent.click(screen.getByRole('button', { name: 'file-29.TXT' }));
      const dialog = screen.getByRole('dialog', { name: 'Run artifacts workspace' });
      await within(dialog).findByText('head', { exact: true });
      fireEvent.change(within(dialog).getByRole('searchbox', { name: 'Filter workspace artifact files' }), { target: { value: 'FiLe-28.TxT' } });
      const sidebar = within(dialog).getByRole('navigation', { name: 'Workspace artifact files' });
      expect(within(sidebar).getAllByRole('button')).toHaveLength(1);
      expect(within(sidebar).getByRole('button', { name: 'file-28.TXT' })).toBeInTheDocument();
      fireEvent.click(within(dialog).getByRole('button', { name: 'Close artifacts workspace' }));
      fireEvent.change(filter, { target: { value: 'does-not-exist' } });
      expect(screen.getByText('No artifact files match this filter.')).toBeInTheDocument();
      expect(within(screen.getByRole('table', { name: 'Artifact files' })).queryAllByRole('button')).toHaveLength(0);
      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });
}

for (const theme of ['dark', 'light'] as const) {
  describe(`${theme} controlled artifact selection`, () => {
    it('waits for the listing before opening a deep link and follows controlled close/file changes', async () => {
      const pending = deferred<Response>();
      const onSelectArtifact = vi.fn();
      vi.mocked(fetch).mockReturnValueOnce(pending.promise).mockResolvedValueOnce(page('head')).mockResolvedValueOnce(page('next'));
      const panel = (selectedArtifact: string | null) => <AgentArtifactsPanel runUUID="run-a" theme={theme} selectedArtifact={selectedArtifact} onSelectArtifact={onSelectArtifact} />;
      const { rerender } = render(panel(item.name));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(fetch).toHaveBeenCalledTimes(1);
      await act(async () => { pending.resolve(list([item, { name: 'second.txt', kind: 'text', size: 4 }])); });
      const dialog = await screen.findByRole('dialog');
      expect(await within(dialog).findByText('head', { exact: true })).toBeInTheDocument();
      fireEvent.click(within(dialog).getByRole('button', { name: 'second.txt' }));
      expect(onSelectArtifact).toHaveBeenLastCalledWith('second.txt');
      rerender(panel('second.txt'));
      expect(await screen.findByText('next', { exact: true })).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Close artifacts workspace' }));
      expect(onSelectArtifact).toHaveBeenLastCalledWith(null);
      rerender(panel(null));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(fetch).toHaveBeenCalledTimes(3);
    });
    it('does not read a deep link absent from the listing and reports the missing artifact', async () => {
      vi.mocked(fetch).mockResolvedValueOnce(list());
      render(<AgentArtifactsPanel runUUID="run-a" theme={theme} selectedArtifact="missing.txt" onSelectArtifact={vi.fn()} />);
      expect(await screen.findByText('Artifact not found in this run.')).toHaveAttribute('role', 'status');
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(fetch).toHaveBeenCalledTimes(1);
    });
  });
}

describe('identity resets and stale asynchronous work', () => {
  it('aborts project/run list requests and ignores responses from the old identity', async () => {
    const first = deferred<Response>();
    const second = deferred<Response>();
    vi.mocked(fetch).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise).mockResolvedValueOnce(list());
    const { rerender } = render(view());
    const oldSignal = vi.mocked(fetch).mock.calls[0][1]?.signal;
    context.projectUUID = 'project-b';
    rerender(view());
    expect(oldSignal?.aborted).toBe(true);
    const secondSignal = vi.mocked(fetch).mock.calls[1][1]?.signal;
    rerender(view('run-b'));
    expect(secondSignal?.aborted).toBe(true);
    await act(async () => { first.resolve(list([{ name: 'old-project-only.log', kind: 'log', size: 4 }])); second.resolve(list([{ name: 'old-run-only.log', kind: 'log', size: 4 }])); });
    expect(await screen.findByRole('button', { name: item.name })).toBeInTheDocument();
    expect(screen.queryByText('old-project-only.log')).not.toBeInTheDocument();
    expect(screen.queryByText('old-run-only.log')).not.toBeInTheDocument();
    expect(vi.mocked(fetch).mock.calls[2][1]?.headers).toMatchObject({ 'X-Project-UUID': 'project-b' });
  });
  it('immediately resets selected files on project/run changes and aborts stale preview reads', async () => {
    const latePage = deferred<Response>();
    vi.mocked(fetch).mockResolvedValueOnce(list()).mockReturnValueOnce(latePage.promise).mockResolvedValueOnce(list()).mockResolvedValueOnce(page('head')).mockResolvedValueOnce(list());
    const { rerender } = render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    const readSignal = vi.mocked(fetch).mock.calls[1][1]?.signal;
    context.projectUUID = 'project-b';
    rerender(view());
    expect(readSignal?.aborted).toBe(true);
    expect(screen.queryByRole('region', { name: 'Selected artifact' })).not.toBeInTheDocument();
    await act(async () => { latePage.resolve(page('late')); });
    expect(screen.queryByText('late', { exact: true })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    expect(await screen.findByText('head', { exact: true })).toBeInTheDocument();
    rerender(view('run-b'));
    expect(screen.queryByRole('region', { name: 'Selected artifact' })).not.toBeInTheDocument();
  });
  it('aborts an old selected-file fetch and ignores its late callback when another file is selected', async () => {
    const late = deferred<Response>();
    vi.mocked(fetch).mockResolvedValueOnce(list([item, { name: 'second.txt', kind: 'text', size: 4 }])).mockReturnValueOnce(late.promise).mockResolvedValueOnce(page('next'));
    render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    const oldSignal = vi.mocked(fetch).mock.calls[1][1]?.signal;
    fireEvent.click(within(screen.getByRole('dialog', { name: 'Run artifacts workspace' })).getByRole('button', { name: 'second.txt' }));
    expect(oldSignal?.aborted).toBe(true);
    expect(await screen.findByText('next', { exact: true })).toBeInTheDocument();
    await act(async () => { late.resolve(page('late')); });
    expect(screen.queryByText('late', { exact: true })).not.toBeInTheDocument();
  });
  it('guards late clipboard and save-picker callbacks after a project reset', async () => {
    const clipboard = deferred<void>();
    const picker = deferred<{ createWritable: () => Promise<never> }>();
    const createWritable = vi.fn();
    vi.mocked(navigator.clipboard.writeText).mockReturnValue(clipboard.promise);
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: vi.fn(() => picker.promise) });
    vi.mocked(fetch).mockResolvedValueOnce(list()).mockResolvedValueOnce(page('head')).mockResolvedValueOnce(list());
    const { rerender } = render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    await screen.findByText('head', { exact: true });
    fireEvent.click(screen.getByRole('button', { name: 'Copy visible page' }));
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    context.projectUUID = 'project-b';
    rerender(view());
    await act(async () => { clipboard.resolve(); picker.resolve({ createWritable }); });
    expect(createWritable).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(3); // no stale download request
    expect(screen.queryByText(/Complete response verified|Visible page copied/)).not.toBeInTheDocument();
  });
  it('aborts a download fetch on project switch and never creates a Blob URL for its late response', async () => {
    const lateDownload = deferred<Response>();
    const createObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    vi.mocked(fetch).mockResolvedValueOnce(list()).mockResolvedValueOnce(page('head')).mockReturnValueOnce(lateDownload.promise).mockResolvedValueOnce(list());
    const { rerender } = render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    await screen.findByText('head', { exact: true });
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    const downloadSignal = vi.mocked(fetch).mock.calls[2][1]?.signal;
    context.projectUUID = 'project-b';
    rerender(view());
    expect(downloadSignal?.aborted).toBe(true);
    await act(async () => { lateDownload.resolve(page('head')); });
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(screen.queryByText(/Complete response verified/)).not.toBeInTheDocument();
  });
});

describe('explicit unavailable, binary and error states', () => {
  it('does not fetch without a run or active project', () => {
    context.projectUUID = null;
    const { rerender } = render(view());
    expect(screen.getByText(/Artifact access disabled: select an active project/)).toBeInTheDocument();
    context.projectUUID = 'project-a';
    rerender(view(''));
    expect(screen.getByText(/Artifact access disabled: select a run/)).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });
  it('shows empty listing and disabled storage states with a local retry', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('', { status: 503 })).mockResolvedValueOnce(list([]));
    render(view());
    expect(await screen.findByRole('alert')).toHaveTextContent(/storage is unavailable or disabled/);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh artifacts' }));
    expect(await screen.findByText('No artifact files stored for this run.')).toBeInTheDocument();
  });
  it.each([401, 403, 404])('shows artifact HTTP %s visibly without resetting the project', async (status) => {
    vi.mocked(fetch).mockResolvedValueOnce(list()).mockResolvedValueOnce(new Response('', { status }));
    render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    expect(await screen.findByRole('alert')).toHaveTextContent(`HTTP ${status}`);
    expect(context.projectUUID).toBe('project-a');
    expect(localStorage.getItem('vigolium_project_uuid')).toBe('different-local-storage-project');
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('makes legacy paging unsupported and refuses a truncated download without a success claim', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(list([{ ...item, size: 100 }])).mockResolvedValueOnce(new Response('head', { headers: { 'X-Artifact-Truncated': '1', 'X-Artifact-Total-Size': '100' } })).mockResolvedValueOnce(new Response('head', { headers: { 'X-Artifact-Truncated': '1', 'X-Artifact-Total-Size': '100' } }));
    const createObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    expect(await screen.findByText(/Server does not expose offset metadata/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Later bytes' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/truncated artifact, not a full download/);
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(screen.queryByText(/Complete response verified/)).not.toBeInTheDocument();
  });
  it('labels invalid/binary content explicitly and disables lossy text copy', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(list()).mockResolvedValueOnce(new Response(Uint8Array.from([255, 0, 65, 10]), { headers: { 'X-Artifact-Total-Size': '4', 'X-Artifact-Offset': '0', 'X-Artifact-Returned-Bytes': '4', 'X-Artifact-Truncated': '0' } }));
    render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    expect(await screen.findByText(/Invalid UTF-8 or binary\/control bytes/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy visible page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Download exact bytes' })).toBeEnabled();
  });
  it('requests a verified small Blob download using an authenticated request, not an API anchor', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:fixture');
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    vi.mocked(fetch).mockResolvedValueOnce(list()).mockResolvedValueOnce(page('head')).mockResolvedValueOnce(page('full'));
    render(view());
    fireEvent.click(await screen.findByRole('button', { name: item.name }));
    await screen.findByText('head', { exact: true });
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    expect(await screen.findByText(/Complete response verified: 4 bytes. Browser download requested/)).toBeInTheDocument();
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(await (createObjectURL.mock.calls[0][0] as Blob).text()).toBe('full');
    expect(vi.mocked(fetch).mock.calls[2][1]?.headers).toMatchObject({ 'X-Project-UUID': 'project-a', Authorization: 'Bearer test-secret' });
  });
});
