import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { setBaseUrl, setProjectUUID, setToken } from '@/api/client';
import { ARTIFACT_BLOB_LIMIT, ARTIFACT_PREVIEW_BYTES } from '@/lib/runArtifacts';
import AgentRuntimeLogPanel from '../AgentRuntimeLogPanel';

const context = vi.hoisted(() => ({ projectUUID: 'project-a' as string | null }));
vi.mock('@/contexts/ProjectContext', () => ({ useProjectContext: () => context }));
const STRIDE = ARTIFACT_PREVIEW_BYTES - 3;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function bytePage(bytes: Uint8Array<ArrayBuffer>, total = bytes.length, offset = 0) {
  return new Response(bytes, { headers: {
    'X-Artifact-Total-Size': String(total), 'X-Artifact-Offset': String(offset),
    'X-Artifact-Returned-Bytes': String(bytes.length), 'X-Artifact-Truncated': offset > 0 || offset + bytes.length < total ? '1' : '0',
  } });
}
function page(text: string, total?: number, offset = 0) { const bytes = encoder.encode(text); return bytePage(bytes, total ?? bytes.length, offset); }
function serveFile(getBytes: () => Uint8Array<ArrayBuffer>) {
  vi.mocked(fetch).mockImplementation(async (input) => {
    const url = new URL(String(input));
    // Access must not depend on inventory pagination or go through /logs (the bounded tail).
    expect(url.pathname).toMatch(/\/artifacts\/runtime\.log$/);
    const bytes = getBytes();
    if (url.searchParams.has('download')) return bytePage(bytes);
    expect(url.searchParams.get('max_bytes')).toBe(String(ARTIFACT_PREVIEW_BYTES));
    const offset = Number(url.searchParams.get('offset'));
    return bytePage(bytes.slice(offset, offset + ARTIFACT_PREVIEW_BYTES), bytes.length, offset);
  });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { resolve, promise };
}
const view = (runUUID = 'run-a', theme: 'dark' | 'light' = 'dark') => <AgentRuntimeLogPanel runUUID={runUUID} theme={theme} />;
const visibleText = () => screen.getByLabelText('Runtime log text').textContent;
const waitText = (text: string) => waitFor(() => expect(visibleText()).toBe(text));

beforeEach(() => {
  context.projectUUID = 'project-a';
  setBaseUrl('https://api.example.invalid');
  setProjectUUID('different-persisted-project');
  setToken('fixture-secret');
  vi.stubGlobal('fetch', vi.fn());
  Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, writable: true, value: undefined });
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } });
});

for (const theme of ['dark', 'light'] as const) {
  describe(`${theme} full runtime.log`, () => {
    it('opens byte zero without inventory selection and renders complete long/multiline commands and results as pre text', async () => {
      const text = `tool rawbash arguments:\ncat <<'EOF'\n${'very-long-command-argument '.repeat(600)}\n<script>doNotExecute()</script>\nEOF\nresult:\nline one\nline two\nlegacy [summary already stored]\n`;
      vi.mocked(fetch).mockResolvedValueOnce(page(text));
      const { container } = render(view('run-a', theme));
      await waitText(text);
      const pre = screen.getByLabelText('Runtime log text');
      expect(pre.tagName).toBe('PRE');
      expect(pre.children).toHaveLength(0);
      expect(container.querySelector('script')).toBeNull();
      expect(pre).not.toHaveClass('truncate', 'line-clamp-3');
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(vi.mocked(fetch).mock.calls[0][0]).toContain('/run-a/artifacts/runtime.log?max_bytes=262144&offset=0');
      expect(vi.mocked(fetch).mock.calls[0][1]).toMatchObject({ cache: 'no-store', headers: { Authorization: 'Bearer fixture-secret', 'X-Project-UUID': 'project-a' } });
      expect(screen.getByLabelText('Runtime log byte range')).toHaveTextContent(`Bytes [0, ${encoder.encode(text).length.toLocaleString()})`);
      expect(screen.getByRole('button', { name: 'First' })).toBeDisabled();
      expect(screen.getByRole('button', { name: 'Prev' })).toBeDisabled();
      expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
      fireEvent.click(screen.getByRole('button', { name: 'Copy visible page' }));
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(text);
      expect(await screen.findByText('Visible page copied, not the full file.')).toBeInTheDocument();
    });

    it('navigates every record beyond 512 KiB with no missing lines or tool summaries added', async () => {
      const text = Array.from({ length: 9000 }, (_, i) => `record-${String(i).padStart(5, '0')}: command ${'argument '.repeat(7)}\n  result-${i}: complete output\n`).join('');
      const bytes = encoder.encode(text);
      expect(bytes.length).toBeGreaterThan(512 * 1024);
      serveFile(() => bytes);
      render(view('run-a', theme));
      let offset = 0;
      let reconstructed = '';
      let pages = 0;
      while (true) {
        const expected = decoder.decode(bytes.slice(offset, offset + ARTIFACT_PREVIEW_BYTES));
        await waitText(expected);
        reconstructed += pages === 0 ? expected : expected.slice(3);
        pages++;
        if (offset + ARTIFACT_PREVIEW_BYTES >= bytes.length) break;
        fireEvent.click(screen.getByRole('button', { name: 'Next' }));
        offset += STRIDE;
      }
      expect(reconstructed).toBe(text);
      expect(pages).toBeGreaterThan(2);
      expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
      expect(vi.mocked(fetch).mock.calls.some(([url]) => Number(new URL(String(url)).searchParams.get('offset')) > 512 * 1024)).toBe(true);
      expect(fetch).toHaveBeenCalledTimes(pages);
    });

    it('preserves a UTF-8 character split at the page boundary through the three-byte overlap', async () => {
      const bytes = encoder.encode(`${'a'.repeat(ARTIFACT_PREVIEW_BYTES - 2)}🙂\nresult: ñ漢字\n`);
      serveFile(() => bytes);
      render(view('run-a', theme));
      await waitText('a'.repeat(ARTIFACT_PREVIEW_BYTES - 2));
      expect(screen.getByLabelText('Runtime log text alignment')).toHaveTextContent('0 leading and 2 trailing bytes');
      expect(screen.queryByText(/Invalid UTF-8 or binary/)).not.toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: 'Next' }));
      await waitText('a🙂\nresult: ñ漢字\n');
      expect(screen.queryByText(/Invalid UTF-8 or binary/)).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Copy visible page' })).toBeEnabled();
    });

    it('supports First/Prev/Next/Latest and reload; Latest refreshes a growing file size', async () => {
      let bytes = encoder.encode('a'.repeat(ARTIFACT_PREVIEW_BYTES * 2) + 'old-last\n');
      serveFile(() => bytes);
      render(view('run-a', theme));
      await waitText('a'.repeat(ARTIFACT_PREVIEW_BYTES));
      fireEvent.click(screen.getByRole('button', { name: 'Next' }));
      await waitFor(() => expect(screen.getByLabelText('Runtime log byte range')).toHaveTextContent(`Bytes [${STRIDE.toLocaleString()},`));
      fireEvent.click(screen.getByRole('button', { name: 'Prev' }));
      await waitFor(() => expect(screen.getByLabelText('Runtime log byte range')).toHaveTextContent('Bytes [0,'));
      bytes = encoder.encode(decoder.decode(bytes) + 'new-last\n');
      fireEvent.click(screen.getByRole('button', { name: 'Latest' }));
      const last = bytes.length - ARTIFACT_PREVIEW_BYTES;
      await waitText(decoder.decode(bytes.slice(last)));
      expect(screen.getByLabelText('Runtime log byte range')).toHaveTextContent(`Bytes [${last.toLocaleString()}, ${bytes.length.toLocaleString()})`);
      expect(vi.mocked(fetch).mock.calls.at(-2)?.[0]).toContain('offset=0');
      expect(vi.mocked(fetch).mock.calls.at(-1)?.[0]).toContain(`offset=${last}`);
      bytes = encoder.encode(decoder.decode(bytes) + 'appended\n');
      fireEvent.click(screen.getByRole('button', { name: 'Reload page' }));
      await waitText(decoder.decode(bytes.slice(last, last + ARTIFACT_PREVIEW_BYTES)));
      expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
      fireEvent.click(screen.getByRole('button', { name: 'First' }));
      await waitFor(() => expect(screen.getByLabelText('Runtime log byte range')).toHaveTextContent('Bytes [0,'));
    });
  });
}

describe('explicit missing, binary, legacy and failed runtime logs', () => {
  it('does not fetch without an active project or selected run', () => {
    context.projectUUID = null;
    const { rerender } = render(view());
    expect(screen.getByText(/Runtime log access disabled: select an active project/)).toBeInTheDocument();
    context.projectUUID = 'project-a';
    rerender(view(''));
    expect(screen.getByText(/select a session or start a run/)).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([401, 403, 404, 503])('reports HTTP %s with no fallback project or invented old console data', async (status) => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ error_code: 'project_not_found' }), { status }));
    render(view());
    expect(await screen.findByRole('alert')).toHaveTextContent(`HTTP ${status}`);
    expect(screen.queryByLabelText('Runtime log text')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload page' })).toBeEnabled();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(context.projectUUID).toBe('project-a');
    expect(localStorage.getItem('vigolium_project_uuid')).toBe('different-persisted-project');
    expect(localStorage.getItem('vigolium_api_token')).toBe('fixture-secret');
  });

  it('clears the old page on a failed reload, then allows a local retry including an empty file', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(page('original')).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(page(''));
    render(view());
    await waitText('original');
    fireEvent.click(screen.getByRole('button', { name: 'Reload page' }));
    expect(screen.queryByLabelText('Runtime log text')).not.toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent('offline');
    fireEvent.click(screen.getByRole('button', { name: 'Reload page' }));
    expect(await screen.findByText('Empty runtime.log file.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('labels binary/invalid bytes, disables lossy copy and leaves byte download available', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(bytePage(Uint8Array.from([255, 0, 65, 10])));
    render(view());
    expect(await screen.findByText(/Invalid UTF-8 or binary\/control bytes/)).toBeInTheDocument();
    expect(visibleText()).toBe('�\0A\n');
    expect(screen.getByRole('button', { name: 'Copy visible page' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Download exact bytes' })).toBeEnabled();
  });

  it('reports legacy offsets as unavailable rather than treating the head as a full log', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('head', { headers: { 'X-Artifact-Total-Size': '900000', 'X-Artifact-Truncated': '1' } }));
    render(view());
    expect(await screen.findByText(/Server does not expose offset metadata/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Latest' })).toBeDisabled();
    expect(visibleText()).toBe('head');
  });

  it('refuses a repeated head from a server ignoring offsets and removes the previous page', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(page('head', 900000)).mockResolvedValueOnce(page('head', 900000));
    render(view());
    await waitText('head');
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/refusing a repeated head page/);
    expect(screen.queryByLabelText('Runtime log text')).not.toBeInTheDocument();
  });
});

describe('cancellation, identity resets and authenticated downloads', () => {
  it('reload remains active during pending reads, aborts them and ignores their late responses', async () => {
    const late = deferred<Response>();
    vi.mocked(fetch).mockReturnValueOnce(late.promise).mockResolvedValueOnce(page('reloaded'));
    render(view());
    const signal = vi.mocked(fetch).mock.calls[0][1]?.signal;
    fireEvent.click(screen.getByRole('button', { name: 'Reload page' }));
    expect(signal?.aborted).toBe(true);
    await waitText('reloaded');
    await act(async () => late.resolve(page('stale')));
    expect(visibleText()).toBe('reloaded');
  });

  it('aborts old project/run reads, clears old content immediately and restarts at byte zero', async () => {
    const oldProject = deferred<Response>();
    const oldRun = deferred<Response>();
    vi.mocked(fetch).mockReturnValueOnce(oldProject.promise).mockReturnValueOnce(oldRun.promise).mockResolvedValueOnce(page('new identity'));
    const { rerender } = render(view());
    const projectSignal = vi.mocked(fetch).mock.calls[0][1]?.signal;
    context.projectUUID = 'project-b';
    rerender(view());
    expect(projectSignal?.aborted).toBe(true);
    const runSignal = vi.mocked(fetch).mock.calls[1][1]?.signal;
    rerender(view('run-b'));
    expect(runSignal?.aborted).toBe(true);
    await waitText('new identity');
    await act(async () => { oldProject.resolve(page('old project')); oldRun.resolve(page('old run')); });
    expect(visibleText()).toBe('new identity');
    expect(vi.mocked(fetch).mock.calls[2][0]).toContain('/run-b/artifacts/runtime.log?max_bytes=262144&offset=0');
    expect(vi.mocked(fetch).mock.calls[2][1]?.headers).toMatchObject({ 'X-Project-UUID': 'project-b' });
    context.projectUUID = null;
    rerender(view('run-b'));
    expect(screen.queryByLabelText('Runtime log text')).not.toBeInTheDocument();
  });

  it.each(['project', 'run', 'unmount'] as const)('aborts a downloader on %s change and never saves its late response', async (change) => {
    const late = deferred<Response>();
    const createObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    vi.mocked(fetch).mockResolvedValueOnce(page('original')).mockReturnValueOnce(late.promise).mockResolvedValueOnce(page('new page'));
    const { rerender, unmount } = render(view());
    await waitText('original');
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    const signal = vi.mocked(fetch).mock.calls[1][1]?.signal;
    if (change === 'project') { context.projectUUID = 'project-b'; rerender(view()); }
    else if (change === 'run') rerender(view('run-b'));
    else unmount();
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByText('original', { exact: true })).not.toBeInTheDocument();
    await act(async () => late.resolve(page('original')));
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(screen.queryByText(/Complete response verified/)).not.toBeInTheDocument();
  });

  it('guards late file picker and clipboard callbacks after a project switch', async () => {
    const clipboard = deferred<void>();
    const picker = deferred<{ createWritable: () => Promise<never> }>();
    const createWritable = vi.fn();
    vi.mocked(navigator.clipboard.writeText).mockReturnValueOnce(clipboard.promise);
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: vi.fn(() => picker.promise) });
    vi.mocked(fetch).mockResolvedValueOnce(page('old page')).mockResolvedValueOnce(page('new page'));
    const { rerender } = render(view());
    await waitText('old page');
    fireEvent.click(screen.getByRole('button', { name: 'Copy visible page' }));
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    context.projectUUID = 'project-b';
    rerender(view());
    await act(async () => { clipboard.resolve(); picker.resolve({ createWritable }); });
    await waitText('new page');
    expect(createWritable).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(/Visible page copied|Complete response verified/)).not.toBeInTheDocument();
  });

  it('offers explicit download cancellation without claiming success', async () => {
    const late = deferred<Response>();
    vi.mocked(fetch).mockResolvedValueOnce(page('text')).mockReturnValueOnce(late.promise);
    render(view());
    await waitText('text');
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    const signal = vi.mocked(fetch).mock.calls[1][1]?.signal;
    fireEvent.click(screen.getByRole('button', { name: 'Cancel download' }));
    expect(signal?.aborted).toBe(true);
    expect(screen.getByText(/Download cancelled; no complete-file receipt/)).toBeInTheDocument();
    await act(async () => late.resolve(page('text')));
    expect(screen.queryByText(/Complete response verified/)).not.toBeInTheDocument();
  });

  it('verifies a small authenticated full download and never exposes an API link or secrets', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:fixture');
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    vi.mocked(fetch).mockResolvedValueOnce(page('head')).mockResolvedValueOnce(page('full'));
    const { container } = render(view());
    await waitText('head');
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    expect(await screen.findByText(/Complete response verified: 4 bytes. Browser download requested/)).toBeInTheDocument();
    expect(await (createObjectURL.mock.calls[0][0] as Blob).text()).toBe('full');
    expect(vi.mocked(fetch).mock.calls[1][0]).toContain('/artifacts/runtime.log?download=1');
    expect(vi.mocked(fetch).mock.calls[1][1]?.headers).toMatchObject({ Authorization: 'Bearer fixture-secret', 'X-Project-UUID': 'project-a' });
    expect(container.querySelectorAll('a')).toHaveLength(0);
    expect(container.textContent).not.toContain('fixture-secret');
  });

  it('refuses capped downloads and preserves paging when a huge download lacks streaming support', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(page('head', ARTIFACT_BLOB_LIMIT + 1));
    const { container } = render(view());
    await waitText('head');
    expect(screen.getByRole('button', { name: 'Download exact bytes' })).toBeDisabled();
    expect(screen.getByText(/Streaming download unsupported in this browser/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
    expect(container.textContent).toContain('${VIGOLIUM_PROJECT_UUID:?Set active project UUID}');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('keeps a visible page but reports download authorization failure without retrying another project', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(page('head')).mockResolvedValueOnce(new Response('', { status: 403 }));
    render(view());
    await waitText('head');
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/access denied.*HTTP 403/);
    expect(visibleText()).toBe('head');
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(localStorage.getItem('vigolium_project_uuid')).toBe('different-persisted-project');
    expect(screen.queryByText(/Complete response verified/)).not.toBeInTheDocument();
  });

  it('does not save a legacy truncated response as a complete download', async () => {
    const createObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    vi.mocked(fetch).mockResolvedValueOnce(page('head', 100)).mockResolvedValueOnce(page('head', 100));
    render(view());
    await waitText('head');
    fireEvent.click(screen.getByRole('button', { name: 'Download exact bytes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/truncated artifact, not a full download/);
    expect(createObjectURL).not.toHaveBeenCalled();
  });
});
