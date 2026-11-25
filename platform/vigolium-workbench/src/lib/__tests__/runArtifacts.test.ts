import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getProjectUUID, setBaseUrl, setProjectUUID, setToken } from '@/api/client';
import {
  ARTIFACT_BLOB_LIMIT, ARTIFACT_PREVIEW_BYTES, artifactCurlTemplate, consumeArtifactBody, downloadRunArtifact,
  listRunArtifacts, loadArtifactPage, parseRunArtifactList, readBoundedArtifactBody, runArtifactPath,
  type ArtifactSavePicker, type ArtifactWritable, type RunArtifact,
} from '../runArtifacts';

const scope = { projectUUID: 'project-explicit', runUUID: 'run-fixture' };
const file: RunArtifact = { name: 'commands/results.jsonl', kind: 'jsonl', size: 4 };
const signal = () => new AbortController().signal;
const bytes = Uint8Array.from([0, 255, 65, 10]);
const pageHeaders = (total: number, offset: number, returned: number, truncated = offset > 0 || returned < total) => ({
  'X-Artifact-Total-Size': String(total), 'X-Artifact-Offset': String(offset),
  'X-Artifact-Returned-Bytes': String(returned), 'X-Artifact-Truncated': truncated ? '1' : '0',
});
function response(body: BodyInit | null, headers: Record<string, string> = {}) { return new Response(body, { headers }); }
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
function trackedBody(chunks: Uint8Array[], headers: Record<string, string> = {}) {
  const cancel = vi.fn();
  const stream = new ReadableStream<Uint8Array>({
    // Keep the producer open: cancellation of an already-closed stream does not call its source's cancel hook.
    pull(controller) { const chunk = chunks.shift(); if (chunk) controller.enqueue(chunk); }, cancel,
  });
  return { response: response(stream, headers), cancel };
}
function pickerFixture() {
  const sink: ArtifactWritable = { write: vi.fn().mockResolvedValue(undefined), close: vi.fn().mockResolvedValue(undefined), abort: vi.fn().mockResolvedValue(undefined) };
  const createWritable = vi.fn().mockResolvedValue(sink);
  const picker = vi.fn<ArtifactSavePicker>().mockResolvedValue({ createWritable });
  return { sink, createWritable, picker };
}

beforeEach(() => {
  setBaseUrl('https://api.example.invalid');
  setToken('local-fixture-secret');
  setProjectUUID('mutable-other-project');
  vi.stubGlobal('fetch', vi.fn());
});

for (const version of ['v1', 'v2'] as const) {
  it(`reads ${version} listing using authenticated explicit scope and no automatic project fallback`, async () => {
    vi.mocked(fetch).mockResolvedValue(response(JSON.stringify(version === 'v1' ? { artifacts: [file], truncated: true } : { ok: true, items: [file], has_more: true, truncated: true })));
    const result = await listRunArtifacts(scope, signal());
    expect(result).toEqual({ artifacts: [file], truncated: true });
    expect(fetch).toHaveBeenCalledWith('https://api.example.invalid/api/agent/sessions/run-fixture/artifacts', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer local-fixture-secret', 'X-Project-UUID': scope.projectUUID }), cache: 'no-store' }));
    expect(getProjectUUID()).toBe('mutable-other-project');
  });
}

describe('artifact listing and path validation', () => {
  it('bounds listing rows and honors v2 extra truncation metadata', () => {
    const rows = Array.from({ length: 501 }, (_, index) => ({ name: `${index}.log`, size: index, kind: 'log' }));
    expect(parseRunArtifactList({ items: rows }).artifacts).toHaveLength(500);
    expect(parseRunArtifactList({ items: rows }).truncated).toBe(true);
    expect(parseRunArtifactList({ items: [], extra: { truncated: true } }).truncated).toBe(true);
    expect(parseRunArtifactList({ artifacts: [{ name: 'unknown.bin' }] }).artifacts[0].size).toBeNull();
  });
  it('encodes each nested filename segment without treating query, fragment or encoded slashes as navigation', async () => {
    const name = "nested dir/ü #?%/'file.jsonl";
    expect(runArtifactPath('run fixture', name)).toBe('/api/agent/sessions/run%20fixture/artifacts/nested%20dir/%C3%BC%20%23%3F%25/%27file.jsonl');
    vi.mocked(fetch).mockResolvedValue(response('test', pageHeaders(4, 0, 4)));
    await loadArtifactPage(scope, { ...file, name }, 0, signal());
    const url = new URL(vi.mocked(fetch).mock.calls[0][0] as string);
    expect(url.search).toBe(`?max_bytes=${ARTIFACT_PREVIEW_BYTES}&offset=0`);
    expect(url.pathname).toContain('/nested%20dir/%C3%BC%20%23%3F%25/%27file.jsonl');
    expect(url.search).not.toContain('local-fixture-secret');
  });
  it.each(['../outside', '/absolute', 'nested/../file', 'a/./b', 'a\\b', 'a//b'])('rejects unsafe name %s before fetch', (name) => {
    expect(() => runArtifactPath(scope.runUUID, name)).toThrow(/Invalid relative/);
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([401, 403, 404, 503])('shows HTTP %s locally without changing global project/auth state', async (status) => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ error_code: 'project_not_found' }), { status }));
    await expect(listRunArtifacts(scope, signal())).rejects.toMatchObject({ status });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(getProjectUUID()).toBe('mutable-other-project');
    expect(localStorage.getItem('vigolium_api_token')).toBe('local-fixture-secret');
  });
  it('does not send unscoped requests for a missing project', async () => {
    await expect(listRunArtifacts({ ...scope, projectUUID: '' }, signal())).rejects.toThrow(/Select a project/);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('bounded byte previews', () => {
  it('uses offset metadata and marks even the last page as partial', async () => {
    vi.mocked(fetch).mockResolvedValue(response('tail', pageHeaders(ARTIFACT_PREVIEW_BYTES + 4, ARTIFACT_PREVIEW_BYTES, 4)));
    const page = await loadArtifactPage(scope, { ...file, size: ARTIFACT_PREVIEW_BYTES + 4 }, ARTIFACT_PREVIEW_BYTES, signal());
    expect(page).toMatchObject({ text: 'tail', offset: ARTIFACT_PREVIEW_BYTES, returnedBytes: 4, totalSize: ARTIFACT_PREVIEW_BYTES + 4, truncated: true, offsetSupported: true });
  });
  it('infers omission from total size even if legacy metadata claims false', async () => {
    vi.mocked(fetch).mockResolvedValue(response('head', { 'X-Artifact-Total-Size': '500000', 'X-Artifact-Truncated': '0' }));
    expect(await loadArtifactPage(scope, { ...file, size: 500000 }, 0, signal())).toMatchObject({ truncated: true, offsetSupported: false });
  });
  it('refuses legacy ignored offsets rather than repeating the head', async () => {
    const body = trackedBody([new TextEncoder().encode('head')]);
    vi.mocked(fetch).mockResolvedValue(body.response);
    await expect(loadArtifactPage(scope, file, 2, signal())).rejects.toThrow(/refusing a repeated head page/);
    expect(body.cancel).toHaveBeenCalled();
  });
  it('refuses a mismatched offset header', async () => {
    vi.mocked(fetch).mockResolvedValue(response('head', pageHeaders(10, 0, 4)));
    await expect(loadArtifactPage(scope, { ...file, size: 10 }, 4, signal())).rejects.toThrow(/requested artifact offset/);
  });
  it('cancels a legacy response that ignores max_bytes before reading an advertised large body', async () => {
    const body = trackedBody([new Uint8Array(1)], { 'Content-Length': String(10 * 1024 * 1024) });
    vi.mocked(fetch).mockResolvedValue(body.response);
    await expect(loadArtifactPage(scope, file, 0, signal())).rejects.toThrow(/ignored the 256 KiB/);
    expect(body.cancel).toHaveBeenCalled();
  });
  it('cancels an unadvertised cap mismatch and rejects inaccurate returned byte metadata', async () => {
    const body = trackedBody([new Uint8Array(ARTIFACT_PREVIEW_BYTES + 1)]);
    vi.mocked(fetch).mockResolvedValueOnce(body.response).mockResolvedValueOnce(response('head', pageHeaders(5, 0, 5)));
    await expect(loadArtifactPage(scope, { ...file, size: null }, 0, signal())).rejects.toThrow(/exceeds/);
    expect(body.cancel).toHaveBeenCalled();
    await expect(loadArtifactPage(scope, file, 0, signal())).rejects.toThrow(/size does not match/);
  });
  it('labels invalid UTF-8/binary and split boundaries without hiding the decoded page', async () => {
    vi.mocked(fetch).mockResolvedValue(response(bytes, pageHeaders(4, 0, 4)));
    expect(await loadArtifactPage(scope, file, 0, signal())).toMatchObject({ binary: true, text: '\0�A\n' });
  });
});

describe('overlapping UTF-8 text pages', () => {
  it.each(['ñ', '漢', '🙂'])('preserves split %s on an adjacent page without changing raw byte metadata', async (character) => {
    const all = new TextEncoder().encode(`${'x'.repeat(ARTIFACT_PREVIEW_BYTES - 1)}${character}\nresult\n`);
    const offset = ARTIFACT_PREVIEW_BYTES - 3;
    const head = all.slice(0, ARTIFACT_PREVIEW_BYTES);
    const next = all.slice(offset);
    vi.mocked(fetch).mockResolvedValueOnce(response(head, pageHeaders(all.length, 0, head.length))).mockResolvedValueOnce(response(next, pageHeaders(all.length, offset, next.length)));
    const first = await loadArtifactPage(scope, { ...file, size: null }, 0, signal(), { overlapUTF8: true });
    const second = await loadArtifactPage(scope, { ...file, size: null }, offset, signal(), { overlapUTF8: true });
    expect(first.text).toBe('x'.repeat(ARTIFACT_PREVIEW_BYTES - 1));
    expect(first.returnedBytes).toBe(ARTIFACT_PREVIEW_BYTES);
    expect(first.utf8BoundaryBytes).toEqual({ leading: 0, trailing: 1 });
    expect(first.binary).toBe(false);
    expect(second.binary).toBe(false);
    expect(second.text).toBe(`xx${character}\nresult\n`);
    expect(second.offset).toBe(offset);
  });

  it('keeps malformed interior bytes and a malformed EOF suffix visible and labelled binary', async () => {
    const invalid = Uint8Array.from([65, 255, 66, 0xf0, 0x9f]);
    vi.mocked(fetch).mockResolvedValueOnce(response(invalid, pageHeaders(invalid.length, 0, invalid.length)));
    const page = await loadArtifactPage(scope, { ...file, size: null }, 0, signal(), { overlapUTF8: true });
    expect(page).toMatchObject({ binary: true, text: 'A�B�', returnedBytes: invalid.length, utf8BoundaryBytes: { leading: 0, trailing: 0 } });
  });

  it('does not silently align away a malformed UTF-8 prefix at a non-final page end', async () => {
    const invalid = Uint8Array.from([65, 0xe0, 0x80]);
    vi.mocked(fetch).mockResolvedValueOnce(response(invalid, pageHeaders(100, 0, invalid.length)));
    const page = await loadArtifactPage(scope, { ...file, size: null }, 0, signal(), { overlapUTF8: true });
    expect(page.binary).toBe(true);
    expect(page.utf8BoundaryBytes?.trailing).toBe(0);
    expect(page.text).toContain('�');
  });
});

describe('verified exact-byte downloads', () => {
  it('creates a small bounded octet Blob with bytes unchanged and no offset/max_bytes query', async () => {
    vi.mocked(fetch).mockResolvedValue(response(bytes, pageHeaders(4, 0, 4)));
    const result = await downloadRunArtifact(scope, file, signal());
    expect(new Uint8Array(await result.blob!.arrayBuffer())).toEqual(bytes);
    expect(result).toMatchObject({ receivedBytes: 4, sizeChanged: false });
    expect(result.blob!.type).toBe('application/octet-stream');
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe('https://api.example.invalid/api/agent/sessions/run-fixture/artifacts/commands/results.jsonl?download=1');
  });
  it('can verify a small legacy download against known listing size without claiming a truncated head is full', async () => {
    vi.mocked(fetch).mockResolvedValue(response(bytes));
    expect((await downloadRunArtifact(scope, file, signal())).receivedBytes).toBe(4);
  });
  it('refuses legacy download=1 capped heads and aborts the file sink before commit', async () => {
    const { sink, picker } = pickerFixture();
    const body = trackedBody([bytes], { 'X-Artifact-Truncated': '1', 'X-Artifact-Total-Size': '20000000' });
    vi.mocked(fetch).mockResolvedValue(body.response);
    await expect(downloadRunArtifact(scope, file, signal(), picker)).rejects.toThrow(/truncated artifact, not a full download/);
    expect(sink.write).not.toHaveBeenCalled();
    expect(sink.close).not.toHaveBeenCalled();
    expect(sink.abort).toHaveBeenCalled();
    expect(body.cancel).toHaveBeenCalled();
  });
  it('refuses inconsistent metadata and incomplete receipt even when truncated flag is false', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(response(bytes, pageHeaders(10, 0, 4, false))).mockResolvedValueOnce(response(bytes, pageHeaders(10, 0, 10, false)));
    await expect(downloadRunArtifact(scope, file, signal())).rejects.toThrow(/size metadata does not match/);
    await expect(downloadRunArtifact(scope, file, signal())).rejects.toThrow(/Incomplete artifact download/);
  });
  it('rejects oversized known downloads without fetch when no streaming picker is available', async () => {
    await expect(downloadRunArtifact(scope, { ...file, size: ARTIFACT_BLOB_LIMIT + 1 }, signal())).rejects.toThrow(/Streaming download unsupported/);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('uses response size to reject oversized/unknown listings and cancels the response', async () => {
    const body = trackedBody([bytes], pageHeaders(ARTIFACT_BLOB_LIMIT + 1, 0, ARTIFACT_BLOB_LIMIT + 1));
    vi.mocked(fetch).mockResolvedValue(body.response);
    await expect(downloadRunArtifact(scope, { ...file, size: null }, signal())).rejects.toThrow(/16 MiB in-memory limit/);
    expect(body.cancel).toHaveBeenCalled();
  });
  it('rejects responses without any verifiable source size', async () => {
    vi.mocked(fetch).mockResolvedValue(response(bytes));
    await expect(downloadRunArtifact(scope, { ...file, size: null }, signal())).rejects.toThrow(/cannot be verified/);
  });
  it('streams large downloads to disk with bounded chunks/backpressure and only closes after verified receipt', async () => {
    const { sink, picker } = pickerFixture();
    const chunk = new Uint8Array(64 * 1024).fill(255);
    const total = 17 * 1024 * 1024;
    let remaining = total;
    const stream = new ReadableStream<Uint8Array>({ pull(controller) { if (!remaining) controller.close(); else { controller.enqueue(chunk); remaining -= chunk.byteLength; } } });
    vi.mocked(fetch).mockResolvedValue(response(stream, pageHeaders(total, 0, total)));
    const result = await downloadRunArtifact(scope, { ...file, size: total }, signal(), picker);
    expect(result).toEqual({ receivedBytes: total, sizeChanged: false, blob: undefined });
    expect(sink.write).toHaveBeenCalledTimes(total / chunk.byteLength);
    expect(vi.mocked(sink.write).mock.calls[0][0]).toBe(chunk);
    expect(sink.close).toHaveBeenCalledTimes(1);
    expect(sink.abort).not.toHaveBeenCalled();
  });
  it('aborts an incomplete disk stream and never closes it', async () => {
    const { sink, picker } = pickerFixture();
    vi.mocked(fetch).mockResolvedValue(response(bytes, pageHeaders(10, 0, 10)));
    await expect(downloadRunArtifact(scope, file, signal(), picker)).rejects.toThrow(/Incomplete/);
    expect(sink.abort).toHaveBeenCalled();
    expect(sink.close).not.toHaveBeenCalled();
  });
  it('ignores a save picker callback arriving after project/run cancellation', async () => {
    const handle = deferred<{ createWritable: () => Promise<ArtifactWritable> }>();
    const createWritable = vi.fn();
    const abort = new AbortController();
    const pending = downloadRunArtifact(scope, file, abort.signal, () => handle.promise);
    abort.abort();
    handle.resolve({ createWritable });
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(createWritable).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });
  it('outputs only an environment-variable scoped curl template, not credentials', () => {
    const template = artifactCurlTemplate(scope.runUUID, "nested/'#?file.bin");
    expect(template).toContain('${VIGOLIUM_TOKEN:?Set token locally}');
    expect(template).toContain('${VIGOLIUM_PROJECT_UUID:?Set active project UUID}');
    expect(template).toContain('/nested/%27%23%3Ffile.bin?download=1');
    expect(template).not.toContain('local-fixture-secret');
    expect(template).not.toContain('mutable-other-project');
    expect(template).toContain('Legacy servers may still return a capped head');
  });
});

describe('bounded readers and abort guards', () => {
  it('cancels and rejects oversized streams before retaining or writing the excessive chunk', async () => {
    const body = trackedBody([new Uint8Array(3), new Uint8Array(3)]);
    const write = vi.fn();
    await expect(consumeArtifactBody(body.response, 4, signal(), write)).rejects.toThrow(/exceeds/);
    expect(write).toHaveBeenCalledTimes(1);
    expect(body.cancel).toHaveBeenCalled();
  });
  it('enforces the 16 MiB fallback bound even for a lying response size', async () => {
    const body = trackedBody([new Uint8Array(ARTIFACT_BLOB_LIMIT + 1)], pageHeaders(ARTIFACT_BLOB_LIMIT, 0, ARTIFACT_BLOB_LIMIT));
    vi.mocked(fetch).mockResolvedValue(body.response);
    await expect(downloadRunArtifact(scope, { ...file, size: ARTIFACT_BLOB_LIMIT }, signal())).rejects.toThrow(/exceeds/);
    expect(body.cancel).toHaveBeenCalled();
  });
  it('cancels a blocked reader on abort and discards late read results', async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ pull() {}, cancel });
    const abort = new AbortController();
    const pending = readBoundedArtifactBody(response(stream), 4, abort.signal);
    abort.abort();
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(cancel).toHaveBeenCalled();
  });
  it('cancels a response arriving after fetch ignored its abort signal', async () => {
    const late = deferred<Response>();
    const abort = new AbortController();
    vi.mocked(fetch).mockReturnValue(late.promise);
    const pending = listRunArtifacts(scope, abort.signal);
    abort.abort();
    const body = trackedBody([bytes]);
    late.resolve(body.response);
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(body.cancel).toHaveBeenCalled();
  });
});
