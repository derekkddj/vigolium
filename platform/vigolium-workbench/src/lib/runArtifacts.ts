import { buildApiUrl, buildAuthHeaders } from '@/api/client';

export const ARTIFACT_LIST_LIMIT = 500;
export const ARTIFACT_PREVIEW_BYTES = 256 * 1024;
export const ARTIFACT_BLOB_LIMIT = 16 * 1024 * 1024;
const LIST_BYTE_LIMIT = 4 * 1024 * 1024;

export interface RunArtifactScope { projectUUID: string; runUUID: string }
export interface RunArtifact { name: string; kind: string; size: number | null }
export interface RunArtifactList { artifacts: RunArtifact[]; truncated: boolean }
export interface ArtifactPage {
  text: string;
  binary: boolean;
  offset: number;
  returnedBytes: number;
  totalSize: number | null;
  truncated: boolean;
  offsetSupported: boolean;
  /** Only for overlapping text pages: incomplete UTF-8 edges are shown on the adjacent page. */
  utf8BoundaryBytes?: { leading: number; trailing: number };
}
export class ArtifactError extends Error {
  constructor(message: string, public status?: number) { super(message); this.name = 'ArtifactError'; }
}

const record = (value: unknown): Record<string, unknown> => value && typeof value === 'object' && !Array.isArray(value)
  ? value as Record<string, unknown> : {};
const sizeNumber = (value: unknown): number | null => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
const truthy = (value: unknown) => value === true || value === 'true' || value === '1' || value === 1;

export function parseRunArtifactList(body: unknown): RunArtifactList {
  const data = record(body);
  if (data.ok === false) throw new ArtifactError('Artifact listing failed.');
  const rows = Array.isArray(data.items) ? data.items : data.artifacts;
  if (!Array.isArray(rows)) throw new ArtifactError('Unsupported artifact listing response (expected artifacts or items).');
  const artifacts: RunArtifact[] = [];
  const seen = new Set<string>();
  for (const row of rows.slice(0, ARTIFACT_LIST_LIMIT)) {
    const item = record(row);
    if (typeof item.name !== 'string' || !item.name || seen.has(item.name)) continue;
    // Validate before making a URL: URL normalization must not escape this endpoint.
    artifactRelativePath(item.name);
    seen.add(item.name);
    artifacts.push({ name: item.name, kind: typeof item.kind === 'string' ? item.kind : 'unknown', size: sizeNumber(item.size) });
  }
  return { artifacts, truncated: rows.length > ARTIFACT_LIST_LIMIT || truthy(data.truncated) || truthy(data.has_more) || truthy(record(data.extra).truncated) };
}

const encodeSegment = (value: string) => encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
function artifactRelativePath(name: string): string {
  const segments = name.split('/');
  if (!name || name.includes('\\') || name.includes('\0') || segments.some((part) => !part || part === '.' || part === '..')) {
    throw new ArtifactError('Invalid relative artifact filename.');
  }
  return segments.map(encodeSegment).join('/');
}
export function runArtifactPath(runUUID: string, name?: string): string {
  if (!runUUID || runUUID === '.' || runUUID === '..') throw new ArtifactError('Missing or invalid run UUID.');
  const base = `/api/agent/sessions/${encodeSegment(runUUID)}/artifacts`;
  return name === undefined ? base : `${base}/${artifactRelativePath(name)}`;
}

function checkAbort(signal: AbortSignal) {
  if (signal.aborted) throw new DOMException('Artifact operation cancelled.', 'AbortError');
}
async function cancelBody(response: Response) {
  try { await response.body?.cancel(); } catch { /* already cancelled/closed */ }
}

/** Backpressure for disk writes; no unbounded arrayBuffer(), text(), or blob(). */
export async function consumeArtifactBody(
  response: Response, limit: number, signal: AbortSignal, write: (bytes: Uint8Array) => void | Promise<void>,
): Promise<number> {
  if (!Number.isSafeInteger(limit) || limit < 0) throw new ArtifactError('Invalid artifact byte limit.');
  if (signal.aborted) { await cancelBody(response); checkAbort(signal); }
  const reader = response.body?.getReader();
  if (!reader) return 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  let received = 0;
  try {
    while (true) {
      checkAbort(signal);
      const chunk = await reader.read();
      checkAbort(signal);
      if (chunk.done) break;
      if (chunk.value.byteLength > limit - received) throw new ArtifactError(`Artifact response exceeds the ${limit.toLocaleString()} byte limit; cancelled without saving a partial file.`);
      received += chunk.value.byteLength;
      await write(chunk.value);
      checkAbort(signal);
    }
    return received;
  } catch (error) {
    try { await reader.cancel(); } catch { /* transport already aborted */ }
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

export async function readBoundedArtifactBody(response: Response, limit: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  const parts: Uint8Array<ArrayBuffer>[] = [];
  const size = await consumeArtifactBody(response, limit, signal, (bytes) => { parts.push(new Uint8Array(bytes)); });
  checkAbort(signal);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
  return result;
}

async function artifactRequest(scope: RunArtifactScope, path: string, signal: AbortSignal): Promise<Response> {
  checkAbort(signal);
  if (!scope.projectUUID) throw new ArtifactError('Select a project to access run artifacts.');
  const headers = buildAuthHeaders({ path });
  // Never use request()/apiGet(): their project_not_found recovery can retry in another project.
  headers['X-Project-UUID'] = scope.projectUUID;
  const response = await fetch(buildApiUrl(path), { headers, signal, cache: 'no-store' });
  if (signal.aborted) { await cancelBody(response); checkAbort(signal); }
  if (!response.ok) {
    await cancelBody(response);
    const message = response.status === 401 || response.status === 403 ? 'Authentication required or access denied for artifacts in this project.'
      : response.status === 404 ? 'Run artifacts or the selected file are missing in the active project (the archive may have been removed).'
      : response.status === 503 ? 'Artifact storage is unavailable or disabled on this server.' : 'Artifact request failed.';
    throw new ArtifactError(`${message} (HTTP ${response.status})`, response.status);
  }
  return response;
}

export async function listRunArtifacts(scope: RunArtifactScope, signal: AbortSignal): Promise<RunArtifactList> {
  const response = await artifactRequest(scope, runArtifactPath(scope.runUUID), signal);
  const bytes = await readBoundedArtifactBody(response, LIST_BYTE_LIMIT, signal);
  checkAbort(signal);
  try { return parseRunArtifactList(JSON.parse(new TextDecoder().decode(bytes))); }
  catch (error) { if (error instanceof ArtifactError) throw error; throw new ArtifactError('Invalid artifact listing JSON.'); }
}

function numericHeader(headers: Headers, name: string): number | null {
  const raw = headers.get(name);
  if (raw === null) return null;
  if (!/^\d+$/.test(raw.trim())) throw new ArtifactError(`Invalid ${name} response metadata.`);
  const value = sizeNumber(Number(raw));
  if (value === null) throw new ArtifactError(`Invalid ${name} response metadata.`);
  return value;
}
function artifactMetadata(response: Response) {
  const flag = response.headers.get('X-Artifact-Truncated');
  if (flag !== null && !['0', '1', 'true', 'false'].includes(flag.toLowerCase())) throw new ArtifactError('Invalid artifact truncation metadata.');
  return {
    total: numericHeader(response.headers, 'X-Artifact-Total-Size'),
    offset: numericHeader(response.headers, 'X-Artifact-Offset'),
    returned: numericHeader(response.headers, 'X-Artifact-Returned-Bytes'),
    truncated: flag !== null && truthy(flag.toLowerCase()),
    // Content-Length is wire size when HTTP compression is used, not artifact size.
    length: response.headers.get('Content-Encoding') && response.headers.get('Content-Encoding') !== 'identity' ? null : numericHeader(response.headers, 'Content-Length'),
  };
}

/** Align only valid partial UTF-8 edges. Callers must overlap adjacent requests by 3 bytes.
 * Byte metadata remains the raw response range, not the length of the decoded text.
 * No lines/records are removed, and invalid interior bytes remain visibly lossy/binary.
 */
function overlappingUTF8Bounds(bytes: Uint8Array, offset: number, hasLater: boolean) {
  let leading = 0;
  if (offset > 0) {
    while (leading < Math.min(3, bytes.length) && (bytes[leading] & 0xc0) === 0x80) leading++;
  }
  let trailing = 0;
  if (hasLater && bytes.length > leading) {
    let start = bytes.length - 1;
    while (start > Math.max(leading, bytes.length - 4) && (bytes[start] & 0xc0) === 0x80) start--;
    const lead = bytes[start];
    const width = lead >= 0xc2 && lead <= 0xdf ? 2 : lead >= 0xe0 && lead <= 0xef ? 3 : lead >= 0xf0 && lead <= 0xf4 ? 4 : 1;
    if (bytes.length - start < width) {
      try {
        // stream=true accepts a valid incomplete suffix, but rejects malformed prefixes.
        new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(start), { stream: true });
        trailing = bytes.length - start;
      } catch { /* malformed bytes must still be displayed and labelled */ }
    }
  }
  return { leading, trailing };
}

export async function loadArtifactPage(
  scope: RunArtifactScope, artifact: RunArtifact, offset: number, signal: AbortSignal,
  options?: { overlapUTF8?: boolean },
): Promise<ArtifactPage> {
  if (sizeNumber(offset) === null) throw new ArtifactError('Invalid artifact page offset.');
  const path = `${runArtifactPath(scope.runUUID, artifact.name)}?max_bytes=${ARTIFACT_PREVIEW_BYTES}&offset=${offset}`;
  const response = await artifactRequest(scope, path, signal);
  try {
    const metadata = artifactMetadata(response);
    if ((metadata.offset !== null && metadata.offset !== offset) || (offset > 0 && metadata.offset === null)) {
      throw new ArtifactError('Server does not support the requested artifact offset; refusing a repeated head page. Upgrade the server for paging.');
    }
    if ((metadata.returned ?? metadata.length ?? 0) > ARTIFACT_PREVIEW_BYTES) throw new ArtifactError('Server ignored the 256 KiB preview cap; response cancelled.');
    const bytes = await readBoundedArtifactBody(response, ARTIFACT_PREVIEW_BYTES, signal);
    const totalSize = metadata.total ?? artifact.size;
    if ((metadata.returned !== null && metadata.returned !== bytes.byteLength) || (metadata.length !== null && metadata.length !== bytes.byteLength)
      || (totalSize !== null && offset + bytes.byteLength > totalSize)) {
      throw new ArtifactError('Artifact page size does not match response metadata/listing; refresh the archive.');
    }
    const hasLater = totalSize !== null ? offset + bytes.byteLength < totalSize : metadata.truncated || bytes.byteLength === ARTIFACT_PREVIEW_BYTES;
    const utf8BoundaryBytes = options?.overlapUTF8 ? overlappingUTF8Bounds(bytes, offset, hasLater) : undefined;
    const textBytes = utf8BoundaryBytes ? bytes.subarray(utf8BoundaryBytes.leading, bytes.length - utf8BoundaryBytes.trailing) : bytes;
    let binary = false;
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(textBytes); }
    catch { text = new TextDecoder('utf-8', { ignoreBOM: true }).decode(textBytes); binary = true; }
    binary ||= /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text);
    return { text, binary, offset, returnedBytes: bytes.byteLength, totalSize,
      truncated: metadata.truncated || offset > 0 || (totalSize !== null && bytes.byteLength < totalSize),
      offsetSupported: metadata.offset !== null,
      ...(utf8BoundaryBytes ? { utf8BoundaryBytes } : {}),
    };
  } catch (error) { await cancelBody(response); throw error; }
}

export interface ArtifactWritable {
  write: (bytes: Uint8Array) => Promise<void>;
  close: () => Promise<void>;
  abort: () => Promise<void>;
}
export type ArtifactSavePicker = (options: { suggestedName: string }) => Promise<{ createWritable: () => Promise<ArtifactWritable> }>;
export function artifactSavePicker(): ArtifactSavePicker | undefined {
  if (typeof window === 'undefined') return undefined;
  const picker = (window as unknown as { showSaveFilePicker?: ArtifactSavePicker }).showSaveFilePicker;
  return picker?.bind(window);
}
export function requiresStreamingDownload(size: number | null): boolean { return size !== null && size > ARTIFACT_BLOB_LIMIT; }

export interface ArtifactDownloadResult { receivedBytes: number; blob?: Blob; sizeChanged: boolean }
/** Complete receipt is verified before Blob creation or committing a streamed file. */
export async function downloadRunArtifact(
  scope: RunArtifactScope, artifact: RunArtifact, signal: AbortSignal, picker?: ArtifactSavePicker,
): Promise<ArtifactDownloadResult> {
  checkAbort(signal);
  if (!picker && requiresStreamingDownload(artifact.size)) throw new ArtifactError('Streaming download unsupported in this browser. Files above 16 MiB require a file save picker; use the scoped curl template below.');
  let writable: ArtifactWritable | undefined;
  let response: Response | undefined;
  const abortWrite = () => { void writable?.abort().catch(() => {}); };
  signal.addEventListener('abort', abortWrite, { once: true });
  try {
    // Must run before fetch (and its awaits) to preserve browser user activation.
    if (picker) {
      const handle = await picker({ suggestedName: artifact.name.split('/').at(-1)! });
      checkAbort(signal);
      writable = await handle.createWritable();
      checkAbort(signal);
    }
    response = await artifactRequest(scope, `${runArtifactPath(scope.runUUID, artifact.name)}?download=1`, signal);
    const metadata = artifactMetadata(response);
    // Legacy servers ignore download=1 and stream a capped head. Never save it as a full archive.
    if (metadata.truncated || (metadata.offset !== null && metadata.offset !== 0)) throw new ArtifactError('Server returned a truncated artifact, not a full download. Nothing saved; upgrade the server or retrieve the archive on the server.');
    const expected = metadata.total ?? artifact.size;
    if (expected === null) throw new ArtifactError('Full download cannot be verified: total size metadata and listing size are unavailable.');
    if ((metadata.returned !== null && metadata.returned !== expected) || (metadata.length !== null && metadata.length !== expected)) {
      throw new ArtifactError('Full download size metadata does not match; refusing a capped or changed file. Refresh the archive.');
    }
    if (!writable && expected > ARTIFACT_BLOB_LIMIT) throw new ArtifactError('Streaming download unsupported in this browser. Response exceeds the 16 MiB in-memory limit; use the scoped curl template below.');
    let receivedBytes: number;
    let blob: Blob | undefined;
    if (writable) {
      const sink = writable;
      receivedBytes = await consumeArtifactBody(response, expected, signal, (bytes) => sink.write(bytes));
      if (receivedBytes !== expected) throw new ArtifactError('Incomplete artifact download; received byte count does not match total size. Nothing saved.');
      checkAbort(signal);
      await sink.close();
      writable = undefined;
    } else {
      const bytes = await readBoundedArtifactBody(response, Math.min(expected, ARTIFACT_BLOB_LIMIT), signal);
      receivedBytes = bytes.byteLength;
      if (receivedBytes !== expected) throw new ArtifactError('Incomplete artifact download; received byte count does not match total size. Nothing saved.');
      checkAbort(signal);
      blob = new Blob([bytes], { type: 'application/octet-stream' });
    }
    checkAbort(signal);
    return { receivedBytes, blob, sizeChanged: artifact.size !== null && artifact.size !== expected };
  } catch (error) {
    if (response) await cancelBody(response);
    try { await writable?.abort(); } catch { /* never commit an incomplete write */ }
    throw error;
  } finally { signal.removeEventListener('abort', abortWrite); }
}

/** No credentials or configured URLs are interpolated into this template. */
export function artifactCurlTemplate(runUUID: string, name: string): string {
  const path = runArtifactPath(runUUID, name);
  return `# Set VIGOLIUM_API_URL, VIGOLIUM_TOKEN, VIGOLIUM_PROJECT_UUID and ARTIFACT_OUTPUT locally.
: "\${VIGOLIUM_API_URL:?Set API base URL}"
curl --fail --show-error \\
  -H "Authorization: Bearer \${VIGOLIUM_TOKEN:?Set token locally}" \\
  -H "X-Project-UUID: \${VIGOLIUM_PROJECT_UUID:?Set active project UUID}" \\
  --dump-header "\${ARTIFACT_OUTPUT:?Set output filename}.headers" \\
  --output "\${ARTIFACT_OUTPUT}" \\
  "\${VIGOLIUM_API_URL%/}${path}?download=1"
# Verify X-Artifact-Truncated: 0 and byte count against X-Artifact-Total-Size.
# Legacy servers may still return a capped head: do not treat it as a full archive.`;
}
