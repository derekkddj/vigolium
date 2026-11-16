'use client';

import { useMemo, useState, type ReactNode } from 'react';
import { boundedPreview, decodeHTTPBase64, type DecodedHTTP } from '@/lib/findingEvidence';
import { rawRequestToCurl } from '@/lib/curl';

export const evidencePalette = {
  dark: { text: '#fce8c3', muted: '#918175', border: '#2e2b26', background: '#141310', accent: '#68a8e4', warning: '#ff9e64' },
  light: { text: '#005661', muted: '#708e8e', border: '#bbc3c4', background: '#ede4d1', accent: '#0078c8', warning: '#a33d00' },
};
export type EvidenceTheme = keyof typeof evidencePalette;

interface Props {
  label: string;
  value?: string;
  encoding?: 'text' | 'base64';
  theme: EvidenceTheme;
  requestURLs?: string[];
  renderPreview?: (text: string) => ReactNode;
}

/** Only the preview is rendered. Downloads retain all fetched bytes, including invalid UTF-8. */
export default function HttpMessage({ label, value, encoding = 'text', theme, requestURLs, renderPreview }: Props) {
  const colors = evidencePalette[theme];
  const decoded = useMemo<DecodedHTTP>(() => value == null ? {} : encoding === 'base64'
    ? decodeHTTPBase64(value)
    : { text: value }, [value, encoding]);
  const preview = boundedPreview(decoded.text ?? '');
  const [copyState, setCopyState] = useState('');
  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyState('Copied');
    } catch {
      setCopyState('Copy failed; use download instead');
    }
  };
  const download = () => {
    const bytes = decoded.bytes ?? new TextEncoder().encode(decoded.text ?? '');
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${label.replace(/[^a-z0-9_-]/gi, '-')}.${encoding === 'base64' ? 'bin' : 'txt'}`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const buttonStyle = { borderColor: colors.border, color: colors.accent };

  return (
    <section className="space-y-1 text-xs" style={{ color: colors.text }} aria-label={label}>
      <div className="flex flex-wrap items-center gap-2">
        <span style={{ color: colors.muted }}>{label}:</span>
        {decoded.text !== undefined && !decoded.error && (
          <>
            <button className="border px-1.5 py-0.5" style={buttonStyle} onClick={() => void copy(decoded.text!)}>Copy full text</button>
            {requestURLs && <button className="border px-1.5 py-0.5" style={buttonStyle} onClick={() => void copy(rawRequestToCurl(decoded.text!, requestURLs))}>Copy curl</button>}
          </>
        )}
        {(decoded.bytes || decoded.text !== undefined) && <button className="border px-1.5 py-0.5" style={buttonStyle} onClick={download}>{encoding === 'base64' ? 'Download exact bytes' : 'Download full UTF-8 text'}</button>}
        {copyState && <span role="status">{copyState}</span>}
      </div>
      {decoded.error && <p role="status" style={{ color: colors.warning }}>{decoded.error}</p>}
      {value == null || value === '' ? <p style={{ color: colors.muted }}>Not stored / unavailable.</p> : decoded.text !== undefined && (
        <>
          {preview.truncated && <p style={{ color: colors.warning }}>Preview truncated to 64 Ki characters. Copy or download the full content above.</p>}
          <pre className="border p-2 overflow-x-auto whitespace-pre-wrap break-all max-h-64 overflow-y-auto" style={{ borderColor: colors.border, background: colors.background }}>{renderPreview ? renderPreview(preview.text) : preview.text}</pre>
        </>
      )}
    </section>
  );
}
