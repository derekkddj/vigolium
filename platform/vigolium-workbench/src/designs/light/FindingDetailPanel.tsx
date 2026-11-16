'use client';

import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import Prism from 'prismjs';
import 'prismjs/components/prism-markdown';
import { Eye, Code, Copy, Check, Link } from 'lucide-react';
import FindingEvidence, { FindingIdentity } from '@/components/shared/FindingEvidence';
import HttpRecordDetailPanel from './HttpRecordDetailPanel';
import { useFinding, useUpdateFindingStatus } from '@/api/hooks';
import { formatDate } from '@/lib/formatters';
import { boundedPreview } from '@/lib/findingEvidence';
import { detailSelectionHref } from '@/lib/detailSelection';
import Dropdown from './Dropdown';
import { SEVERITY_COLORS, CONFIDENCE_COLORS } from './theme';
import { FINDING_STATUSES } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';

const mdTokenStyles: Record<string, React.CSSProperties> = {
  title: { color: '#d55d00', fontWeight: 'bold' },
  bold: { color: '#8839ef', fontWeight: 'bold' },
  italic: { color: '#7c3aed', fontStyle: 'italic' },
  strike: { color: '#9ca0b0', textDecoration: 'line-through' },
  punctuation: { color: '#e64553' },
  'code-snippet': { color: '#40a02b', backgroundColor: '#e0d7c4', padding: '1px 4px', borderRadius: '2px' },
  code: { color: '#40a02b', backgroundColor: '#e0d7c4', padding: '1px 4px', borderRadius: '2px' },
  url: { color: '#1e66f5', textDecoration: 'underline' },
  'url-reference': { color: '#1e66f5' },
  blockquote: { color: '#179299' },
  'hr': { color: '#9ca0b0' },
  list: { color: '#d55d00' },
  'table-header': { color: '#1e66f5', fontWeight: 'bold' },
  'table-data-rows': { color: '#4c4f69' },
  'table-line': { color: '#9ca0b0' },
  important: { color: '#e64553', fontWeight: 'bold' },
};

function highlightMarkdown(code: string): string {
  // First pass: apply Prism token styles
  const html = Prism.highlight(code, Prism.languages.markdown, 'markdown');
  let styled = html;
  for (const [token, style] of Object.entries(mdTokenStyles)) {
    const styleStr = Object.entries(style)
      .map(([k, v]) => `${k.replace(/([A-Z])/g, '-$1').toLowerCase()}:${v}`)
      .join(';');
    styled = styled.replace(
      new RegExp(`class="token ${token}"`, 'g'),
      `style="${styleStr}"`
    );
  }
  // Second pass: highlight inline code (`...`) and fenced code blocks (```...```) that Prism markdown grammar doesn't fully tokenize
  // Fenced code blocks: ```lang\n...\n```
  styled = styled.replace(
    /(```\w*\n)([\s\S]*?)(```)/g,
    '<span style="color:#e64553">$1</span><span style="color:#40a02b;background:#e0d7c4;padding:2px 0;display:inline">$2</span><span style="color:#e64553">$3</span>'
  );
  // Inline code: `...`  (not already inside a styled span)
  styled = styled.replace(
    /(?<!<[^>]*)(`)((?:(?!`).)+)(`)/g,
    '<span style="color:#e64553">$1</span><span style="color:#40a02b;background:#e0d7c4;padding:1px 4px;border-radius:2px">$2</span><span style="color:#e64553">$3</span>'
  );
  return styled;
}

interface Props {
  findingId: number;
  onClose: () => void;
}

export default function FindingDetailPanel({ findingId, onClose }: Props) {
  const { data: finding, isLoading, isError } = useFinding(findingId);
  const updateStatus = useUpdateFindingStatus();
  const { toast } = useToast();
  const [descTab, setDescTab] = useState<'rendered' | 'raw'>('raw');
  const [copied, setCopied] = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const [copiedExtracted, setCopiedExtracted] = useState(false);
  const [matchedAtExpanded, setMatchedAtExpanded] = useState(false);

  return (
    <div className="border-l border-[#bbc3c4] bg-[#f6edda] h-full overflow-y-auto">
      <div className="px-3 py-1.5 border-b border-[#bbc3c4] flex items-center justify-between sticky top-0 bg-[#f6edda] z-10">
        <span className="text-[#0078c8] text-xs font-bold">FINDING #{findingId}</span>
        <div className="flex items-center gap-1">
          <button
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(new URL(detailSelectionHref('finding', findingId), window.location.origin).href);
                setLinkCopied(true);
                setTimeout(() => setLinkCopied(false), 2000);
              } catch {
                toast('Could not copy link', 'error');
              }
            }}
            className="text-[#708e8e] hover:text-[#0078c8] text-xs px-1"
            title="Copy link (active project; does not switch projects)"
          >
            {linkCopied ? <Check className="w-3 h-3" /> : <Link className="w-3 h-3" />}
          </button>
          <button onClick={onClose} className="text-[#708e8e] hover:text-[#e34e1c] text-xs px-1">[x]</button>
        </div>
      </div>

      {isLoading && (
        <div className="p-3 text-xs text-[#708e8e]">loading...</div>
      )}

      {isError && (
        <div className="p-3 text-xs text-[#e34e1c]">failed to load finding</div>
      )}

      {finding && (
        <div className="p-3 space-y-3 text-xs">
          <FindingIdentity finding={finding} theme="light" />
          {/* Severity + Confidence + Type + Source */}
          <div className="flex flex-wrap gap-x-3 gap-y-0.5">
            <div>
              <span className="text-[#708e8e]">severity: </span>
              <span className="font-bold uppercase" style={{ color: SEVERITY_COLORS[finding.severity] || '#708e8e' }}>
                {finding.severity}
              </span>
            </div>
            <div>
              <span className="text-[#708e8e]">confidence: </span>
              <span style={{ color: CONFIDENCE_COLORS[finding.confidence] || '#708e8e' }}>
                {finding.confidence}
              </span>
            </div>
            {finding.module_type && (
              <div><span className="text-[#708e8e]">type: </span><span className="text-[#0078c8]">{finding.module_type}</span></div>
            )}
            {finding.finding_source && (
              <div><span className="text-[#708e8e]">source: </span><span className="text-[#005661] font-semibold">{finding.finding_source}</span></div>
            )}
            <div className="flex items-center gap-1">
              <span className="text-[#708e8e]">status: </span>
              <Dropdown
                value={finding.status || 'draft'}
                options={FINDING_STATUSES.map((s) => ({ value: s, label: s }))}
                onChange={(next) => {
                  if (next === (finding.status || 'draft')) return;
                  updateStatus.mutate(
                    { id: finding.id, status: next },
                    {
                      onSuccess: () => toast(`status → ${next}`, 'success'),
                      onError: (err) => toast(`failed to update status: ${(err as Error).message}`, 'error'),
                    }
                  );
                }}
              />
            </div>
            {finding.cvss_score != null && finding.cvss_score > 0 && (
              <div><span className="text-[#708e8e]">cvss: </span><span className="text-[#005661] font-semibold">{finding.cvss_score}</span></div>
            )}
          </div>

          {/* Module */}
          <div className="text-[#005661] [&_code]:text-[#7d2a00] [&_code]:bg-[#e0d7c4] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_p]:inline">
            <span className="text-[#708e8e]">module: </span>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.module_name}</ReactMarkdown>
            <span className="text-[#bbc3c4]"> ({finding.module_id})</span>
          </div>

          {/* Module short description */}
          {finding.module_short && (
            <div className="text-[#708e8e] italic [&_code]:text-[#7d2a00] [&_code]:bg-[#e0d7c4] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_code]:not-italic [&_p]:inline">
              <span>module_short: </span>
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.module_short}</ReactMarkdown>
            </div>
          )}

          {/* Repo + Source file */}
          {(finding.repo_name || finding.source_file) && (
            <div className="space-y-0.5">
              {finding.repo_name && (
                <div><span className="text-[#708e8e]">repo: </span><span className="text-[#005661] font-semibold">{finding.repo_name}</span></div>
              )}
              {finding.source_file && (
                <div><span className="text-[#708e8e]">source_file: </span><span className="text-[#005661]">{finding.source_file}</span></div>
              )}
            </div>
          )}

          {/* Tags + Matched at + Metadata — compact block */}
          <div className="space-y-0.5">
            {finding.tags && finding.tags.length > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span className="text-[#708e8e]">tags:</span>
                {finding.tags.map((tag) => (
                  <span key={tag} className="px-1 py-px border border-[#bbc3c4] text-[#0078c8] text-[10px]">{tag}</span>
                ))}
              </div>
            )}
            {finding.matched_at && finding.matched_at.length > 0 && (() => {
              const MATCHED_AT_LIMIT = 20;
              const items = finding.matched_at!;
              const needsCollapse = items.length > MATCHED_AT_LIMIT;
              const visible = needsCollapse && !matchedAtExpanded ? items.slice(0, MATCHED_AT_LIMIT) : items;
              return (
                <div className="flex flex-wrap items-baseline gap-x-1">
                  <span className="text-[#708e8e]">matched_at: <span className="text-[#bbc3c4]">({items.length})</span></span>
                  <span className="text-[#005661] break-all">{visible.join(', ')}</span>
                  {needsCollapse && (
                    <button
                      onClick={() => setMatchedAtExpanded((v) => !v)}
                      className="text-[#0078c8] hover:underline text-[10px]"
                    >
                      {matchedAtExpanded ? `[collapse]` : `[+${items.length - MATCHED_AT_LIMIT} more]`}
                    </button>
                  )}
                </div>
              );
            })()}
            <div className="flex flex-wrap gap-x-3 text-[#708e8e]">
              <span>finding_hash: <span className="text-[#005661] break-all">{finding.finding_hash}</span></span>
              <span>found_at: <span className="text-[#005661]">{formatDate(finding.found_at)}</span></span>
            </div>
          </div>

          {/* Description */}
          {finding.description && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">description:</span>
                <div className="flex gap-0.5">
                  <button
                    onClick={() => setDescTab('rendered')}
                    className={`px-1.5 py-0.5 text-[10px] border ${descTab === 'rendered' ? 'border-[#0078c8] text-[#0078c8] bg-[#ede4d1]' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
                  >
                    <Eye size={10} className="inline-block mr-0.5 -mt-px" />rendered
                  </button>
                  <button
                    onClick={() => setDescTab('raw')}
                    className={`px-1.5 py-0.5 text-[10px] border ${descTab === 'raw' ? 'border-[#0078c8] text-[#0078c8] bg-[#ede4d1]' : 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]'}`}
                  >
                    <Code size={10} className="inline-block mr-0.5 -mt-px" />raw
                  </button>
                  <button
                    onClick={() => { navigator.clipboard.writeText(finding.description!); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
                    className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                  >
                    {copied ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                  </button>
                </div>
              </div>
              {boundedPreview(finding.description).truncated && <p className="text-[#708e8e] mb-1">Description preview truncated to 64 Ki characters; copy retains the full text.</p>}
              {descTab === 'rendered' ? (
                <div className={`bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto overflow-y-auto text-[#005661] ${finding.module_type === 'whitebox' ? 'max-h-[600px]' : 'max-h-64'} [&_p]:mb-1.5 [&_p]:leading-relaxed [&_h1]:text-sm [&_h1]:font-bold [&_h1]:text-[#005661] [&_h1]:mb-1.5 [&_h1]:mt-2 [&_h2]:text-xs [&_h2]:font-bold [&_h2]:text-[#005661] [&_h2]:mb-1 [&_h2]:mt-2 [&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-[#005661] [&_h3]:mb-1 [&_h3]:mt-1.5 [&_ul]:list-disc [&_ul]:pl-4 [&_ul]:mb-1.5 [&_ol]:list-decimal [&_ol]:pl-4 [&_ol]:mb-1.5 [&_li]:mb-0.5 [&_li]:leading-relaxed [&_a]:text-[#0078c8] [&_a]:underline [&_strong]:font-bold [&_strong]:text-[#005661] [&_em]:italic [&_code]:text-[#7d2a00] [&_code]:bg-[#e0d7c4] [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_pre]:bg-[#e0d7c4] [&_pre]:p-2 [&_pre]:rounded [&_pre]:overflow-x-auto [&_pre]:mb-1.5 [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_blockquote]:border-l-2 [&_blockquote]:border-[#708e8e] [&_blockquote]:pl-2 [&_blockquote]:text-[#708e8e] [&_blockquote]:mb-1.5 [&_hr]:border-[#bbc3c4] [&_hr]:my-2 [&_table]:w-full [&_table]:mb-1.5 [&_th]:border [&_th]:border-[#bbc3c4] [&_th]:px-1.5 [&_th]:py-0.5 [&_th]:text-left [&_td]:border [&_td]:border-[#bbc3c4] [&_td]:px-1.5 [&_td]:py-0.5`}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{boundedPreview(finding.description).text}</ReactMarkdown>
                </div>
              ) : (
                <pre
                  className={`bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all overflow-y-auto ${finding.module_type === 'whitebox' ? 'max-h-[600px]' : 'max-h-64'}`}
                  dangerouslySetInnerHTML={{ __html: highlightMarkdown(boundedPreview(finding.description).text) }}
                />
              )}
            </div>
          )}

          {/* Extracted results */}
          {finding.extracted_results && finding.extracted_results.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[#708e8e]">extracted_results:</span>
                <button
                  onClick={() => { navigator.clipboard.writeText(finding.extracted_results!.join('\n')); setCopiedExtracted(true); setTimeout(() => setCopiedExtracted(false), 1500); }}
                  className="px-1.5 py-0.5 text-[10px] border border-[#bbc3c4] text-[#708e8e] hover:text-[#005661]"
                >
                  {copiedExtracted ? <><Check size={10} className="inline-block mr-0.5 -mt-px" />copied!</> : <><Copy size={10} className="inline-block mr-0.5 -mt-px" />copy</>}
                </button>
              </div>
              <pre className="bg-[#ede4d1] border border-[#bbc3c4] p-2 overflow-x-auto text-[#005661] whitespace-pre-wrap break-all max-h-32 overflow-y-auto">
                {boundedPreview(finding.extracted_results.join('\n')).text}
                {boundedPreview(finding.extracted_results.join('\n')).truncated && '\n[Preview truncated; copy retains full results]'}
              </pre>
            </div>
          )}

          <FindingEvidence finding={finding} theme="light" RecordInspector={HttpRecordDetailPanel} />
        </div>
      )}
    </div>
  );
}
