'use client';

import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { Square, Send, Bot, Terminal, Clock, CheckCircle, XCircle, Loader2, Zap, Layers, Bug, ScrollText, Copy, Check, Upload, ChevronDown, Play, Settings2, Crosshair, Scale, ShieldCheck } from 'lucide-react';
import type { AgentSession, AgentSessionDetail } from '@/api/types';
import { agentStatusTone, type AgentStatusTone } from '@/api/types';
import { formatDate, formatDuration, truncate } from '@/lib/formatters';
import PageShell from './PageShell';
import Dropdown from './Dropdown';
import AgentArtifactsPanel from '@/components/shared/AgentArtifactsPanel';
import AgentRuntimeLogPanel from '@/components/shared/AgentRuntimeLogPanel';
import AgentRunContext, { formatAgentRunCount } from '@/components/shared/AgentRunContext';
import { useAgentsLogic, AGENT_OPTIONS, AUDIT_PREP_MODE_OPTIONS, INTENSITY_OPTIONS, AUDIT_MODE_OPTIONS, type DetectedInputType } from '@/hooks/useAgentsLogic';

const INPUT_TYPE_LABELS: Record<DetectedInputType, { label: string; color: string }> = {
  url: { label: 'URL', color: '#7fd962' },
  raw: { label: 'RAW REQUEST', color: '#68a8e4' },
  curl: { label: 'CURL', color: '#d8a657' },
  empty: { label: '', color: '#918175' },
};

const STATUS_ICON: Record<string, typeof CheckCircle> = {
  completed: CheckCircle,
  error: XCircle,
  running: Loader2,
};

const STATUS_TONE_COLOR: Record<AgentStatusTone, string> = {
  ok: '#7fd962', warn: '#f2c55c', fail: '#ef2f27', running: '#68a8e4', idle: '#918175',
};

function StatusBadge({ status }: { status: string }) {
  const Icon = STATUS_ICON[status] || Clock;
  const color = STATUS_TONE_COLOR[agentStatusTone(status)];
  return (
    <span className="flex items-center gap-1 text-xs font-bold" style={{ color }}>
      <Icon className={`w-3 h-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {status}
    </span>
  );
}

function tryPrettyJson(s: string | undefined): string {
  if (!s) return '';
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; }
}

function SessionDetailPanel({ session, onClose }: { session: AgentSessionDetail; onClose: () => void }) {
  const [copied, setCopied] = useState<string | null>(null);
  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 2000);
    });
  };

  return (
    <div className="border-t border-[#2e2b26] flex flex-col">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#2e2b26] shrink-0">
        <span className="text-xs font-bold text-[#7fd962]">SESSION DETAILS</span>
        <button aria-label="Close session details" onClick={onClose} className="text-[#918175] hover:text-[#fce8c3] text-xs font-bold px-1">&#10005;</button>
      </div>
      <div className="shrink-0 border-b border-[#2e2b26] px-3 py-2 text-xs space-y-1">
        <div className="text-[#68a8e4] font-mono break-all">{session.uuid}</div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">status </span><StatusBadge status={session.status} /></span>
          <span><span className="text-[#918175]">mode </span><span className="text-[#fce8c3]">{session.mode}</span></span>
          <span><span className="text-[#918175]">agent </span><span className="text-[#fce8c3]">{session.agent_name}</span></span>
          {session.input_type && <span><span className="text-[#918175]">input </span><span className="text-[#fce8c3]">{session.input_type}</span></span>}
        </div>
        {session.target_url && (
          <div><span className="text-[#918175]">target </span><span className="text-[#fce8c3] break-all">{session.target_url}</span></div>
        )}
        <div className="flex flex-wrap gap-x-4 gap-y-0.5" aria-label="Session summary counts">
          <span><span className="text-[#918175]">findings </span><span className="text-[#fce8c3]">{formatAgentRunCount(session.finding_count)}</span></span>
          <span><span className="text-[#918175]">records </span><span className="text-[#fce8c3]">{formatAgentRunCount(session.record_count)}</span></span>
          <span><span className="text-[#918175]">saved </span><span className="text-[#98bc37]">{formatAgentRunCount(session.saved_count)}</span></span>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-0.5">
          <span><span className="text-[#918175]">duration </span><span className="text-[#fce8c3]">{formatDuration(session.duration_ms)}</span></span>
          <span><span className="text-[#918175]">started </span><span className="text-[#fce8c3]">{formatDate(session.started_at)}</span></span>
          {session.completed_at && <span><span className="text-[#918175]">completed </span><span className="text-[#fce8c3]">{formatDate(session.completed_at)}</span></span>}
        </div>
        {session.phases_run && session.phases_run.length > 0 && (
          <div><span className="text-[#918175]">phases </span><span className="text-[#fce8c3]">{session.phases_run.join(' \u2192 ')}</span></div>
        )}
        {session.error_message && (
          <div className="whitespace-pre-wrap break-words" style={{ color: STATUS_TONE_COLOR[agentStatusTone(session.status) === 'fail' ? 'fail' : 'warn'] }}>
            <span className="font-bold">{agentStatusTone(session.status) === 'fail' ? 'error ' : 'warnings '}</span>{session.error_message}
          </div>
        )}
        {session.module_names && session.module_names.length > 0 && (
          <div><span className="text-[#918175]">modules </span><span className="text-[#fce8c3]">{session.module_names.join(', ')}</span></div>
        )}
      </div>
      <div className="text-xs">
        <AgentRunContext session={session} theme="dark" />
        <AgentArtifactsPanel runUUID={session.uuid} theme="dark" />
        {session.prompt_sent && (
          <details className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <Terminal className="w-3 h-3" />PROMPT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(session.prompt_sent!, 'prompt')} className="absolute top-1.5 right-2 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'prompt' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <pre className="px-3 py-2 bg-[#141310] text-[#fce8c3] whitespace-pre-wrap break-all font-mono overflow-x-auto">{session.prompt_sent}</pre>
            </div>
          </details>
        )}
        {session.agent_raw_output && (
          <details open className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <ScrollText className="w-3 h-3" />RETAINED CONSOLE SNAPSHOT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(session.agent_raw_output!, 'output')} className="absolute top-1.5 right-2 z-10 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'output' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              {/* ANSI-stripped terminal output, not Markdown: parsing up to 200 KB
                  of it on every re-render stalled the page. */}
              <pre className="px-3 py-2 bg-[#141310] text-[#fce8c3] whitespace-pre-wrap break-words font-mono overflow-x-auto">{session.agent_raw_output}</pre>
            </div>
          </details>
        )}
        {session.attack_plan && (
          <details open className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <Zap className="w-3 h-3" />ATTACK PLAN
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(tryPrettyJson(session.attack_plan), 'plan')} className="absolute top-1.5 right-2 z-10 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'plan' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <div className="px-3 py-2 bg-[#141310] text-[#fce8c3] overflow-x-auto prose prose-xs prose-invert max-w-none [&_pre]:bg-[#0c0b09] [&_pre]:p-2 [&_pre]:text-xs [&_pre]:rounded [&_code]:text-[#98bc37] [&_p]:m-0 [&_p]:mb-1.5 [&_h1]:text-sm [&_h2]:text-sm [&_h3]:text-xs [&_h1]:mt-2 [&_h2]:mt-2 [&_h3]:mt-1 [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0">
                <ReactMarkdown>{tryPrettyJson(session.attack_plan)}</ReactMarkdown>
              </div>
            </div>
          </details>
        )}
        {session.triage_result && (
          <details className="border-b border-[#2e2b26]">
            <summary className="px-3 py-1.5 cursor-pointer text-[#7fd962] font-bold hover:bg-[#2e2b26] flex items-center gap-1.5">
              <Bug className="w-3 h-3" />TRIAGE RESULT
            </summary>
            <div className="relative">
              <button onClick={() => copyToClipboard(tryPrettyJson(session.triage_result), 'triage')} className="absolute top-1.5 right-2 text-[#918175] hover:text-[#fce8c3] p-0.5" title="Copy to clipboard">
                {copied === 'triage' ? <Check className="w-3.5 h-3.5 text-[#98bc37]" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
              <pre className="px-3 py-2 bg-[#141310] text-[#fce8c3] whitespace-pre-wrap break-all font-mono overflow-x-auto">{tryPrettyJson(session.triage_result)}</pre>
            </div>
          </details>
        )}
      </div>
    </div>
  );
}

export default function AgentsPage() {
  const h = useAgentsLogic();

  const inputClass = 'bg-[#141310] border border-[#2e2b26] text-[#fce8c3] text-xs px-2 py-1 focus:outline-none focus:border-[#7fd962]/50 w-full';
  const modeBtnClass = (active: boolean) =>
    `px-3 py-0.5 text-xs font-bold transition-colors ${active ? 'text-[#7fd962] bg-[#7fd962]/10' : 'text-[#918175] hover:text-[#fce8c3]'}`;

  return (
    <PageShell>
      <div className="flex flex-col flex-1 min-h-0" style={{ minHeight: 500 }}>

        {/* ── Top: Config (full width) ── */}
        <div className="shrink-0 border border-[#2e2b26] bg-[#1c1b19] flex flex-col overflow-hidden">
          {/* Header with scan button */}
          <div className="px-3 py-2 border-b border-[#2e2b26] shrink-0 flex items-center justify-between">
            <h2 className="text-[#7fd962] text-xs font-bold tracking-wide">AGENTIC SCAN</h2>
            {h.isScanStreaming && (
              <span className="text-xs text-[#68a8e4] flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" /> streaming...</span>
            )}
          </div>

          <div className="overflow-y-auto px-3 py-2 space-y-3">
            {/* Target + GitHub/Upload — same row */}
            <div className="grid grid-cols-3 gap-2 items-stretch">
              {/* Target input — 2/3 */}
              <div className="col-span-2 flex flex-col">
                <div className="flex items-center gap-1.5 mb-0.5" style={{ minHeight: '1.25rem' }}>
                  <button
                    onClick={() => h.setTargetInputTab('target')}
                    className={`text-xs font-bold transition-colors ${h.targetInputTab === 'target' ? 'text-[#7fd962]' : 'text-[#918175] hover:text-[#fce8c3]'}`}
                  >Target</button>
                  <span className="text-[#2e2b26]">|</span>
                  <button
                    onClick={() => h.setTargetInputTab('prompt')}
                    className={`text-xs font-bold transition-colors flex items-center gap-1 ${h.targetInputTab === 'prompt' ? 'text-[#7fd962]' : 'text-[#918175] hover:text-[#fce8c3]'}`}
                  ><Crosshair className="w-3 h-3" />Prompt</button>
                  {h.targetInputTab === 'target' ? (
                    <span className="text-[10px]" style={{ color: INPUT_TYPE_LABELS[h.detectedInputType].color }}>
                      (type: {h.detectedInputType === 'empty' ? 'url' : h.detectedInputType === 'raw' ? 'raw request' : h.detectedInputType})
                    </span>
                  ) : (
                    <span className="text-[10px] text-[#d8a657]">(type: natural language)</span>
                  )}
                </div>
                {h.targetInputTab === 'target' ? (
                  <>
                    <textarea
                      value={h.targetUrl}
                      onChange={(e) => h.setTargetUrl(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey && h.detectedInputType === 'url') {
                          e.preventDefault();
                          h.handleProfileSubmit();
                        }
                      }}
                      placeholder={"https://example.com/api/endpoint\n\nor paste a raw HTTP request / curl command"}
                      rows={Math.max(4, Math.min(20, h.targetUrl.split('\n').length + 1))}
                      className={`${inputClass} !text-xs !py-1.5 font-mono resize-y whitespace-pre-wrap break-all flex-1`}
                    />
                    {h.scanError && <p className="text-xs text-[#ef2f27] mt-1">{h.scanError}</p>}
                  </>
                ) : (
                  <>
                    <textarea
                      value={h.targetPrompt}
                      onChange={(e) => h.setTargetPrompt(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          h.handleTargetSubmit();
                        }
                      }}
                      placeholder="scan localhost:3000 for auth bypass"
                      rows={Math.max(4, Math.min(20, h.targetPrompt.split('\n').length + 1))}
                      className={`${inputClass} !text-xs !py-1.5 font-mono resize-y whitespace-pre-wrap break-all flex-1`}
                    />
                    {h.targetError && <p className="text-xs text-[#ef2f27] mt-1">{h.targetError}</p>}
                    {h.targetRunStatus?.error && <p className="text-xs text-[#ef2f27] mt-1">{h.targetRunStatus.error}</p>}
                  </>
                )}
              </div>
              {/* Source upload — 1/3 */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[#918175] text-xs mb-0.5">Source Code</label>
                <div
                  onDragEnter={h.onUploadDragEnter} onDragLeave={h.onUploadDragLeave} onDragOver={h.onUploadDragOver} onDrop={h.onUploadDrop}
                  className={`border border-dashed p-2 text-center transition-colors flex-1 flex flex-col items-center justify-center gap-0.5 ${h.uploadCompressing || h.uploadRepo.isPending ? '' : 'cursor-pointer'} ${h.uploadDragging ? 'border-[#7fd962] bg-[#7fd962]/10' : h.activeSource ? 'border-[#98bc37] bg-[#98bc37]/5' : 'border-[#2e2b26] hover:border-[#7fd962]/50'}`}
                  onClick={() => { if (!h.uploadCompressing && !h.uploadRepo.isPending) h.uploadFileInputRef.current?.click(); }}
                >
                  <input ref={h.uploadFileInputRef} type="file" accept=".zip,.tar.gz,.tgz,.tar" onChange={h.handleFileUpload} className="hidden" />
                  {h.uploadCompressing || h.uploadRepo.isPending ? (
                    <div className="flex items-center justify-center gap-1.5"><Loader2 className="w-3.5 h-3.5 text-[#7fd962] animate-spin" /><span className="text-[10px] text-[#fce8c3]">{h.uploadCompressing ? 'Compressing...' : 'Uploading...'}</span></div>
                  ) : (
                    <div className="flex items-center justify-center gap-1.5"><Upload className="w-3.5 h-3.5 text-[#7fd962]/70" /><span className="text-[10px] text-[#fce8c3]">{h.uploadDragging ? 'Drop here' : 'Upload source code'}</span></div>
                  )}
                  <p className="text-[9px] text-[#918175]">.zip, .tar.gz, folder — max 500 MB</p>
                  {h.activeSource && (
                    <p className="text-[9px] text-[#918175] truncate max-w-full px-2" title={h.activeSource.includes('x-access-token') ? 'Authenticated clone URL' : h.activeSource}>
                      {h.activeSource.includes('x-access-token') ? h.activeSource.replace(/https:\/\/x-access-token:[^@]+@/, 'https://') : h.activeSource}
                    </p>
                  )}
                  {h.uploadRepo.isSuccess && <p className="text-[9px] text-[#98bc37]">uploaded</p>}
                  {h.uploadRepo.isError && <p className="text-[9px] text-[#ef2f27]">failed</p>}
                </div>
              </div>
            </div>

            {/* Scanning Mode */}
            <div>
              <label className="text-[#918175] text-xs block mb-1">Scanning Mode</label>
              {/* Top-level mode selector */}
              <div className="grid grid-cols-3 gap-0">
                <button
                  onClick={() => h.setScanProfile('autopilot')}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile === 'autopilot'
                      ? 'border-[#6bb856] bg-[#6bb856]/8'
                      : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <Bot className={`w-3 h-3 ${h.scanProfile === 'autopilot' ? 'text-[#6bb856]' : 'text-[#918175]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile === 'autopilot' ? 'text-[#6bb856]' : 'text-[#fce8c3]'}`}>AUTOPILOT</span>
                  </div>
                  <p className="text-[10px] text-[#706560] leading-tight">AI agent drives the CLI autonomously — explores, scans, and iterates on findings.</p>
                </button>
                <button
                  onClick={() => { if (h.scanProfile !== 'quick') h.setScanProfile('quick'); }}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile === 'quick'
                      ? 'border-[#6bb856] bg-[#6bb856]/8'
                      : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <Bug className={`w-3 h-3 ${h.scanProfile === 'quick' ? 'text-[#6bb856]' : 'text-[#918175]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile === 'quick' ? 'text-[#6bb856]' : 'text-[#fce8c3]'}`}>SWARM</span>
                  </div>
                  <p className="text-[10px] text-[#706560] leading-tight">AI-guided targeted vulnerability scan with module selection.</p>
                </button>
                <button
                  onClick={() => h.setScanProfile('audit')}
                  className={`px-3 py-2 text-center border transition-colors ${
                    h.scanProfile === 'audit'
                      ? 'border-[#6bb856] bg-[#6bb856]/8'
                      : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                  }`}
                >
                  <div className="flex items-center justify-center gap-1.5 mb-0.5">
                    <ShieldCheck className={`w-3 h-3 ${h.scanProfile === 'audit' ? 'text-[#6bb856]' : 'text-[#918175]'}`} />
                    <span className={`text-xs font-bold ${h.scanProfile === 'audit' ? 'text-[#6bb856]' : 'text-[#fce8c3]'}`}>AUDIT</span>
                  </div>
                  <p className="text-[10px] text-[#706560] leading-tight">Thorough source-code security audit driven by the piolium harness.</p>
                </button>
              </div>
            </div>

            {/* Intensity */}
            <div>
              <label className="text-[#918175] text-xs block mb-1">Scan Intensity Level</label>
              <div className="grid grid-cols-3 gap-0">
                {INTENSITY_OPTIONS.filter((o) => o.value !== '').map((o) => {
                  const currentIntensity = h.scanProfile === 'autopilot' ? h.autopilotIntensity : h.scanProfile === 'audit' ? h.auditIntensity : h.swarmIntensity;
                  const active = currentIntensity === o.value || (!currentIntensity && o.value === 'balanced');
                  const Icon = o.icon === 'zap' ? Zap : o.icon === 'scale' ? Scale : Layers;
                  return (
                    <button
                      key={o.value}
                      onClick={() => { h.setSwarmIntensity(o.value); h.setAutopilotIntensity(o.value); h.setAuditIntensity(o.value); }}
                      className={`px-3 py-2 text-center border transition-colors ${
                        active
                          ? 'border-[#68a8e4] bg-[#68a8e4]/10'
                          : 'border-[#2e2b26] hover:border-[#918175] hover:bg-[#2e2b26]/30'
                      }`}
                    >
                      <div className="flex items-center justify-center gap-1.5 mb-0.5">
                        <Icon className={`w-3 h-3 ${active ? 'text-[#68a8e4]' : 'text-[#918175]'}`} />
                        <span className={`text-xs font-bold ${active ? 'text-[#68a8e4]' : 'text-[#fce8c3]'}`}>{o.label}</span>
                      </div>
                      {o.description && <p className="text-[10px] text-[#706560] leading-tight">{o.description}</p>}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Start Scan / Stop + Advanced toggle */}
            <div className="flex items-center gap-2">
              {h.targetInputTab === 'prompt' ? (
                <button
                  onClick={h.handleTargetSubmit}
                  disabled={!h.targetPrompt.trim() || h.startAutopilotRun.isPending}
                  className="px-4 py-1 text-xs font-bold border border-[#FF9F2F] text-[#FF9F2F] bg-[#FF9F2F]/10 hover:bg-[#FF9F2F]/20 shadow-[inset_0_0_18px_rgba(255,159,47,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,159,47,0.7)] transition-colors disabled:opacity-30 flex items-center gap-1.5"
                >
                  {h.startAutopilotRun.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                  {h.startAutopilotRun.isPending ? 'SUBMITTING...' : 'START SCAN'}
                </button>
              ) : !h.isScanStreaming ? (
                <button
                  onClick={h.handleProfileSubmit}
                  disabled={h.scanProfile === 'audit' ? !h.activeSource : (!h.targetUrl.trim() && !h.activeSource)}
                  className="px-4 py-1 text-xs font-bold border border-[#FF9F2F] text-[#FF9F2F] bg-[#FF9F2F]/10 hover:bg-[#FF9F2F]/20 shadow-[inset_0_0_18px_rgba(255,159,47,0.5)] hover:shadow-[inset_0_0_28px_rgba(255,159,47,0.7)] transition-colors disabled:opacity-30 flex items-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5" /> START SCAN
                </button>
              ) : (
                <button
                  onClick={h.handleScanCancel}
                  className="px-4 py-1 text-xs font-bold bg-[#ef2f27]/10 text-[#ef2f27] border border-[#ef2f27]/30 hover:bg-[#ef2f27]/20 transition-colors flex items-center gap-1.5"
                >
                  <Square className="w-3 h-3" /> STOP
                </button>
              )}
              <button
                onClick={() => h.setShowAdvanced(!h.showAdvanced)}
                className={`px-3 py-1 text-xs font-bold border flex items-center gap-1 transition-colors ${
                  h.showAdvanced
                    ? 'border-[#918175] bg-[#918175]/10 text-[#918175]'
                    : 'border-[#2e2b26] text-[#706560] hover:border-[#918175] hover:text-[#918175]'
                }`}
              >
                <Settings2 className="w-3 h-3" /> ADVANCED
              </button>
              {h.targetInputTab === 'prompt' && h.targetRunId && h.targetRunStatus && (
                <span className="flex items-center gap-1.5 text-xs">
                  <span className="text-[#918175]">run</span>
                  <span className="text-[#68a8e4] font-mono">{h.targetRunId.slice(0, 12)}</span>
                  <StatusBadge status={h.targetRunStatus.status} />
                  {h.targetRunStatus.current_phase && <span className="text-[#fce8c3]">{h.targetRunStatus.current_phase}</span>}
                  {h.targetRunStatus.finding_count > 0 && <span className="text-[#7fd962] font-bold">{h.targetRunStatus.finding_count} findings</span>}
                </span>
              )}
            </div>

            {/* Advanced Options */}
            {h.showAdvanced && (
              <div className="mt-2 space-y-2">
                {/* Swarm options (default mode) */}
                {h.advancedMode === 'swarm' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Module Tags</label>
                        <input value={h.swarmModuleTags} onChange={(e) => h.setSwarmModuleTags(e.target.value)} placeholder="xss, sqli" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Vuln Type</label>
                        <input value={h.swarmVulnType} onChange={(e) => h.setSwarmVulnType(e.target.value)} placeholder="sqli" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Max Iterations</label>
                        <input value={h.swarmMaxIterations} onChange={(e) => h.setSwarmMaxIterations(e.target.value)} placeholder="3" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.swarmTimeout} onChange={(e) => h.setSwarmTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#918175] text-[10px] block mb-0.5">Instruction</label>
                      <textarea value={h.swarmInstruction} onChange={(e) => h.setSwarmInstruction(e.target.value)} placeholder="Focus on business logic flaws..." rows={2} className={`${inputClass} resize-y`} />
                    </div>
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Focus</label>
                        <input value={h.swarmFocus} onChange={(e) => h.setSwarmFocus(e.target.value)} placeholder="auth bypass" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Profile</label>
                        <input value={h.swarmProfile} onChange={(e) => h.setSwarmProfile(e.target.value)} placeholder="thorough" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Diff</label>
                        <input value={h.swarmDiff} onChange={(e) => h.setSwarmDiff(e.target.value)} placeholder="PR URL or main...branch" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Intensity</label>
                        <Dropdown value={h.swarmIntensity} onChange={h.setSwarmIntensity} options={INTENSITY_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Vigolium Audit</label>
                        <Dropdown value={h.swarmAudit} onChange={h.setSwarmAudit} options={AUDIT_PREP_MODE_OPTIONS} />
                      </div>
                    </div>
                    <div className="flex flex-wrap items-end gap-1">
                      {([
                        ['Discover', h.swarmDiscover, h.setSwarmDiscover] as const,
                        ['Source Only', h.swarmSourceAnalysisOnly, h.setSwarmSourceAnalysisOnly] as const,
                        ['Code Audit', h.swarmCodeAudit, h.setSwarmCodeAudit] as const,
                        ['Triage', h.swarmTriage, h.setSwarmTriage] as const,
                        ['Show Prompt', h.swarmShowPrompt, h.setSwarmShowPrompt] as const,
                        ['Dry Run', h.swarmDryRun, h.setSwarmDryRun] as const,
                      ]).map(([label, value, setter]) => (
                        <button key={label} type="button" onClick={() => setter(!value)}
                          className={`px-2.5 py-1 text-xs font-bold border transition-colors ${
                            value
                              ? 'border-[#7fd962] bg-[#7fd962]/15 text-[#7fd962]'
                              : 'border-[#2e2b26] text-[#918175] hover:border-[#918175]'
                          }`}
                        >{label}</button>
                      ))}
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Only Phase</label>
                        <input value={h.swarmOnlyPhase} onChange={(e) => h.setSwarmOnlyPhase(e.target.value)} placeholder="plan" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Skip Phases <span className="text-[#706560] italic">comma-sep</span></label>
                        <input value={h.swarmSkipPhases} onChange={(e) => h.setSwarmSkipPhases(e.target.value)} placeholder="triage, native-rescan" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Start From</label>
                        <input value={h.swarmStartFrom} onChange={(e) => h.setSwarmStartFrom(e.target.value)} placeholder="triage" className={inputClass} />
                      </div>
                    </div>
                  </div>
                )}

                {/* Autopilot options */}
                {h.advancedMode === 'autopilot' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Agent</label>
                        <Dropdown value={h.autopilotAgent} onChange={h.setAutopilotAgent} options={AGENT_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Focus</label>
                        <input value={h.autopilotFocus} onChange={(e) => h.setAutopilotFocus(e.target.value)} placeholder="auth, api" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.autopilotTimeout} onChange={(e) => h.setAutopilotTimeout(e.target.value)} placeholder="30m" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Max Commands</label>
                        <input value={h.autopilotMaxCommands} onChange={(e) => h.setAutopilotMaxCommands(e.target.value)} placeholder="50" className={inputClass} />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Source</label>
                        <input value={h.autopilotSource} onChange={(e) => h.setAutopilotSource(e.target.value)} placeholder="git URL or local path" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Diff</label>
                        <input value={h.autopilotDiff} onChange={(e) => h.setAutopilotDiff(e.target.value)} placeholder="PR URL or main...branch" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Intensity</label>
                        <Dropdown value={h.autopilotIntensity} onChange={h.setAutopilotIntensity} options={INTENSITY_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Vigolium Audit Mode</label>
                        <Dropdown value={h.autopilotAuditMode} onChange={h.setAutopilotAuditMode} options={AUDIT_PREP_MODE_OPTIONS} />
                      </div>
                    </div>
                    <div>
                      <label className="text-[#918175] text-[10px] block mb-0.5">Instruction</label>
                      <textarea value={h.autopilotInstruction} onChange={(e) => h.setAutopilotInstruction(e.target.value)} placeholder="Custom instruction for the agent..." rows={2} className={`${inputClass} resize-y`} />
                    </div>
                    <div className="flex items-center gap-1">
                      {([
                        ['Dry Run', h.autopilotDryRun, h.setAutopilotDryRun] as const,
                        ['Skip Audit', h.autopilotNoAudit, h.setAutopilotNoAudit] as const,
                      ]).map(([label, value, setter]) => (
                        <button key={label} type="button" onClick={() => setter(!value)}
                          className={`px-2 py-0.5 text-[9px] font-bold border transition-colors ${
                            value
                              ? 'border-[#7fd962] bg-[#7fd962]/15 text-[#7fd962]'
                              : 'border-[#2e2b26] text-[#918175] hover:border-[#918175]'
                          }`}
                        >{label}</button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Audit options */}
                {h.advancedMode === 'audit' && (
                  <div className="space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Mode</label>
                        <Dropdown value={h.auditMode} onChange={h.setAuditMode} options={AUDIT_MODE_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Intensity</label>
                        <Dropdown value={h.auditIntensity} onChange={h.setAuditIntensity} options={INTENSITY_OPTIONS} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Timeout</label>
                        <input value={h.auditTimeout} onChange={(e) => h.setAuditTimeout(e.target.value)} placeholder="2h" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Commit Depth</label>
                        <input value={h.auditCommitDepth} onChange={(e) => h.setAuditCommitDepth(e.target.value)} placeholder="0" className={inputClass} />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Diff</label>
                        <input value={h.auditDiff} onChange={(e) => h.setAuditDiff(e.target.value)} placeholder="PR URL or HEAD~3" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Last Commits</label>
                        <input value={h.auditLastCommits} onChange={(e) => h.setAuditLastCommits(e.target.value)} placeholder="5" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Files <span className="text-[#706560] italic">comma-sep</span></label>
                        <input value={h.auditFiles} onChange={(e) => h.setAuditFiles(e.target.value)} placeholder="src/main.go, src/auth.go" className={inputClass} />
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Pi Provider</label>
                        <input value={h.auditPiProvider} onChange={(e) => h.setAuditPiProvider(e.target.value)} placeholder="vertex-anthropic" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Pi Model</label>
                        <input value={h.auditPiModel} onChange={(e) => h.setAuditPiModel(e.target.value)} placeholder="claude-opus-4-6" className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-[10px] block mb-0.5">Source <span className="text-[#706560] italic">git URL or path</span></label>
                        <input value={h.auditSource} onChange={(e) => h.setAuditSource(e.target.value)} placeholder="git@github.com:org/repo.git" className={inputClass} />
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      {([
                        ['Upload Results', h.auditUploadResults, h.setAuditUploadResults] as const,
                      ]).map(([label, value, setter]) => (
                        <button key={label} type="button" onClick={() => setter(!value)}
                          className={`px-2.5 py-1 text-xs font-bold border transition-colors ${
                            value
                              ? 'border-[#7fd962] bg-[#7fd962]/15 text-[#7fd962]'
                              : 'border-[#2e2b26] text-[#918175] hover:border-[#918175]'
                          }`}
                        >{label}</button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Query options */}
                {h.advancedMode === 'query' && (
                  <div className="space-y-2">
                    <div className="flex border border-[#2e2b26]">
                      <button onClick={() => h.setScanMode('template')} className={modeBtnClass(h.scanMode === 'template')}>TEMPLATE</button>
                      <button onClick={() => h.setScanMode('custom')} className={modeBtnClass(h.scanMode === 'custom')}>CUSTOM</button>
                    </div>
                    {h.scanMode === 'template' ? (
                      <>
                        <div>
                          <label className="text-[#918175] text-xs block mb-0.5">Agent</label>
                          <input value={h.agentName} onChange={(e) => h.setAgentName(e.target.value)} placeholder="claude" className={inputClass} />
                        </div>
                        <div>
                          <label className="text-[#918175] text-xs block mb-0.5">Prompt Template</label>
                          <input value={h.promptTemplate} onChange={(e) => h.setPromptTemplate(e.target.value)} placeholder="security-analysis" className={inputClass} />
                        </div>
                      </>
                    ) : (
                      <div>
                        <label className="text-[#918175] text-xs block mb-0.5">Prompt</label>
                        <textarea value={h.customPrompt} onChange={(e) => h.setCustomPrompt(e.target.value)} placeholder="Enter your prompt..." rows={3} className={`${inputClass} resize-y`} />
                      </div>
                    )}
                    <div>
                      <label className="text-[#918175] text-xs block mb-0.5">Files <span className="text-[#706560] italic">comma-sep</span></label>
                      <input value={h.queryFiles} onChange={(e) => h.setQueryFiles(e.target.value)} placeholder="src/main.go" className={inputClass} />
                    </div>
                    <div className="grid grid-cols-2 gap-1.5">
                      <div>
                        <label className="text-[#918175] text-xs block mb-0.5">Instruction</label>
                        <input value={h.queryInstruction} onChange={(e) => h.setQueryInstruction(e.target.value)} placeholder="Custom instruction..." className={inputClass} />
                      </div>
                      <div>
                        <label className="text-[#918175] text-xs block mb-0.5">Source Label</label>
                        <input value={h.querySourceLabel} onChange={(e) => h.setQuerySourceLabel(e.target.value)} placeholder="my-source" className={inputClass} />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

        </div>

        {/* ── Bottom: Output ── */}
        <div className="flex-1 min-h-0 flex flex-col overflow-auto">
          {/* Sessions — open by default when there are sessions and no active scan */}
          <details open={!!h.expandedSessionUuid || (!h.scanOutput && (!!h.sessionsCount || h.sessionsLoading || !!h.sessionsError))} className="border border-t-0 border-[#2e2b26] bg-[#1c1b19] overflow-hidden shrink-0">
            <summary className="px-3 py-1.5 border-b border-[#2e2b26] cursor-pointer hover:bg-[#2e2b26]/30 list-none [&::-webkit-details-marker]:hidden flex items-center gap-1.5">
              <ChevronDown className="w-3 h-3 text-[#7fd962] transition-transform [[open]>&]:rotate-0 [details:not([open])>&]:-rotate-90" />
              <span className="text-[#7fd962] text-xs font-bold inline-flex items-center gap-1.5">
                <Layers className="w-3 h-3" />AGENT SESSIONS
                {h.sessionsTotal != null && <span className="text-[#918175] font-normal ml-1">({h.sessionsTotal})</span>}
              </span>
            </summary>
            <div className="flex items-center justify-between gap-3 px-3 py-2 text-xs text-[#918175] border-b border-[#2e2b26]">
              <span>{h.sessionsLoading ? 'Loading agent sessions…' : h.sessionsError && !h.sessionsData ? 'Session history unavailable' : `Showing ${h.sessionsCount ? h.sessionsOffset + 1 : 0}–${h.sessionsCount ? h.sessionsOffset + h.sessionsCount : 0} of ${h.sessionsTotal ?? 'unknown'} sessions`}</span>
              <div className="flex gap-3">
                <button type="button" disabled={h.sessionsOffset === 0 || h.sessionsBusy} onClick={h.sessionsPrevious} className="underline disabled:opacity-40">Previous sessions</button>
                <button type="button" disabled={!h.sessionsHasNext || h.sessionsBusy || !!h.sessionsError} onClick={h.sessionsNext} className="underline disabled:opacity-40">Next sessions</button>
              </div>
            </div>
            {h.sessionsError && (
              <div role="alert" className="px-3 py-2 text-xs text-[#ff6b6b] border-b border-[#2e2b26]">
                Session history: {h.sessionsError}
                <button type="button" onClick={h.sessionsRetry} className="ml-3 underline">Retry session history</button>
              </div>
            )}
            <div className="flex flex-col">
              <div className="w-full overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#2e2b26] text-[#706560]">
                      <th className="text-left px-2 py-1 font-bold">STATUS</th>
                      <th className="text-left px-2 py-1 font-bold">UUID</th>
                      <th className="text-left px-2 py-1 font-bold">MODE</th>
                      <th className="text-left px-2 py-1 font-bold">TARGET</th>
                      <th className="text-right px-2 py-1 font-bold">FINDINGS</th>
                      <th className="text-right px-2 py-1 font-bold">SAVED</th>
                      <th className="text-right px-2 py-1 font-bold">DURATION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.sessionsData?.data && h.sessionsData.data.length > 0 ? (
                      h.sessionsData.data.map((s: AgentSession) => (
                        <tr
                          key={s.uuid}
                          onClick={() => h.setExpandedSessionUuid(prev => prev === s.uuid ? null : s.uuid)}
                          className={`border-b border-[#2e2b26]/50 hover:bg-[#2e2b26]/30 cursor-pointer ${h.expandedSessionUuid === s.uuid ? 'bg-[#2e2b26]' : ''}`}
                        >
                          <td className="px-2 py-1"><StatusBadge status={s.status} /></td>
                          <td className="px-2 py-1 text-[#68a8e4] font-mono">{s.uuid.slice(0, 8)}</td>
                          <td className="px-2 py-1 text-[#918175]">{s.mode}</td>
                          <td className="px-2 py-1 text-[#fce8c3]">{s.target_url ? truncate(s.target_url, 30) : '\u2014'}</td>
                          <td className="px-2 py-1 text-right text-[#fce8c3]">{formatAgentRunCount(s.finding_count)}</td>
                          <td className="px-2 py-1 text-right text-[#98bc37]">{formatAgentRunCount(s.saved_count)}</td>
                          <td className="px-2 py-1 text-right text-[#fce8c3]">{formatDuration(s.duration_ms)}</td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={7} className="px-3 py-3 text-center text-[#918175]">{h.sessionsLoading ? 'Loading session history…' : h.sessionsError ? 'Could not load session history' : h.sessionsOffset ? 'No sessions on this page' : 'No session history in the active project'}</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
              {h.expandedSessionUuid && (
                <div key={h.sessionSelectionKey} className="w-full min-w-0">
                  {h.sessionDetailError && (
                    <div role="alert" className="px-3 py-2 text-xs text-[#ff6b6b] border-b border-[#2e2b26]">
                      Session details: {h.sessionDetailError}
                      <button type="button" onClick={h.sessionDetailRetry} className="ml-3 underline">Retry session details</button>
                    </div>
                  )}
                  {h.sessionDetail ? (
                    <SessionDetailPanel session={h.sessionDetail} onClose={() => h.setExpandedSessionUuid(null)} />
                  ) : (
                    <div className="px-3 py-2 text-xs text-[#918175]">
                      <div className="flex justify-between gap-2">
                        <span className="font-bold">SESSION DETAILS — active project</span>
                        <button type="button" aria-label="Close session details" onClick={() => h.setExpandedSessionUuid(null)}>&#10005;</button>
                      </div>
                      <div className="font-mono break-all py-2">{h.expandedSessionUuid}</div>
                      <p>{h.sessionDetailLoading ? 'Loading session details…' : h.sessionDetailError ? 'Session details unavailable in the active project.' : 'No session details available in the active project.'}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </details>

          {/* Full runtime.log by default; following the bounded tail is explicit and optional. */}
          <div className={`border border-t-0 border-[#2e2b26] bg-[#141310] flex flex-col overflow-hidden ${h.streamingOpen ? h.consoleMode === 'full' ? 'flex-1 min-h-[24rem]' : 'flex-1' : 'shrink-0'}`}>
            <button
              type="button"
              onClick={() => h.setStreamingOpen(!h.streamingOpen)}
              className="px-3 py-1.5 border-b border-[#2e2b26] hover:bg-[#2e2b26]/30 flex items-center justify-between shrink-0 text-left"
            >
              <span className="text-[#7fd962] text-xs font-bold flex items-center gap-1.5">
                <ChevronDown className={`w-3 h-3 text-[#7fd962] transition-transform ${h.streamingOpen ? '' : '-rotate-90'}`} />
                <ScrollText className="w-3 h-3" />{h.consoleMode === 'tail' ? 'AGENT CONSOLE TAIL' : 'AGENT RUNTIME LOG'}
              </span>
              <div className="flex items-center gap-3">
                {h.panelIsRunning && <span className="text-xs text-[#7fd962]">run active</span>}
                {h.consoleMode === 'tail' && h.panelConnection !== 'idle' && (
                  <span className="text-xs text-[#68a8e4] flex items-center gap-1">
                    {(h.panelConnection === 'connecting' || h.panelConnection === 'retrying') && <Loader2 className="w-3 h-3 animate-spin" />}
                    {h.panelConnection === 'complete' ? 'tail loaded' : `tail ${h.panelConnection}`}
                  </span>
                )}
                {h.scanResult && (
                  <span className="text-xs text-[#918175]">
                    {h.scanResult.finding_count != null && <span className="text-[#fce8c3] mr-3">findings: <b className="text-[#7fd962]">{String(h.scanResult.finding_count)}</b></span>}
                    {h.scanResult.saved_count != null && <span className="text-[#fce8c3]">saved: <b className="text-[#98bc37]">{String(h.scanResult.saved_count)}</b></span>}
                  </span>
                )}
              </div>
            </button>
            {h.activeRunStatusError && (
              <div role="alert" className="shrink-0 px-3 py-2 text-xs text-[#ff6b6b] border-b border-[#2e2b26]">
                Run status: {h.activeRunStatusError}. The run may still be active.
                <button type="button" onClick={h.activeRunStatusRetry} className="ml-3 underline">Retry run status</button>
              </div>
            )}
            {h.cancelError && (
              <div role="alert" className="shrink-0 px-3 py-2 text-xs text-[#ff6b6b] border-b border-[#2e2b26]">
                Cancel run: {h.cancelError}
                <button type="button" onClick={h.handleScanCancel} className="ml-3 underline">Retry cancel run</button>
              </div>
            )}
            {h.streamingOpen && (
              <>
                <div className="shrink-0 flex gap-3 px-3 py-2 border-b border-[#2e2b26] text-xs" aria-label="Log display mode">
                  <button type="button" aria-pressed={h.consoleMode === 'full'} onClick={() => h.setConsoleMode('full')} className={h.consoleMode === 'full' ? 'text-[#7fd962] font-bold' : 'text-[#918175] underline'}>Full log (paged)</button>
                  <button type="button" aria-pressed={h.consoleMode === 'tail'} onClick={() => h.setConsoleMode('tail')} className={h.consoleMode === 'tail' ? 'text-[#7fd962] font-bold' : 'text-[#918175] underline'}>Live tail (bounded)</button>
                </div>
                {h.consoleMode === 'full' ? (
                  <div className="flex-1 min-h-0 overflow-auto"><AgentRuntimeLogPanel runUUID={h.expandedSessionUuid ?? ''} theme="dark" /></div>
                ) : (
                  <>
                    {h.expandedSessionUuid && (
                      <div role="status" className="shrink-0 px-3 py-1.5 text-xs text-[#918175] border-b border-[#2e2b26]">
                        {h.panelTruncated ? 'Earlier output omitted from this bounded console tail.' : 'Bounded console tail; not a full log download.'}
                        {h.panelLogSize !== null && ` Saved log size: ${h.panelLogSize.toLocaleString()} bytes.`}
                      </div>
                    )}
                    {h.panelError && (
                      <div role="alert" className="shrink-0 px-3 py-2 text-xs text-[#ff6b6b] whitespace-pre-wrap border-b border-[#2e2b26]">
                        {h.panelError}
                      </div>
                    )}
                    {(h.panelConnection === 'error' || h.panelConnection === 'exhausted') && (
                      <button type="button" onClick={h.panelRetry} className="shrink-0 self-start mx-3 my-2 text-xs text-[#68a8e4] underline">Retry console tail</button>
                    )}
                    <pre ref={h.scanOutputRef} onScroll={h.onScanOutputScroll} className="flex-1 overflow-auto p-3 text-xs text-[#a89888] font-mono whitespace-pre-wrap leading-relaxed">
                      {h.panelOutput || <span className="text-[#403d38]">{h.panelPlaceholder}</span>}
                    </pre>
                  </>
                )}
              </>
            )}
          </div>
        </div>

      </div>
    </PageShell>
  );
}
