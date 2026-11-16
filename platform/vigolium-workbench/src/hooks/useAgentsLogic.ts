'use client';

import { useState, useRef, useCallback, useEffect, useLayoutEffect, useMemo, type SetStateAction } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useFollowTail } from '@/lib/useFollowTail';
import { zipSync } from 'fflate';
import { useAgentSessions, useAgentSessionDetail, useUploadRepo, useStartAutopilotRun, useStartAgentRun, useCancelAgentRun, useAgentRunStatus } from '@/api/hooks';
import { useProjectContext } from '@/contexts/ProjectContext';
import { getProjectUUID } from '@/api/client';
import { isTerminalAgentStatus } from '@/api/types';
import { fetchSSE } from '@/lib/sse';
import { useAgentSessionLogs } from '@/lib/useAgentSessionLogs';

export type ScanProfile = 'quick' | 'deep' | 'code-review' | 'autopilot' | 'audit';
export type InputMode = 'url' | 'raw' | 'curl';
export type TargetInputTab = 'target' | 'prompt';
export type DetectedInputType = 'url' | 'raw' | 'curl' | 'empty';
export type AdvancedMode = 'swarm' | 'autopilot' | 'query' | 'audit';
export type ScanMode = 'template' | 'custom';

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export const AGENT_OPTIONS = [
  { value: '', label: 'default' },
  { value: 'claude', label: 'claude' },
  { value: 'codex', label: 'codex' },
  { value: 'gemini', label: 'gemini' },
  { value: 'custom', label: 'custom' },
];

export const PROFILE_OPTIONS: { value: ScanProfile; label: string; description: string; icon: string }[] = [
  { value: 'quick', label: 'Quick Scan', description: 'Fast surface-level scan with light profile', icon: 'zap' },
  { value: 'deep', label: 'Deep Scan', description: 'Thorough scan with crawling & discovery', icon: 'layers' },
  { value: 'code-review', label: 'Code Review', description: 'Static analysis & source code audit', icon: 'scroll-text' },
  { value: 'autopilot', label: 'Autopilot', description: 'AI agent drives the CLI autonomously', icon: 'bot' },
];

export const AUDIT_PREP_MODE_OPTIONS = [
  { value: '', label: 'Default' },
  { value: 'lite', label: 'Lite' },
  { value: 'scan', label: 'Scan' },
  { value: 'deep', label: 'Deep' },
];

export const INTENSITY_OPTIONS = [
  { value: '', label: 'Default (balanced)' },
  { value: 'quick', label: 'Quick', description: 'Fast surface-level scan for common issues', icon: 'zap' },
  { value: 'balanced', label: 'Balanced', description: 'Thorough scan with smart defaults', icon: 'scale' },
  { value: 'deep', label: 'Deep', description: 'Exhaustive scan with full discovery and verification', icon: 'layers' },
];

export const AUDIT_MODE_OPTIONS = [
  { value: '', label: 'Default (balanced)' },
  { value: 'lite', label: 'Lite' },
  { value: 'balanced', label: 'Balanced' },
  { value: 'deep', label: 'Deep' },
  { value: 'revisit', label: 'Revisit' },
  { value: 'confirm', label: 'Confirm' },
  { value: 'merge', label: 'Merge' },
  { value: 'diff', label: 'Diff' },
  { value: 'longshot', label: 'Longshot' },
  { value: 'status', label: 'Status' },
  { value: 'smoke', label: 'Smoke' },
];

const HTTP_METHODS = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s/;

export function detectInputType(value: string): DetectedInputType {
  const trimmed = value.trim();
  if (!trimmed) return 'empty';
  if (/^curl\s/i.test(trimmed)) return 'curl';
  if (HTTP_METHODS.test(trimmed)) return 'raw';
  return 'url';
}

const SESSION_PAGE_SIZE = 20;

function writeSessionURL(uuid: string | null, replace = false) {
  const url = new URL(window.location.href);
  // A file belongs to one session only; clear it atomically with a session change.
  if (url.searchParams.get('session') !== uuid) url.searchParams.delete('artifact');
  if (uuid) url.searchParams.set('session', uuid);
  else url.searchParams.delete('session');
  const href = url.pathname + url.search + url.hash;
  if (href !== window.location.pathname + window.location.search + window.location.hash) {
    if (replace) window.history.replaceState(window.history.state, '', href);
    else window.history.pushState(window.history.state, '', href);
  }
}

function writeArtifactURL(name: string | null, replace = false) {
  const url = new URL(window.location.href);
  if (name) url.searchParams.set('artifact', name);
  else url.searchParams.delete('artifact');
  const href = url.pathname + url.search + url.hash;
  if (href !== window.location.pathname + window.location.search + window.location.hash) {
    if (replace) window.history.replaceState(window.history.state, '', href);
    else window.history.pushState(window.history.state, '', href);
  }
}

function errorMessage(error: unknown, fallback: string): string {
  return error ? (error instanceof Error ? error.message : fallback) : '';
}

export function useAgentsLogic() {
  const { projectUUID: contextProjectUUID } = useProjectContext();
  // Match the API scope while ProjectProvider hydrates its persisted selection.
  const projectUUID = getProjectUUID() ?? contextProjectUUID;
  const lastProjectRef = useRef(projectUUID);
  const currentProjectRef = useRef(projectUUID);
  currentProjectRef.current = projectUUID;
  const projectGenerationRef = useRef(0);

  // Hero state
  const [targetUrl, setTargetUrl] = useState('');
  const [scanProfile, setScanProfile] = useState<ScanProfile>('autopilot');

  // Advanced options visibility
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advancedMode, setAdvancedMode] = useState<AdvancedMode>('autopilot');

  // Chat panel visibility
  const [chatOpen, setChatOpen] = useState(false);

  // Auto-detect input type from content
  const detectedInputType = useMemo(() => detectInputType(targetUrl), [targetUrl]);

  // Swarm advanced fields
  const [inputMode, setInputMode] = useState<InputMode>('url');
  const [swarmAgent, setSwarmAgent] = useState('');
  const [swarmModuleTags, setSwarmModuleTags] = useState('');
  const [swarmVulnType, setSwarmVulnType] = useState('');
  const [swarmMaxIterations, setSwarmMaxIterations] = useState('');
  const [swarmTimeout, setSwarmTimeout] = useState('');
  const [swarmDryRun, setSwarmDryRun] = useState(false);
  const [swarmScanUuid, setSwarmScanUuid] = useState('');
  const [swarmProjectUuid, setSwarmProjectUuid] = useState('');
  const [swarmInstruction, setSwarmInstruction] = useState('');
  const [swarmFiles, setSwarmFiles] = useState('');
  const [swarmFocus, setSwarmFocus] = useState('');
  const [swarmProfile, setSwarmProfile] = useState('');
  const [swarmSource, setSwarmSource] = useState('');
  const [swarmInputs, setSwarmInputs] = useState('');
  const [swarmSourceAnalysisOnly, setSwarmSourceAnalysisOnly] = useState(false);
  const [swarmDiscover, setSwarmDiscover] = useState(false);
  const [swarmCodeAudit, setSwarmCodeAudit] = useState(false);
  const [swarmDiff, setSwarmDiff] = useState('');
  const [swarmLastCommits, setSwarmLastCommits] = useState('');
  const [swarmTriage, setSwarmTriage] = useState(false);
  const [swarmOnlyPhase, setSwarmOnlyPhase] = useState('');
  const [swarmSkipPhases, setSwarmSkipPhases] = useState('');
  const [swarmStartFrom, setSwarmStartFrom] = useState('');
  const [swarmShowPrompt, setSwarmShowPrompt] = useState(false);
  const [swarmAudit, setSwarmAudit] = useState('');
  const [swarmIntensity, setSwarmIntensity] = useState('');

  // Autopilot advanced fields
  const [autopilotAgent, setAutopilotAgent] = useState('');
  const [autopilotFocus, setAutopilotFocus] = useState('');
  const [autopilotTimeout, setAutopilotTimeout] = useState('');
  const [autopilotInstruction, setAutopilotInstruction] = useState('');
  const [autopilotMaxCommands, setAutopilotMaxCommands] = useState('');
  const [autopilotDryRun, setAutopilotDryRun] = useState(false);
  const [autopilotSource, setAutopilotSource] = useState('');
  const [autopilotFiles, setAutopilotFiles] = useState('');
  const [autopilotScanUuid, setAutopilotScanUuid] = useState('');
  const [autopilotDiff, setAutopilotDiff] = useState('');
  const [autopilotAuditMode, setAutopilotAuditMode] = useState('');
  const [autopilotNoAudit, setAutopilotNoAudit] = useState(false);
  const [autopilotIntensity, setAutopilotIntensity] = useState('');

  // Audit advanced fields
  const [auditSource, setAuditSource] = useState('');
  const [auditMode, setAuditMode] = useState('');
  const [auditIntensity, setAuditIntensity] = useState('');
  const [auditTimeout, setAuditTimeout] = useState('');
  const [auditDiff, setAuditDiff] = useState('');
  const [auditLastCommits, setAuditLastCommits] = useState('');
  const [auditCommitDepth, setAuditCommitDepth] = useState('');
  const [auditFiles, setAuditFiles] = useState('');
  const [auditPiProvider, setAuditPiProvider] = useState('');
  const [auditPiModel, setAuditPiModel] = useState('');
  const [auditUploadResults, setAuditUploadResults] = useState(false);

  // Query advanced fields
  const [scanMode, setScanMode] = useState<ScanMode>('template');
  const [agentName, setAgentName] = useState('');
  const [promptTemplate, setPromptTemplate] = useState('');
  const [customPrompt, setCustomPrompt] = useState('');
  const [repoPath, setRepoPath] = useState('');
  const [queryFiles, setQueryFiles] = useState('');
  const [append, setAppend] = useState('');
  const [querySource, setQuerySource] = useState('');
  const [queryScanUuid, setQueryScanUuid] = useState('');
  const [queryInstruction, setQueryInstruction] = useState('');
  const [querySourceLabel, setQuerySourceLabel] = useState('');

  // Target input tab (target vs prompt)
  const [targetInputTab, setTargetInputTab] = useState<TargetInputTab>('target');
  const [targetPrompt, setTargetPrompt] = useState('');
  const [targetRunId, setTargetRunId] = useState<string | null>(null);
  const [targetError, setTargetError] = useState('');
  const startAutopilotRun = useStartAutopilotRun();
  const { data: targetRunStatus } = useAgentRunStatus(targetRunId);

  const handleTargetSubmit = useCallback(() => {
    const prompt = targetPrompt.trim();
    if (!prompt || startAutopilotRun.isPending) return;
    setTargetError('');
    setTargetRunId(null);
    startAutopilotRun.mutate({ prompt }, {
      onSuccess: (data) => {
        setTargetRunId(data.agentic_scan_uuid);
      },
      onError: (err) => {
        setTargetError(err instanceof Error ? err.message : 'Failed to start autopilot run');
      },
    });
  }, [targetPrompt, startAutopilotRun]);

  // Async scan-run state. The scan is fire-and-poll (stream:false): the POST
  // returns a run UUID, we track its status via useAgentRunStatus and tail its
  // runtime.log through the watched session (expandedSessionUuid), and Stop hits
  // the cancel endpoint. No client-held SSE drives the run, so closing the tab
  // or navigating away no longer interrupts it.
  const [activeRun, setActiveRun] = useState<{ projectUUID: typeof projectUUID; uuid: string | null }>({ projectUUID, uuid: null });
  const activeRunId = activeRun.projectUUID === projectUUID ? activeRun.uuid : null;
  const activeRunRef = useRef(activeRunId);
  activeRunRef.current = activeRunId;
  const [scanError, setScanError] = useState('');
  const [cancelFailure, setCancelFailure] = useState<{ projectUUID: typeof projectUUID; uuid: string; message: string } | null>(null);
  const cancelError = cancelFailure?.projectUUID === projectUUID && cancelFailure.uuid === activeRunId ? cancelFailure.message : '';
  const [streamingOpen, setStreamingOpen] = useState(false);
  const startAgentRun = useStartAgentRun();
  const cancelAgentRun = useCancelAgentRun();
  // Separate observer: row mutations must not replace the active-panel callbacks.
  const rowCancelAgentRun = useCancelAgentRun();
  const queryClient = useQueryClient();
  const rowRequests = useRef(new Map<string, symbol>());
  const rowCancellationMounted = useRef(false);
  const [rowCancellations, setRowCancellations] = useState({ projectUUID, pending: new Set<string>(), errors: {} as Record<string, string> });
  const cancelingUuids = rowCancellations.projectUUID === projectUUID ? rowCancellations.pending : new Set<string>();
  const cancelErrorForUuid = (uuid: string) => rowCancellations.projectUUID === projectUUID ? rowCancellations.errors[uuid] ?? '' : '';
  useEffect(() => {
    rowCancellationMounted.current = true;
    const requests = rowRequests.current;
    return () => { rowCancellationMounted.current = false; requests.clear(); };
  }, []);
  const activeRunQuery = useAgentRunStatus(activeRunId);
  const activeRunStatus = activeRunId ? activeRunQuery.data : undefined;
  const activeRunStatusError = activeRunId ? errorMessage(activeRunQuery.error, 'Failed to load run status') : '';
  const activeRunTerminal = isTerminalAgentStatus(activeRunStatus?.status);
  // The Start/Stop toggle and the spinner treat a run as "streaming" while we're
  // submitting or while the active run hasn't reached a terminal status
  // (including the brief "cancelling" window after Stop).
  const isScanStreaming = startAgentRun.isPending || (!!activeRunId && !activeRunTerminal);
  // Findings/saved counts come from the run status once it finishes.
  const scanResult: Record<string, unknown> | null =
    activeRunId && activeRunTerminal && activeRunStatus
      ? (activeRunStatus as unknown as Record<string, unknown>)
      : null;

  // Chat state
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [isChatStreaming, setIsChatStreaming] = useState(false);
  const chatAbortRef = useRef<AbortController | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Repo upload state
  const [uploadDragging, setUploadDragging] = useState(false);
  const [uploadCompressing, setUploadCompressing] = useState(false);
  const uploadDragCounter = useRef(0);
  const uploadFileInputRef = useRef<HTMLInputElement>(null);
  const uploadRepo = useUploadRepo();

  // Selection starts empty for static HTML/hydration. Scope it before querying,
  // so a project switch never requests the old UUID against the new project.
  const [selection, setSelection] = useState<{ projectUUID: typeof projectUUID; uuid: string | null }>({ projectUUID, uuid: null });
  const expandedSessionUuid = selection.projectUUID === projectUUID ? selection.uuid : null;
  const [artifactSelection, setArtifactSelection] = useState<{ projectUUID: typeof projectUUID; uuid: string | null; name: string | null }>({ projectUUID, uuid: null, name: null });
  const selectedArtifact = artifactSelection.projectUUID === projectUUID && artifactSelection.uuid === expandedSessionUuid ? artifactSelection.name : null;
  const selectedSessionRef = useRef(expandedSessionUuid);
  selectedSessionRef.current = expandedSessionUuid;
  const setExpandedSessionUuid = useCallback((value: SetStateAction<string | null>) => {
    if (currentProjectRef.current !== projectUUID) return;
    const uuid = typeof value === 'function' ? value(selectedSessionRef.current) : value;
    selectedSessionRef.current = uuid;
    writeSessionURL(uuid);
    if (uuid !== expandedSessionUuid) setArtifactSelection({ projectUUID, uuid, name: null });
    setSelection({ projectUUID, uuid });
  }, [projectUUID, expandedSessionUuid]);
  const artifactGeneration = projectGenerationRef.current;
  const setSelectedArtifact = useCallback((name: string | null) => {
    if (currentProjectRef.current !== projectUUID || projectGenerationRef.current !== artifactGeneration || selectedSessionRef.current !== expandedSessionUuid || !expandedSessionUuid) return;
    writeArtifactURL(name);
    setArtifactSelection({ projectUUID, uuid: expandedSessionUuid, name });
  }, [projectUUID, expandedSessionUuid, artifactGeneration]);

  const [history, setHistory] = useState({ projectUUID, offset: 0 });
  const sessionsOffset = history.projectUUID === projectUUID ? history.offset : 0;
  const sessionsQuery = useAgentSessions({ limit: SESSION_PAGE_SIZE, offset: sessionsOffset });
  // keepPreviousData is not the requested page; don't show its rows/range as new.
  const sessionsData = sessionsQuery.isPlaceholderData ? undefined : sessionsQuery.data;
  const sessionsLoading = !!(sessionsQuery.isPending || sessionsQuery.isPlaceholderData);
  const sessionsError = errorMessage(sessionsQuery.error, 'Failed to load agent sessions');
  const sessionsCount = sessionsData?.data?.length ?? 0;
  const sessionsTotal = typeof sessionsData?.total === 'number' && Number.isFinite(sessionsData.total) && sessionsData.total >= 0 ? sessionsData.total : null;
  const sessionsHasNext = !!sessionsData && (typeof sessionsData.has_more === 'boolean'
    ? sessionsData.has_more
    : sessionsTotal !== null ? sessionsOffset + sessionsCount < sessionsTotal : sessionsCount === SESSION_PAGE_SIZE);
  const sessionsBusy = sessionsLoading || !!sessionsQuery.isFetching;
  const sessionsPrevious = () => setHistory({ projectUUID, offset: Math.max(0, sessionsOffset - SESSION_PAGE_SIZE) });
  const sessionsNext = () => {
    if (sessionsHasNext && !sessionsBusy) setHistory({ projectUUID, offset: sessionsOffset + SESSION_PAGE_SIZE });
  };
  // A different project/run always opens the full byte-paged log, never a retained tail.
  const sessionSelectionKey = JSON.stringify([projectUUID, expandedSessionUuid]);
  const [tailSelectionKey, setTailSelectionKey] = useState<string | null>(null);
  const consoleMode = tailSelectionKey === sessionSelectionKey ? 'tail' : 'full';
  useEffect(() => { setTailSelectionKey(null); }, [sessionSelectionKey]);
  const setConsoleMode = (mode: 'full' | 'tail') => setTailSelectionKey(mode === 'tail' ? sessionSelectionKey : null);
  const sessionDetailQuery = useAgentSessionDetail(expandedSessionUuid);
  const sessionDetail = expandedSessionUuid ? sessionDetailQuery.data : undefined;
  const sessionDetailError = expandedSessionUuid ? errorMessage(sessionDetailQuery.error, 'Failed to load session details') : '';
  const sessionLog = useAgentSessionLogs(consoleMode === 'tail' && contextProjectUUID ? expandedSessionUuid : null, sessionDetail?.status);
  const sessionLogs = sessionLog.logs;

  // Layout synchronization clears old URL identity before passive request effects run.
  useLayoutEffect(() => {
    const syncFromURL = () => {
      const params = new URLSearchParams(window.location.search);
      const uuid = params.get('session')?.trim() || null;
      const name = uuid ? params.get('artifact') || null : null;
      if (!uuid) writeArtifactURL(null, true);
      selectedSessionRef.current = uuid;
      setSelection({ projectUUID, uuid });
      setArtifactSelection({ projectUUID, uuid, name });
    };
    if (lastProjectRef.current !== projectUUID) {
      lastProjectRef.current = projectUUID;
      projectGenerationRef.current++;
      rowRequests.current.clear();
      setRowCancellations({ projectUUID, pending: new Set(), errors: {} });
      writeSessionURL(null, true);
      selectedSessionRef.current = null;
      setSelection({ projectUUID, uuid: null });
      setArtifactSelection({ projectUUID, uuid: null, name: null });
      setHistory({ projectUUID, offset: 0 });
      setActiveRun({ projectUUID, uuid: null });
      setCancelFailure(null);
      setScanError('');
      setStreamingOpen(false);
    } else {
      syncFromURL();
    }
    window.addEventListener('popstate', syncFromURL);
    return () => window.removeEventListener('popstate', syncFromURL);
  }, [projectUUID]);

  // Sync advancedMode with scanProfile so the correct advanced section renders
  useEffect(() => {
    if (scanProfile === 'autopilot') setAdvancedMode('autopilot');
    else if (scanProfile === 'audit') setAdvancedMode('audit');
    else setAdvancedMode('swarm');
  }, [scanProfile]);

  // Auto-enable Code Audit when source code is selected
  useEffect(() => {
    if (swarmSource) setSwarmCodeAudit(true);
  }, [swarmSource]);

  useEffect(() => {
    if (isScanStreaming || expandedSessionUuid) setStreamingOpen(true);
  }, [isScanStreaming, expandedSessionUuid]);

  const scanOutputTail = useFollowTail<HTMLPreElement>(sessionLogs, JSON.stringify([projectUUID, expandedSessionUuid]));

  const scrollChatToBottom = useCallback(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(scrollChatToBottom, [messages, scrollChatToBottom]);

  // Fire an async run and start observing it: track its status (isScanStreaming
  // / scanResult) and tail its runtime.log by pointing the watched session at
  // the new run UUID. Replaces the old client-held SSE consumption.
  const startScan = useCallback((endpoint: string, body: Record<string, unknown>) => {
    const projectGeneration = projectGenerationRef.current;
    setScanError('');
    setCancelFailure(null);
    setActiveRun({ projectUUID, uuid: null });
    activeRunRef.current = null;
    setStreamingOpen(true);
    startAgentRun.mutate({ endpoint, body }, {
      onSuccess: (data) => {
        if (currentProjectRef.current !== projectUUID || projectGenerationRef.current !== projectGeneration) return;
        activeRunRef.current = data.agentic_scan_uuid;
        setActiveRun({ projectUUID, uuid: data.agentic_scan_uuid });
        setExpandedSessionUuid(data.agentic_scan_uuid);
      },
      onError: (err) => {
        if (currentProjectRef.current !== projectUUID || projectGenerationRef.current !== projectGeneration) return;
        setScanError(err instanceof Error ? err.message : 'Failed to start run');
      },
    });
  }, [startAgentRun, projectUUID, setExpandedSessionUuid]);

  const handleScanCancel = useCallback(() => {
    if (!activeRunId || cancelAgentRun.isPending || currentProjectRef.current !== projectUUID || activeRunRef.current !== activeRunId) return;
    const uuid = activeRunId;
    const projectGeneration = projectGenerationRef.current;
    const stillCurrent = () => currentProjectRef.current === projectUUID
      && projectGenerationRef.current === projectGeneration && activeRunRef.current === uuid;
    setCancelFailure(null);
    cancelAgentRun.mutate(uuid, {
      onSuccess: () => {
        if (stillCurrent()) setCancelFailure(null);
      },
      onError: (error) => {
        if (stillCurrent()) setCancelFailure({ projectUUID, uuid, message: errorMessage(error, 'Failed to cancel run') });
      },
    });
  }, [activeRunId, cancelAgentRun, projectUUID]);

  const cancellationGeneration = projectGenerationRef.current;
  const cancelRunByUuid = useCallback((uuid: string) => {
    if (!rowCancellationMounted.current || !uuid || !projectUUID || currentProjectRef.current !== projectUUID || projectGenerationRef.current !== cancellationGeneration || rowRequests.current.has(uuid)) return;
    const ticket = Symbol(uuid);
    rowRequests.current.set(uuid, ticket); // Synchronous guard, before a second click/rerender.
    const stillCurrent = () => rowCancellationMounted.current && currentProjectRef.current === projectUUID
      && projectGenerationRef.current === cancellationGeneration && rowRequests.current.get(uuid) === ticket;
    setRowCancellations(previous => ({ projectUUID, pending: new Set([...previous.pending, uuid]), errors: { ...previous.errors, [uuid]: '' } }));
    // Per-call mutate callbacks only run for the latest observer. Independent
    // promises preserve every row's settlement when several scans stop together.
    void rowCancelAgentRun.mutateAsync({ runId: uuid, projectUUID, isCurrent: stillCurrent }).then(() => {
      if (stillCurrent()) void queryClient.invalidateQueries({ queryKey: [projectUUID, 'agent-sessions'] });
    }).catch((error: unknown) => {
      if (stillCurrent()) setRowCancellations(previous => ({ ...previous, errors: { ...previous.errors, [uuid]: errorMessage(error, 'Failed to cancel run') } }));
    }).finally(() => {
      if (!stillCurrent()) return;
      rowRequests.current.delete(uuid);
      setRowCancellations(previous => {
        const pending = new Set(previous.pending); pending.delete(uuid);
        return { ...previous, pending };
      });
    });
  }, [projectUUID, cancellationGeneration, rowCancelAgentRun, queryClient]);

  const handleChatCancel = useCallback(() => {
    chatAbortRef.current?.abort();
    chatAbortRef.current = null;
    setIsChatStreaming(false);
  }, []);

  // Profile-based submit (the main "Start Scan" action). Async: builds the
  // request body and fires startScan, which POSTs without stream:true and then
  // observes the run via status polling + runtime.log tailing.
  const handleProfileSubmit = useCallback(() => {
    const url = targetUrl.trim();
    const sharedSource = auditSource || swarmSource;
    const needsSourceOnly = scanProfile === 'audit';
    if (isScanStreaming || (needsSourceOnly ? !sharedSource : (!url && !sharedSource))) return;

    if (scanProfile === 'autopilot') {
      const apBody: Record<string, unknown> = {};
      if (url) apBody.target = url;
      if (swarmSource) apBody.source = swarmSource;
      if (autopilotIntensity) apBody.intensity = autopilotIntensity;
      startScan('/api/agent/run/autopilot', apBody);
    } else if (scanProfile === 'audit') {
      const body: Record<string, unknown> = { source: sharedSource };
      if (url) body.target = url;
      if (auditIntensity) body.intensity = auditIntensity;
      if (auditMode) body.mode = auditMode;
      if (auditTimeout) body.timeout = auditTimeout;
      if (auditDiff) body.diff = auditDiff;
      if (auditLastCommits) body.last_commits = parseInt(auditLastCommits, 10);
      if (auditCommitDepth) body.commit_depth = parseInt(auditCommitDepth, 10);
      if (auditFiles) body.files = auditFiles.split(',').map((f) => f.trim()).filter(Boolean);
      if (auditPiProvider) body.pi_provider = auditPiProvider;
      if (auditPiModel) body.pi_model = auditPiModel;
      if (auditUploadResults) body.upload_results = true;
      startScan('/api/agent/run/audit', body);
    } else {
      // Custom mode — use advancedMode to decide endpoint
      handleCustomSubmit(url);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetUrl, scanProfile, isScanStreaming, startScan, swarmSource, autopilotIntensity, auditSource, auditMode, auditIntensity, auditTimeout, auditDiff, auditLastCommits, auditCommitDepth, auditFiles, auditPiProvider, auditPiModel, auditUploadResults]);

  const handleCustomSubmit = useCallback((url: string) => {
    if (advancedMode === 'swarm') {
      const body: Record<string, unknown> = {};
      if (url) {
        if (detectedInputType === 'raw') {
          body.http_request_base64 = btoa(url);
        } else {
          body.input = url;
        }
      }
      if (swarmInputs) body.inputs = swarmInputs.split('\n').map((s) => s.trim()).filter(Boolean);
      if (swarmSource) body.source = swarmSource;
      if (swarmModuleTags) body.module_names = swarmModuleTags.split(',').map((t) => t.trim()).filter(Boolean);
      if (swarmAgent) body.agent = swarmAgent;
      if (swarmVulnType) body.vuln_type = swarmVulnType;
      if (swarmMaxIterations) body.max_iterations = parseInt(swarmMaxIterations, 10);
      if (swarmTimeout) body.timeout = swarmTimeout;
      if (swarmDryRun) body.dry_run = true;
      if (swarmScanUuid) body.scan_uuid = swarmScanUuid;
      if (swarmProjectUuid) body.project_uuid = swarmProjectUuid;
      if (swarmInstruction) body.instruction = swarmInstruction;
      if (swarmFiles) body.files = swarmFiles.split('\n').map((s) => s.trim()).filter(Boolean);
      if (swarmFocus) body.focus = swarmFocus;
      if (swarmProfile) body.profile = swarmProfile;
      if (swarmSourceAnalysisOnly) body.source_analysis_only = true;
      if (swarmDiscover) body.discover = true;
      if (swarmCodeAudit) body.code_audit = true;
      if (swarmDiff) body.diff = swarmDiff;
      if (swarmLastCommits) body.last_commits = parseInt(swarmLastCommits, 10);
      if (swarmTriage) body.triage = true;
      if (swarmOnlyPhase) body.only_phase = swarmOnlyPhase;
      if (swarmSkipPhases) body.skip_phases = swarmSkipPhases.split(',').map((s) => s.trim()).filter(Boolean);
      if (swarmStartFrom) body.start_from = swarmStartFrom;
      if (swarmShowPrompt) body.show_prompt = true;
      if (swarmAudit) body.audit = swarmAudit;
      if (swarmIntensity) body.intensity = swarmIntensity;
      startScan('/api/agent/run/swarm', body);
    } else if (advancedMode === 'autopilot') {
      const body: Record<string, unknown> = {};
      if (url) body.target = url;
      if (autopilotAgent) body.agent = autopilotAgent;
      if (autopilotFocus) body.focus = autopilotFocus;
      if (autopilotTimeout) body.timeout = autopilotTimeout;
      if (autopilotInstruction) body.instruction = autopilotInstruction;
      if (autopilotMaxCommands) body.max_commands = parseInt(autopilotMaxCommands, 10);
      if (autopilotDryRun) body.dry_run = true;
      if (autopilotSource) body.source = autopilotSource;
      if (autopilotFiles) body.files = autopilotFiles.split(',').map((f) => f.trim()).filter(Boolean);
      if (autopilotScanUuid) body.scan_uuid = autopilotScanUuid;
      if (autopilotDiff) body.diff = autopilotDiff;
      if (autopilotAuditMode) body.audit_mode = autopilotAuditMode;
      if (autopilotNoAudit) body.no_audit = true;
      if (autopilotIntensity) body.intensity = autopilotIntensity;
      startScan('/api/agent/run/autopilot', body);
    } else {
      // query
      const body: Record<string, unknown> = {};
      if (scanMode === 'template') {
        if (agentName) body.agent = agentName;
        if (promptTemplate) body.prompt_template = promptTemplate;
      } else {
        if (customPrompt) body.prompt = customPrompt;
      }
      if (repoPath) body.source = repoPath;
      if (queryFiles) body.files = queryFiles.split(',').map((f) => f.trim()).filter(Boolean);
      if (append) body.append = append;
      if (querySource) body.source = querySource;
      if (queryScanUuid) body.scan_uuid = queryScanUuid;
      if (queryInstruction) body.instruction = queryInstruction;
      if (querySourceLabel) body.source_label = querySourceLabel;
      startScan('/api/agent/run/query', body);
    }
  }, [advancedMode, detectedInputType, swarmInputs, swarmSource, swarmModuleTags, swarmAgent, swarmVulnType, swarmMaxIterations, swarmTimeout, swarmDryRun, swarmScanUuid, swarmProjectUuid, swarmInstruction, swarmFiles, swarmFocus, swarmProfile, swarmSourceAnalysisOnly, swarmDiscover, swarmCodeAudit, swarmDiff, swarmLastCommits, swarmTriage, swarmOnlyPhase, swarmSkipPhases, swarmStartFrom, swarmShowPrompt, swarmAudit, swarmIntensity, autopilotAgent, autopilotFocus, autopilotTimeout, autopilotInstruction, autopilotMaxCommands, autopilotDryRun, autopilotSource, autopilotFiles, autopilotScanUuid, autopilotDiff, autopilotAuditMode, autopilotNoAudit, autopilotIntensity, scanMode, agentName, promptTemplate, customPrompt, repoPath, queryFiles, append, querySource, queryScanUuid, queryInstruction, querySourceLabel, startScan]);

  // Chat
  const handleChatSend = useCallback(() => {
    const text = chatInput.trim();
    if (!text || isChatStreaming) return;
    setChatInput('');
    const newMessages: ChatMessage[] = [...messages, { role: 'user', content: text }];
    setMessages(newMessages);
    setIsChatStreaming(true);

    const abort = new AbortController();
    chatAbortRef.current = abort;

    setMessages((prev) => [...prev, { role: 'assistant', content: '' }]);

    fetchSSE('/api/agent/chat/completions', {
      model: 'default',
      messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
    }, {
      onChunk: (chunk) => {
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = { ...last, content: last.content + chunk };
          }
          return updated;
        });
      },
      onDone: () => {
        setIsChatStreaming(false);
        chatAbortRef.current = null;
      },
      onError: (err) => {
        setIsChatStreaming(false);
        chatAbortRef.current = null;
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = { ...last, content: last.content + `\n\n**Error:** ${err.message}` };
          }
          return updated;
        });
      },
    }, abort.signal);
  }, [chatInput, isChatStreaming, messages]);

  const handleChatKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleChatSend();
    }
  }, [handleChatSend]);

  // Repo upload
  const doUpload = useCallback((file: File) => {
    uploadRepo.mutate(file, {
      onSuccess: (data) => {
        if (advancedMode === 'swarm') setSwarmSource(data.source ?? '');
        else if (advancedMode === 'autopilot') setAutopilotSource(data.source ?? '');
        else if (advancedMode === 'audit') setAuditSource(data.source ?? '');
        else if (advancedMode === 'query') setRepoPath(data.source ?? '');
      },
    });
  }, [uploadRepo, advancedMode]);

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    doUpload(file);
    e.target.value = '';
  }, [doUpload]);

  const readEntryRecursive = (entry: FileSystemEntry): Promise<{ path: string; file: File }[]> => {
    return new Promise((resolve) => {
      if (entry.isFile) {
        (entry as FileSystemFileEntry).file((f) => resolve([{ path: entry.fullPath.replace(/^\//, ''), file: f }]));
      } else {
        const reader = (entry as FileSystemDirectoryEntry).createReader();
        const results: { path: string; file: File }[] = [];
        const readBatch = () => {
          reader.readEntries(async (entries) => {
            if (entries.length === 0) { resolve(results); return; }
            for (const e of entries) {
              results.push(...await readEntryRecursive(e));
            }
            readBatch();
          });
        };
        readBatch();
      }
    });
  };

  const compressAndUpload = useCallback(async (items: DataTransferItemList) => {
    const entries: FileSystemEntry[] = [];
    for (let i = 0; i < items.length; i++) {
      const entry = items[i].webkitGetAsEntry?.();
      if (entry) entries.push(entry);
    }
    if (entries.length === 0) return;
    if (entries.length === 1 && entries[0].isFile) {
      const item = items[0];
      const file = item.getAsFile();
      if (file && /\.(zip|tar|tar\.gz|tgz)$/i.test(file.name)) {
        doUpload(file);
        return;
      }
    }
    setUploadCompressing(true);
    try {
      const allFiles: { path: string; file: File }[] = [];
      for (const entry of entries) {
        allFiles.push(...await readEntryRecursive(entry));
      }
      if (allFiles.length === 0) { setUploadCompressing(false); return; }
      const zipData: Record<string, Uint8Array> = {};
      for (const { path, file } of allFiles) {
        const buf = await file.arrayBuffer();
        zipData[path] = new Uint8Array(buf);
      }
      const zipped = zipSync(zipData);
      const zipFile = new File([new Uint8Array(zipped) as BlobPart], 'repo.zip', { type: 'application/zip' });
      setUploadCompressing(false);
      doUpload(zipFile);
    } catch {
      setUploadCompressing(false);
    }
  }, [doUpload]);

  const onUploadDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    uploadDragCounter.current++;
    setUploadDragging(true);
  }, []);
  const onUploadDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    uploadDragCounter.current--;
    if (uploadDragCounter.current === 0) setUploadDragging(false);
  }, []);
  const onUploadDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
  }, []);
  const onUploadDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation();
    uploadDragCounter.current = 0;
    setUploadDragging(false);
    if (uploadRepo.isPending) return;
    const items = e.dataTransfer.items;
    if (items && items.length > 0) {
      compressAndUpload(items);
    } else {
      const file = e.dataTransfer.files?.[0];
      if (file) doUpload(file);
    }
  }, [compressAndUpload, doUpload, uploadRepo.isPending]);

  return {
    // Hero
    targetUrl, setTargetUrl,
    scanProfile, setScanProfile,
    handleProfileSubmit,

    // Advanced
    showAdvanced, setShowAdvanced,
    advancedMode, setAdvancedMode,

    // Input detection
    detectedInputType,

    // Swarm fields
    inputMode, setInputMode,
    swarmAgent, setSwarmAgent,
    swarmModuleTags, setSwarmModuleTags,
    swarmVulnType, setSwarmVulnType,
    swarmMaxIterations, setSwarmMaxIterations,
    swarmTimeout, setSwarmTimeout,
    swarmDryRun, setSwarmDryRun,
    swarmScanUuid, setSwarmScanUuid,
    swarmProjectUuid, setSwarmProjectUuid,
    swarmInstruction, setSwarmInstruction,
    swarmFiles, setSwarmFiles,
    swarmFocus, setSwarmFocus,
    swarmProfile, setSwarmProfile,
    swarmSource, setSwarmSource,
    swarmInputs, setSwarmInputs,
    swarmSourceAnalysisOnly, setSwarmSourceAnalysisOnly,
    swarmDiscover, setSwarmDiscover,
    swarmCodeAudit, setSwarmCodeAudit,
    swarmDiff, setSwarmDiff,
    swarmLastCommits, setSwarmLastCommits,
    swarmTriage, setSwarmTriage,
    swarmOnlyPhase, setSwarmOnlyPhase,
    swarmSkipPhases, setSwarmSkipPhases,
    swarmStartFrom, setSwarmStartFrom,
    swarmShowPrompt, setSwarmShowPrompt,
    swarmAudit, setSwarmAudit,
    swarmIntensity, setSwarmIntensity,

    // Autopilot fields
    autopilotAgent, setAutopilotAgent,
    autopilotFocus, setAutopilotFocus,
    autopilotTimeout, setAutopilotTimeout,
    autopilotInstruction, setAutopilotInstruction,
    autopilotMaxCommands, setAutopilotMaxCommands,
    autopilotDryRun, setAutopilotDryRun,
    autopilotSource, setAutopilotSource,
    autopilotFiles, setAutopilotFiles,
    autopilotScanUuid, setAutopilotScanUuid,
    autopilotDiff, setAutopilotDiff,
    autopilotAuditMode, setAutopilotAuditMode,
    autopilotNoAudit, setAutopilotNoAudit,
    autopilotIntensity, setAutopilotIntensity,

    // Audit fields
    auditSource, setAuditSource,
    auditMode, setAuditMode,
    auditIntensity, setAuditIntensity,
    auditTimeout, setAuditTimeout,
    auditDiff, setAuditDiff,
    auditLastCommits, setAuditLastCommits,
    auditCommitDepth, setAuditCommitDepth,
    auditFiles, setAuditFiles,
    auditPiProvider, setAuditPiProvider,
    auditPiModel, setAuditPiModel,
    auditUploadResults, setAuditUploadResults,
    // Source visible in the upload card depends on the active mode.
    activeSource: advancedMode === 'audit' ? auditSource : advancedMode === 'autopilot' ? (autopilotSource || swarmSource) : swarmSource,

    // Query fields
    scanMode, setScanMode,
    agentName, setAgentName,
    promptTemplate, setPromptTemplate,
    customPrompt, setCustomPrompt,
    repoPath, setRepoPath,
    queryFiles, setQueryFiles,
    append, setAppend,
    querySource, setQuerySource,
    queryScanUuid, setQueryScanUuid,
    queryInstruction, setQueryInstruction,
    querySourceLabel, setQuerySourceLabel,

    // Target input tab (prompt-based autopilot)
    targetInputTab, setTargetInputTab,
    targetPrompt, setTargetPrompt,
    targetRunId, targetRunStatus, targetError,
    startAutopilotRun, handleTargetSubmit,

    // Async scan run (status-polled). Full runtime.log pages load in the shared viewer;
    // scanOutput contains only the optional live tail. scanResult/scanError surface
    // the durable run outcome independently of the chosen log display mode.
    scanOutput: activeRunId ? sessionLogs : '',
    scanResult,
    scanError: scanError
      || (activeRunId && (activeRunStatus?.status === 'failed' || activeRunStatus?.status === 'error')
        ? (activeRunStatus?.error || 'run failed')
        : ''),
    isScanStreaming, handleScanCancel,
    cancelRunByUuid, cancelingUuids, cancelErrorForUuid,
    activeRunStatusError, cancelError,
    activeRunStatusRetry: () => activeRunQuery.refetch?.(),
    streamingOpen, setStreamingOpen,
    consoleMode, setConsoleMode,
    scanOutputRef: scanOutputTail.ref,
    onScanOutputScroll: scanOutputTail.onScroll,

    // Run status and log connection status are independent: losing the console
    // connection does not stop the durable server-side agent run.
    panelOutput: sessionLogs,
    panelIsRunning: startAgentRun.isPending || (!!expandedSessionUuid &&
      (sessionDetail?.status ? !isTerminalAgentStatus(sessionDetail.status) : activeRunId === expandedSessionUuid && !activeRunTerminal)),
    panelConnection: sessionLog.connection,
    panelTruncated: sessionLog.truncated,
    panelLogSize: sessionLog.logSize,
    panelRetry: sessionLog.retry,
    panelError: [scanError, sessionLog.error].filter(Boolean).join('\n'),
    panelPlaceholder: sessionsData?.data && sessionsData.data.length > 0
      ? 'Select a session above or start a new scan...'
      : 'agent output will appear here...',

    // Chat
    chatOpen, setChatOpen,
    messages, chatInput, setChatInput,
    isChatStreaming, handleChatSend, handleChatCancel, handleChatKeyDown,
    chatEndRef,

    // Upload
    uploadDragging, uploadCompressing, uploadFileInputRef, uploadRepo,
    handleFileUpload, onUploadDragEnter, onUploadDragLeave, onUploadDragOver, onUploadDrop,

    // Sessions
    expandedSessionUuid, setExpandedSessionUuid,
    selectedArtifact, setSelectedArtifact,
    sessionsData, sessionsLoading, sessionsBusy, sessionsError,
    sessionsOffset, sessionsCount, sessionsTotal, sessionsHasNext, sessionsPrevious, sessionsNext,
    sessionsRetry: () => sessionsQuery.refetch?.(),
    sessionDetail, sessionDetailError,
    sessionDetailLoading: !!sessionDetailQuery.isPending,
    sessionDetailRetry: () => sessionDetailQuery.refetch?.(),
    sessionSelectionKey,
  };
}
