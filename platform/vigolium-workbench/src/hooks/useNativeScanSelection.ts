'use client';

import { useCallback, useEffect, useRef, useState, type SetStateAction } from 'react';
import type { ScansQueryParams } from '@/api/types';
import { getProjectUUID } from '@/api/client';
import { useProjectContext } from '@/contexts/ProjectContext';

/** Reset pagination before a new project's query renders, not one effect later. */
export function useNativeScanHistory(pageSize: number, projectKey: string) {
  const [history, setHistory] = useState(() => ({ projectKey, params: { limit: pageSize, offset: 0 } as ScansQueryParams }));
  if (history.projectKey !== projectKey) {
    setHistory({ projectKey, params: { limit: pageSize, offset: 0 } });
  }
  const setParams = useCallback((value: SetStateAction<ScansQueryParams>) => {
    setHistory((previous) => {
      const params = previous.projectKey === projectKey ? previous.params : { limit: pageSize, offset: 0 };
      return { projectKey, params: typeof value === 'function' ? value(params) : value };
    });
  }, [pageSize, projectKey]);
  return [history.projectKey === projectKey ? history.params : { limit: pageSize, offset: 0 }, setParams] as const;
}

function browserUUID(): string | null {
  return new URLSearchParams(window.location.search).get('uuid')?.trim() || null;
}

const HISTORY_PROJECT_KEY = '__vigoliumNativeScanProject';

function writeUUID(uuid: string | null, project: string, replace = false) {
  const url = new URL(window.location.href);
  if (uuid) url.searchParams.set('uuid', uuid);
  else url.searchParams.delete('uuid');
  const href = url.pathname + url.search + url.hash;
  const state = { ...window.history.state, [HISTORY_PROJECT_KEY]: project };
  if (replace || href === window.location.pathname + window.location.search + window.location.hash) {
    window.history.replaceState(state, '', href);
  } else {
    window.history.pushState(state, '', href);
  }
}

/** Browser-only URL consumption keeps static HTML/hydration independent of query strings. */
export function useNativeScanSelection() {
  const { projectUUID } = useProjectContext();
  const project = getProjectUUID() ?? projectUUID ?? 'default';
  const [selection, setSelection] = useState<{ project: string; uuid: string | null }>(() => ({ project, uuid: null }));
  const previousProject = useRef(project);
  const syncFromURL = useCallback(() => {
    // Back/Forward must not reopen a known old-project selection in this scope.
    const entryProject = window.history.state?.[HISTORY_PROJECT_KEY];
    if (entryProject !== undefined && entryProject !== project) {
      writeUUID(null, project, true);
      setSelection({ project, uuid: null });
      return;
    }
    // Unstamped cold/shared URLs use the active project, without switching it.
    window.history.replaceState({ ...window.history.state, [HISTORY_PROJECT_KEY]: project }, '');
    setSelection({ project, uuid: browserUUID() });
  }, [project]);

  useEffect(() => {
    if (previousProject.current !== project) {
      previousProject.current = project;
      // Clear immediately on scope change; never reapply an old-project deep link.
      writeUUID(null, project, true);
      setSelection({ project, uuid: null });
    } else {
      syncFromURL();
    }
    window.addEventListener('popstate', syncFromURL);
    return () => window.removeEventListener('popstate', syncFromURL);
  }, [project, syncFromURL]);

  const selectScan = useCallback((uuid: string | null) => {
    writeUUID(uuid, project);
    setSelection({ project, uuid });
  }, [project]);

  return {
    selectedUUID: selection.project === project ? selection.uuid : null,
    selectScan, syncFromURL, projectKey: project,
  };
}
