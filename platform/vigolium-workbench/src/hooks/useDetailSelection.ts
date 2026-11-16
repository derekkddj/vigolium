'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { getProjectUUID } from '@/api/client';
import { useProjectContext } from '@/contexts/ProjectContext';
import {
  DETAIL_ROUTES, detailIdFromSearch, detailSelectionHref, legacyDetailIdFromPath, parseDetailId,
  type DetailSelectionKind, type DetailSelectionValues,
} from '@/lib/detailSelection';

const HISTORY_PROJECT_KEY = '__vigoliumDetailProject';

/** Shared by both themes; query strings are consumed only after hydration. */
export function useDetailSelection<K extends DetailSelectionKind>(kind: K, initialId?: DetailSelectionValues[K] | null) {
  const { projectUUID } = useProjectContext();
  // Next/Link can change a same-page query without a popstate event. Treat it
  // only as a resync signal; never derive SSR/initial render selection from it.
  const searchParams = useSearchParams();
  const searchVersion = searchParams?.toString();
  // Match the API client's scope during ProjectContext's localStorage bootstrap.
  const project = getProjectUUID() ?? projectUUID ?? 'default';
  const [selection, setSelection] = useState<{ project: string; id: DetailSelectionValues[K] | null }>(() => ({ project, id: null }));
  const previousProject = useRef(project);

  const writeURL = useCallback((id: DetailSelectionValues[K] | null, replace: boolean) => {
    const href = detailSelectionHref(kind, id);
    const state = { ...window.history.state, [HISTORY_PROJECT_KEY]: project };
    if (replace || href === window.location.pathname + window.location.search + window.location.hash) {
      window.history.replaceState(state, '', href);
    } else {
      window.history.pushState(state, '', href);
    }
  }, [kind, project]);

  const syncFromURL = useCallback(() => {
    const { pathname, search } = window.location;
    const { path } = DETAIL_ROUTES[kind];
    if (pathname !== path.slice(0, -1) && !pathname.startsWith(path)) {
      setSelection({ project, id: null });
      return;
    }
    // Back to a known old-project entry must not hydrate that ID in this project.
    const entryProject = window.history.state?.[HISTORY_PROJECT_KEY];
    if (entryProject !== undefined && entryProject !== project) {
      writeURL(null, true);
      setSelection({ project, id: null });
      return;
    }
    const legacyId = legacyDetailIdFromPath(kind, pathname);
    // Retain validated dev/backwards-compatible route props only while actually
    // on that legacy path. A stale initialId must never reopen a closed panel.
    const fallback = legacyId !== null && legacyId === parseDetailId(kind, initialId) ? initialId : legacyId;
    const id = detailIdFromSearch(kind, search, fallback);
    window.history.replaceState({ ...window.history.state, [HISTORY_PROJECT_KEY]: project }, '');
    setSelection({ project, id });
  }, [kind, initialId, project, writeURL]);

  useEffect(() => {
    if (previousProject.current !== project) {
      previousProject.current = project;
      writeURL(null, true);
      setSelection({ project, id: null });
    } else {
      syncFromURL();
    }
    window.addEventListener('popstate', syncFromURL);
    return () => window.removeEventListener('popstate', syncFromURL);
  }, [project, searchVersion, syncFromURL, writeURL]);

  const selectDetail = useCallback((value: DetailSelectionValues[K] | null) => {
    const id = parseDetailId(kind, value);
    writeURL(id, false);
    setSelection({ project, id });
  }, [kind, project, writeURL]);

  return {
    // Suppress the old ID during the very first new-project render, before an
    // effect runs and before a detail component can fetch it in the wrong scope.
    selectedId: selection.project === project ? selection.id : null,
    selectDetail,
    projectKey: project,
  };
}
