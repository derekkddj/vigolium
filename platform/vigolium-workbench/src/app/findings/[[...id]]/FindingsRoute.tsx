'use client';

import { Suspense } from 'react';
import { useParams } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import { parseLegacyDetailId } from '@/lib/detailSelection';
import DarkFindingsPage from '@/designs/dark/FindingsPage';
import LightFindingsPage from '@/designs/light/FindingsPage';

export default function FindingsRoute() {
  // useSearchParams in the shared selection hook needs a client boundary for
  // static export; no query-specific detail is emitted into the static HTML.
  return <Suspense fallback={null}><FindingsContent /></Suspense>;
}

function FindingsContent() {
  const { themeId } = useTheme();
  const params = useParams();
  const initialId = parseLegacyDetailId('finding', params?.id);
  return themeId === 'dark'
    ? <DarkFindingsPage initialId={initialId} />
    : <LightFindingsPage initialId={initialId} />;
}
