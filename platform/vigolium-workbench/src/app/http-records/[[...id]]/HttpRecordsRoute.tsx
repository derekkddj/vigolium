'use client';

import { Suspense } from 'react';
import { useParams } from 'next/navigation';
import { useTheme } from '@/contexts/ThemeContext';
import { parseLegacyDetailId } from '@/lib/detailSelection';
import DarkHttpRecordsPage from '@/designs/dark/HttpRecordsPage';
import LightHttpRecordsPage from '@/designs/light/HttpRecordsPage';

export default function HttpRecordsRoute() {
  // Keep same-page query navigation reactive without requiring a Next server.
  return <Suspense fallback={null}><HttpRecordsContent /></Suspense>;
}

function HttpRecordsContent() {
  const { themeId } = useTheme();
  const params = useParams();
  const initialId = parseLegacyDetailId('http-record', params?.id);
  return themeId === 'dark'
    ? <DarkHttpRecordsPage initialId={initialId} />
    : <LightHttpRecordsPage initialId={initialId} />;
}
