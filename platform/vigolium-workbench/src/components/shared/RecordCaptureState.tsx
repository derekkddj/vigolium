'use client';

import type { HTTPRecord } from '@/api/types';
import { evidencePalette, type EvidenceTheme } from './HttpMessage';

interface Props {
  record: Pick<HTTPRecord, 'capture_request_state' | 'capture_response_state'>;
  theme: EvidenceTheme;
}

/** Display only persisted fidelity; bytes, lengths and status cannot establish it. */
export default function RecordCaptureState({ record, theme }: Props) {
  const colors = evidencePalette[theme];
  return (
    <div className="flex flex-wrap gap-2" role="note" aria-label="Saved capture fidelity" style={{ color: colors.muted }}>
      <span className="border px-1" style={{ borderColor: colors.border }}>Saved request state: {record.capture_request_state ?? 'not recorded / unknown'}</span>
      <span className="border px-1" style={{ borderColor: colors.border }}>Saved response state: {record.capture_response_state ?? 'not recorded / unknown'}</span>
    </div>
  );
}
