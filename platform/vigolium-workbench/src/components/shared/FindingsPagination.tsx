'use client';

interface Props {
  offset: number;
  pageSize: number;
  returned: number;
  total: number;
  hasMore?: boolean;
  busy: boolean;
  onPageChange: (page: number) => void;
  ariaLabel?: string;
}

/** The same server-page controls in table and grouped views, in both themes. */
export default function FindingsPagination({ offset, pageSize, returned, total, hasMore, busy, onPageChange, ariaLabel = 'Findings pagination' }: Props) {
  const page = Math.floor(offset / pageSize) + 1;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const canNext = hasMore ?? offset + pageSize < total;
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + returned, total);

  return (
    <nav
      aria-label={ariaLabel}
      aria-busy={busy}
      className="shrink-0 flex items-center justify-between flex-wrap gap-2 px-3 py-2 border-t text-xs"
      style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}
    >
      <span aria-live="polite">
        {busy ? 'Loading findings…' : `${start}–${end} of ${total} findings`}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={busy || page <= 1}
          className="min-h-8 px-3 py-1 border rounded-sm hover:opacity-80 disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ borderColor: 'var(--v-border)', color: 'var(--v-accent)' }}
        >
          Previous
        </button>
        <span>Page {page} of {pages}</span>
        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={busy || !canNext}
          className="min-h-8 px-3 py-1 border rounded-sm hover:opacity-80 disabled:opacity-40 disabled:cursor-not-allowed"
          style={{ borderColor: 'var(--v-border)', color: 'var(--v-accent)' }}
        >
          Next
        </button>
      </div>
    </nav>
  );
}
