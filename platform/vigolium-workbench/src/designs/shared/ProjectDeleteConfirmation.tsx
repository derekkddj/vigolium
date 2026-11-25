'use client';

import { useState } from 'react';

interface ProjectDeleteConfirmationProps {
  projectName: string;
  onDelete: (deleteData: boolean) => void;
  onCancel: () => void;
  isPending?: boolean;
}

/** Explicitly distinguishes moving project data to Default from irreversible purge. */
export default function ProjectDeleteConfirmation({
  projectName,
  onDelete,
  onCancel,
  isPending = false,
}: ProjectDeleteConfirmationProps) {
  const [confirmingPurge, setConfirmingPurge] = useState(false);
  const [typedName, setTypedName] = useState('');
  const canConfirmPurge = typedName === projectName;

  return (
    <section
      aria-label={`Delete project ${projectName}`}
      className="space-y-2 border p-2 text-xs"
      style={{ borderColor: 'var(--v-error)', backgroundColor: 'var(--v-surface)', color: 'var(--v-text)' }}
    >
      {!confirmingPurge ? (
        <>
          <p className="font-bold">Choose what happens to “{projectName}”:</p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => onDelete(false)}
              disabled={isPending}
              className="border px-2 py-1 font-bold disabled:opacity-50"
              style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
            >
              Delete project, keep data (move to Default)
            </button>
            <button
              type="button"
              onClick={() => setConfirmingPurge(true)}
              disabled={isPending}
              className="border px-2 py-1 font-bold disabled:opacity-50"
              style={{ borderColor: 'var(--v-error)', color: 'var(--v-error)' }}
            >
              Delete project AND all data (irreversible)
            </button>
            <button type="button" onClick={onCancel} disabled={isPending} className="px-2 py-1" style={{ color: 'var(--v-text-muted)' }}>
              Cancel
            </button>
          </div>
          <p style={{ color: 'var(--v-text-muted)' }}>
            Keeping data merges it into Default. Purging deletes project data from the database and disk.
          </p>
        </>
      ) : (
        <>
          <p className="font-bold" style={{ color: 'var(--v-error)' }}>
            This permanently deletes all project data from the database and disk. Type the project name to confirm.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              value={typedName}
              onChange={(event) => setTypedName(event.target.value)}
              aria-label="Type project name to confirm"
              autoComplete="off"
              className="border px-2 py-1"
              style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
            />
            <button
              type="button"
              onClick={() => onDelete(true)}
              disabled={!canConfirmPurge || isPending}
              className="border px-2 py-1 font-bold disabled:opacity-40"
              style={{ borderColor: 'var(--v-error)', color: 'var(--v-error)' }}
            >
              {isPending ? 'Deleting permanently…' : 'Confirm permanent deletion'}
            </button>
            <button
              type="button"
              onClick={() => { setConfirmingPurge(false); setTypedName(''); }}
              disabled={isPending}
              className="px-2 py-1"
              style={{ color: 'var(--v-text-muted)' }}
            >
              Back
            </button>
            <button type="button" onClick={onCancel} disabled={isPending} className="px-2 py-1" style={{ color: 'var(--v-text-muted)' }}>
              Cancel
            </button>
          </div>
        </>
      )}
    </section>
  );
}
