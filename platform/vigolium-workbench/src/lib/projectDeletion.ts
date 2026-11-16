import type { DeleteProjectResponse } from '@/api/types';

export interface ProjectDeletionSummary {
  successMessage: string;
  diskFailureMessage?: string;
}

export function summarizeProjectDeletion(result: DeleteProjectResponse): ProjectDeletionSummary {
  if (result.mode !== 'purge') {
    return { successMessage: 'Project deleted; data moved to Default.' };
  }

  const rowCount = Object.values(result.rows_deleted ?? {}).reduce((total, count) => total + count, 0);
  const configStatus = result.config_dir_deleted ? 'config directory deleted' : 'config directory not removed';
  const successMessage = `Project purged: ${rowCount} rows removed, ${result.session_dirs_deleted ?? 0} session directories deleted, ${configStatus}.`;
  const failures = result.disk_deletion_failures ?? [];

  return {
    successMessage,
    ...(failures.length > 0 && {
      diskFailureMessage: `Disk cleanup failed for ${failures.length} path(s): ${failures.join(', ')}`,
    }),
  };
}
