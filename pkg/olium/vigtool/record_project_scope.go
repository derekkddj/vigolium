package vigtool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

func effectiveRecordProjectUUID(projectUUID string) string {
	if projectUUID == "" {
		return database.DefaultProjectUUID
	}
	return projectUUID
}

// resolveRecordInProject resolves exact UUIDs and unambiguous prefixes without
// considering records outside the selected project. An empty project selection
// means the default project, not an unscoped lookup.
func resolveRecordInProject(ctx context.Context, repo *database.Repository, id, projectUUID string) (*database.HTTPRecord, error) {
	projectUUID = effectiveRecordProjectUUID(projectUUID)

	// Preserve exact-ID behavior (including short legacy IDs), but reject an
	// exact record from another project before returning its contents.
	record, err := repo.GetRecordByUUID(ctx, id)
	if err == nil {
		if record.ProjectUUID != projectUUID {
			return nil, fmt.Errorf("record %q does not belong to the current project", id)
		}
		return record, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(id) < database.MinUUIDPrefix {
		return nil, sql.ErrNoRows
	}

	fullUUID, candidates, err := repo.ResolveRecordUUIDInProject(ctx, id, projectUUID)
	if err != nil {
		return nil, err
	}
	if len(candidates) > 0 {
		uuids := make([]string, len(candidates))
		for index, candidate := range candidates {
			uuids[index] = candidate.UUID
		}
		return nil, fmt.Errorf("uuid prefix %q matches %d records (%s) - use more characters", id, len(uuids), strings.Join(uuids, ", "))
	}
	if fullUUID == "" {
		return nil, sql.ErrNoRows
	}

	record, err = repo.GetRecordByUUID(ctx, fullUUID)
	if err != nil {
		return nil, err
	}
	// Keep the ownership check even though the prefix resolver is scoped: the
	// row could change between the lookup and fetch, or be from legacy data.
	if record.ProjectUUID != projectUUID {
		return nil, fmt.Errorf("record %q does not belong to the current project", id)
	}
	return record, nil
}
