package database

import (
	"context"
	"fmt"
	"strings"
)

// UNION (not UNION ALL) makes malformed cycles finite. The project predicate
// on every recursion edge prevents a foreign historical child being followed.
const agenticRunTreeCTE = `WITH RECURSIVE run_tree(uuid) AS (
	SELECT uuid FROM agentic_scans WHERE uuid = ? AND project_uuid = ?
	UNION
	SELECT child.uuid FROM agentic_scans child JOIN run_tree parent ON child.parent_run_uuid = parent.uuid WHERE child.project_uuid = ?
)`

// EXISTS counts a finding once even when it has both direct and native links.
// A native re-detection must not claim a canonical finding with an older owner.
const agenticRunFindingPredicate = `f.project_uuid = ?
	AND (f.record_kind IS NULL OR f.record_kind = '' OR f.record_kind = ?)
	AND (f.agentic_scan_uuid IN (SELECT uuid FROM run_tree)
		OR ((f.agentic_scan_uuid IS NULL OR f.agentic_scan_uuid = '') AND EXISTS (
			SELECT 1 FROM scans s WHERE s.uuid = f.scan_uuid AND s.project_uuid = f.project_uuid
			AND s.agentic_scan_uuid IN (SELECT uuid FROM run_tree))))`

func (r *Repository) agenticRunFindingArgs(ctx context.Context, projectUUID, rootUUID string) ([]any, error) {
	if rootUUID == "" {
		return nil, fmt.Errorf("missing agentic scan UUID")
	}
	projectUUID = defaultProjectUUID(projectUUID)
	root, err := r.GetAgenticScan(ctx, rootUUID)
	if err != nil {
		return nil, err
	}
	if defaultProjectUUID(root.ProjectUUID) != projectUUID {
		return nil, fmt.Errorf("%w: finding count root belongs to another project", ErrScanProjectMismatch)
	}
	return []any{rootUUID, projectUUID, projectUUID, projectUUID, RecordKindFinding}, nil
}

// CountAgenticScanFindings counts distinct persisted canonical findings for a
// run and its same-project descendants, including native child scans whose
// findings have not yet acquired a direct agentic parent. It never reassigns
// historical ownership or infers attribution from URLs, timestamps or modules.
// Missing roots, foreign roots and query failures return an error, not zero.
func (r *Repository) CountAgenticScanFindings(ctx context.Context, projectUUID, rootUUID string) (int64, map[string]int64, error) {
	args, err := r.agenticRunFindingArgs(ctx, projectUUID, rootUUID)
	if err != nil {
		return 0, nil, fmt.Errorf("finding count unavailable: %w", err)
	}
	var rows []SeverityCount
	err = r.db.NewRaw(agenticRunTreeCTE+`
	SELECT f.severity, COUNT(*) AS count FROM findings f
	WHERE `+agenticRunFindingPredicate+` GROUP BY f.severity`, args...).Scan(ctx, &rows)
	if err != nil {
		return 0, nil, fmt.Errorf("finding count unavailable: %w", err)
	}
	counts := make(map[string]int64, len(rows))
	var total int64
	for _, row := range rows {
		counts[strings.ToLower(strings.TrimSpace(row.Severity))] += row.Count
		total += row.Count
	}
	return total, counts, nil
}

// ListAgenticScanFindings returns a bounded, severity-first summary using the
// exact same ownership predicate as CountAgenticScanFindings. It does not
// hydrate raw traffic or evidence corpora. A positive limit is required.
func (r *Repository) ListAgenticScanFindings(ctx context.Context, projectUUID, rootUUID string, limit int) ([]*Finding, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("a positive finding summary limit is required")
	}
	args, err := r.agenticRunFindingArgs(ctx, projectUUID, rootUUID)
	if err != nil {
		return nil, err
	}
	args = append(args, limit)
	var findings []*Finding
	err = r.db.NewRaw(agenticRunTreeCTE+`
	SELECT f.* FROM findings f WHERE `+agenticRunFindingPredicate+`
	ORDER BY CASE LOWER(TRIM(f.severity))
		WHEN 'critical' THEN 6 WHEN 'high' THEN 5 WHEN 'medium' THEN 4
		WHEN 'low' THEN 3 WHEN 'info' THEN 2 WHEN 'suspect' THEN 1 ELSE 0 END DESC,
		f.found_at DESC, f.id DESC LIMIT ?`, args...).Scan(ctx, &findings)
	return findings, err
}
