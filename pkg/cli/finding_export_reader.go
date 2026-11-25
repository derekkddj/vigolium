package cli

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/database"
)

// iterateFilteredEvidenceFindings reuses the shared findings predicates/sorting.
// Metadata pages are bounded, and all row cursors close before receipt hydration.
// RecordUUIDs is not yet a shared finding predicate: intersect the complete legacy
// junction/array reference union BEFORE applying the requested offset and limit.
func iterateFilteredEvidenceFindings(ctx context.Context, db *database.DB, filters database.QueryFilters, visit func(*database.Finding) error) error {
	const pageSize = 64
	wanted := make(map[string]struct{}, len(filters.RecordUUIDs))
	for _, id := range filters.RecordUUIDs {
		wanted[id] = struct{}{}
	}
	limit, skip := filters.Limit, filters.Offset
	filters.RecordUUIDs = nil
	filters.Limit, filters.Offset = pageSize, 0
	if len(wanted) == 0 {
		filters.Offset, skip = skip, 0
	}
	repo := database.NewRepository(db)
	emitted := 0
	for {
		page, err := database.NewFindingsQueryBuilder(db, filters).Execute(ctx)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		if err := repo.HydrateFindingRecordRefs(ctx, page); err != nil {
			return err
		}
		for i, f := range page {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Release the page's reference before hydration, so completed findings
			// do not accumulate up to a page of raw receipt bodies in memory.
			page[i] = nil
			if len(wanted) > 0 {
				matches := false
				for _, id := range f.HTTPRecordUUIDs {
					if _, ok := wanted[id]; ok {
						matches = true
						break
					}
				}
				if !matches {
					continue
				}
			}
			if skip > 0 {
				skip--
				continue
			}
			if err := hydrateFindingReaderEvidence(ctx, repo, []*database.Finding{f}, true, true); err != nil {
				return err
			}
			if err := visit(f); err != nil {
				return err
			}
			emitted++
			if limit > 0 && emitted >= limit {
				return nil
			}
		}
		filters.Offset += len(page)
	}
}

// iterateEvidenceFindings closes each metadata query before hydrating a finding.
// This stays bounded and works even with a one-connection SQLite pool; querying
// exchanges while holding a raw row cursor can otherwise deadlock the exporter.
// Callers supply found_at/id ordering matching asc, and an optional total limit.
func iterateEvidenceFindings(ctx context.Context, db *database.DB, query *bun.SelectQuery, asc bool, limit int, visit func(*database.Finding) error) error {
	// Compare SQLite's stored timestamp text to itself, not a reformatted Go
	// time. This also retains the supplied query's exact timestamp/id ordering.
	type cursorRow struct {
		database.Finding
		CursorTime string `bun:"export_cursor_time"`
	}
	var lastTime any
	var lastID int64
	repo := database.NewRepository(db)
	for n := 0; limit <= 0 || n < limit; n++ {
		q := query.Clone().ExcludeColumn("request", "response", "additional_evidence").
			ColumnExpr("CAST(f.found_at AS TEXT) AS export_cursor_time").Limit(1)
		if n > 0 {
			q = q.Offset(0) // initial offset applies once, not on every keyset page
			op := "<"
			if asc {
				op = ">"
			}
			q = q.Where(fmt.Sprintf("(f.found_at %s ? OR (f.found_at = ? AND f.id %s ?))", op, op), lastTime, lastTime, lastID)
		}
		var page []*cursorRow
		if err := q.Scan(ctx, &page); err != nil {
			return err
		}
		if len(page) == 0 {
			return nil
		}
		f := &page[0].Finding
		lastTime, lastID = f.FoundAt, f.ID
		if db.Driver() == "sqlite" {
			lastTime = page[0].CursorTime
		}
		if err := hydrateFindingReaderEvidence(ctx, repo, []*database.Finding{f}, true, true); err != nil {
			return err
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}
