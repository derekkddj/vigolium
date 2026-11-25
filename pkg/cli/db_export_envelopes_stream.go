package cli

import (
	"context"
	"io"

	"github.com/vigolium/vigolium/pkg/database"
)

// streamDBEnvelopes exports both selected types without discovering findings
// through a materialized traffic page. Each type uses its shared predicates and
// pagination, so receipt-only findings remain selectable and two record links
// cannot duplicate a finding. The record spool closes its cursor before the
// finding reader lazily hydrates one receipt set at a time (including with a
// single-connection SQLite pool). The count is the number of emitted envelopes.
func streamDBEnvelopes(ctx context.Context, db *database.DB, filters database.QueryFilters, out io.Writer) (int, map[string]int, error) {
	scope := dbExportScope()
	counts := map[string]int{"records": 0, "http_record": 0, "finding": 0}
	n := 0
	if scope.includes("http") {
		count, err := streamRecordDBExport(ctx, db, filters, out)
		n += count
		counts["http_record"], counts["records"] = count, n
		if err != nil {
			return n, counts, err
		}
	}
	if scope.includes("findings") {
		count, err := exportFindingJSONL(ctx, db, filters, out)
		n += count
		counts["finding"], counts["records"] = count, n
		if err != nil {
			return n, counts, err
		}
	}
	return n, counts, nil
}
