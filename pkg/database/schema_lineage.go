package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// ErrSchemaLineageRequiresConversion is deliberately NOT ErrSchemaOutdated:
// ordinary read auto-migration and `db migrate` cannot convert this lineage.
var ErrSchemaLineageRequiresConversion = errors.New("database schema lineage requires explicit conversion")

// SchemaLineageRequiresConversionError fences a local receipts-era catalog (or
// an incomplete mixture of it and upstream) before ordinary schema mutation.
// Version and written_by are not provenance: both branches used versions 6..9,
// and a previous ordinary open may already have changed the stamp.
type SchemaLineageRequiresConversionError struct {
	Missing []string
}

func (e *SchemaLineageRequiresConversionError) Error() string {
	return fmt.Sprintf("%v: receipts-era local or mixed catalog lacks upstream markers (%s); refusing ordinary schema migration — preserve the source and use a separately validated lineage conversion, not `vigolium db migrate` or auto_migrate_on_read",
		ErrSchemaLineageRequiresConversion, strings.Join(e.Missing, ", "))
}

func (e *SchemaLineageRequiresConversionError) Is(target error) bool {
	return target == ErrSchemaLineageRequiresConversion
}

func (e *SchemaLineageRequiresConversionError) Code() apicontract.ErrorCode {
	return apicontract.CodeSchemaLineageRequiresConversion
}

// guardSchemaLineage uses the existing SQLite/PostgreSQL catalogs, never data
// values or numeric stamps. Even one surviving protected table is enough to
// fence a partial/mixed local v6..9 store when upstream markers are missing.
// The frozen historical signature is in testdata/schema_local_v9.sql; this is
// intentionally independent of the current DDL/column migration lists.
//
// This is a small safety fence, NOT a provenance attestation or converter. A
// contaminated store already given every combined-schema marker (including a
// combined-shaped v10) is indistinguishable here from a legitimate upstream
// store. We cannot safely infer its hash identity or history from its stamp or
// rows. Existing upstream stores with all markers remain usable without adoption.
//
// It prevents schema DDL/backfills/stamping through normal readiness/migration
// paths. NewDB's usual SQLite maintenance is unchanged; opening a source as a
// strictly byte-identical artifact still needs a dedicated neutral preflight.
func (db *DB) guardSchemaLineage(ctx context.Context) error {
	present, err := db.listSchemaObjects(ctx)
	if err != nil {
		return fmt.Errorf("schema lineage catalog unreadable: %w", err)
	}
	if !present["evidence_exchanges"] && !present["finding_evidence"] && !present["oast_planting_receipts"] {
		return nil
	}
	columns, err := listAllColumns(ctx, db)
	if err != nil {
		return fmt.Errorf("schema lineage column catalog unreadable: %w", err)
	}
	var missing []string
	if !present["finding_hash_aliases"] {
		missing = append(missing, "finding_hash_aliases")
	}
	for _, marker := range []struct{ table, column string }{
		{"findings", "last_seen_at"},
		{"scans", "module_stats"},
		{"scans", "coverage_modules"},
	} {
		if !columns[marker.table][marker.column] {
			missing = append(missing, marker.table+"."+marker.column)
		}
	}
	if len(missing) > 0 {
		return &SchemaLineageRequiresConversionError{Missing: missing}
	}
	return nil
}
