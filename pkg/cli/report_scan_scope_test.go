package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

// stubReportFormat collects a small test producer so selection can be asserted
// without invoking a real renderer. Production reports never use this collector.
func stubReportFormat(captured *[]any) reportFormatEntry {
	return reportFormatEntry{
		format: "report",
		label:  "stub",
		streamGenerate: func(produce output.ReportItemProducer, _ string, _ output.HTMLReportMeta) error {
			*captured = nil
			return produce(func(item any) error { *captured = append(*captured, item); return nil })
		},
	}
}

// seedScanFinding inserts one finding attributed to scanUUID.
func seedScanFinding(t *testing.T, db *database.DB, project, scanUUID, suffix string) {
	t.Helper()
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(context.Background(), &database.Finding{
		ProjectUUID: project,
		ScanUUID:    scanUUID,
		ModuleID:    "mod-" + suffix,
		ModuleName:  "Module " + suffix,
		Severity:    "high",
		Confidence:  "firm",
		FindingHash: "hash-" + suffix,
		URL:         "http://" + suffix + ".example/",
		Hostname:    suffix + ".example",
	}))
}

// findingModuleIDs pulls the module ids out of an exported item slice.
func findingModuleIDs(items []any) []string {
	var out []string
	for _, it := range items {
		env, ok := it.(exportEnvelope)
		if !ok || env.Type != "finding" {
			continue
		}
		if f, ok := env.Data.(*database.Finding); ok {
			out = append(out, f.ModuleID)
		}
	}
	return out
}

// TestGenerateReportFromDBScopesMaterializedFormatsToScan guards the historical
// document-format scope bug. All formats now use producers, and must still pass
// the captured scan UUID rather than exporting the project's entire history.
func TestGenerateReportFromDBScopesMaterializedFormatsToScan(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)

	const project = ""
	seedScanFinding(t, db, project, "scan-current", "current")
	seedScanFinding(t, db, project, "scan-previous", "previous")

	// A stub generator keeps this a selection test — no renderer, no Chrome.
	var captured []any
	stub := stubReportFormat(&captured)

	out := filepath.Join(t.TempDir(), "r.out")
	require.NoError(t, generateReportFromDB(ctx, db, out, false, project, "scan-current", stub, nil))

	ids := findingModuleIDs(captured)
	assert.Contains(t, ids, "mod-current", "the current scan's finding must be rendered")
	assert.NotContains(t, ids, "mod-previous",
		"a previous scan's finding leaked into this scan's report (materialized branch dropped scanUUID)")
}

// An explicit whole-project export (empty scanUUID) must still see everything.
func TestGenerateReportFromDBEmptyScanUUIDExportsWholeProject(t *testing.T) {
	ctx := context.Background()
	db := newExportTestDB(t)

	seedScanFinding(t, db, "", "scan-a", "alpha")
	seedScanFinding(t, db, "", "scan-b", "bravo")

	var captured []any
	stub := stubReportFormat(&captured)

	out := filepath.Join(t.TempDir(), "r.out")
	require.NoError(t, generateReportFromDB(ctx, db, out, false, "", "", stub, nil))

	ids := findingModuleIDs(captured)
	assert.Contains(t, ids, "mod-alpha")
	assert.Contains(t, ids, "mod-bravo")
}
