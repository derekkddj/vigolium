package database

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/uptrace/bun"
)

// This is an ordinary upstream pre-v6 model, not a local receipts fixture.
// The existing compatibility test and interruption tests use the same shape.
func stripUpstreamPreV6LineageAdditions(t *testing.T, db *DB) {
	t.Helper()
	for _, statement := range []string{
		"DROP TABLE evidence_exchanges", "DROP TABLE finding_evidence", "DROP TABLE oast_planting_receipts",
		"DROP TABLE finding_hash_aliases", "ALTER TABLE findings DROP COLUMN last_seen_at",
		"ALTER TABLE scans DROP COLUMN module_stats", "ALTER TABLE scans DROP COLUMN coverage_modules",
		"UPDATE schema_meta SET version = 5, min_reader_version = 1",
	} {
		mustExec(t, db, statement)
	}
}

func normalizedLineageQuery(query string) string {
	return strings.ToUpper(strings.Join(strings.Fields(query), " "))
}

type lineageReceiptCancelHook struct {
	table  string
	cancel context.CancelFunc
	fired  bool
}

func (h *lineageReceiptCancelHook) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (h *lineageReceiptCancelHook) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	if h.fired || event.Err != nil || !strings.HasPrefix(normalizedLineageQuery(event.Query),
		"CREATE TABLE IF NOT EXISTS "+strings.ToUpper(h.table)+" (") {
		return
	}
	// Cancellation happens AFTER a successful, individually committed receipts
	// CREATE, not before the lineage guard or on a failed statement.
	h.fired = true
	h.cancel()
}

func assertLineageInterruptedMigrationRetry(t *testing.T, db *DB, table string, version int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook := &lineageReceiptCancelHook{table: table, cancel: cancel}
	interrupted := &DB{DB: db.WithQueryHook(hook), driver: db.driver}
	if err := interrupted.CreateSchema(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted CreateSchema = %v, want cancellation after successful %s DDL", err, table)
	}
	if !hook.fired {
		t.Fatalf("successful %s DDL cancellation hook did not fire", table)
	}
	present, err := db.listSchemaObjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !present[table] {
		t.Fatalf("%s was not committed before cancellation", table)
	}
	if err := db.guardSchemaLineage(context.Background()); err != nil {
		t.Fatalf("our interrupted migration fenced its own retry: %v", err)
	}
	info, err := db.SchemaInfo(context.Background())
	if err != nil || info.Version != version {
		t.Fatalf("interrupted migration stamped metadata: %+v, %v; want version %d", info, err, version)
	}

	// SQLite retries also use a newly opened handle, like a subsequent CLI
	// invocation. PostgreSQL's disposable test pool retries with a fresh context.
	retry := db
	if db.driver == driverSQLite && db.Path() != "" {
		path := db.Path()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		retry = openDBFile(t, path, false)
		t.Cleanup(func() { _ = retry.Close() })
	}
	if err := retry.CheckSchema(context.Background()); !errors.Is(err, ErrSchemaOutdated) || errors.Is(err, ErrSchemaLineageRequiresConversion) {
		t.Fatalf("interrupted upstream/fresh CheckSchema = %v, want ordinary outdated schema", err)
	}
	result, err := retry.Migrate(context.Background())
	if err != nil {
		t.Fatalf("ordinary migration retry: %v", err)
	}
	if result.FromVersion != version || result.ToVersion != currentSchemaVersion || result.AlreadyCurrent {
		t.Fatalf("retry result = %+v, want %d -> %d", result, version, currentSchemaVersion)
	}
	if err := retry.CheckSchema(context.Background()); err != nil {
		t.Fatalf("CheckSchema after retry: %v", err)
	}
}

func TestSchemaLineageOrdinaryUpstreamPreV6InterruptedMigrationRetry(t *testing.T) {
	for _, table := range []string{"evidence_exchanges", "finding_evidence", "oast_planting_receipts"} {
		t.Run(table, func(t *testing.T) {
			db := openDBFile(t, filepath.Join(t.TempDir(), "upstream.sqlite"), false)
			t.Cleanup(func() { _ = db.Close() })
			if err := db.CreateSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
			stripUpstreamPreV6LineageAdditions(t, db)
			assertLineageInterruptedMigrationRetry(t, db, table, 5)
		})
	}
}

func TestSchemaLineageFreshInterruptedInitializationRetry(t *testing.T) {
	for _, table := range []string{"evidence_exchanges", "finding_evidence", "oast_planting_receipts"} {
		t.Run(table, func(t *testing.T) {
			db := openDBFile(t, filepath.Join(t.TempDir(), "fresh.sqlite"), false)
			t.Cleanup(func() { _ = db.Close() })
			assertLineageInterruptedMigrationRetry(t, db, table, 0)
		})
	}
}

func TestPg_SchemaLineageInterruptedMigrationRetry(t *testing.T) {
	for _, version := range []int{0, 5} {
		name := map[int]string{0: "fresh", 5: "upstream-pre-v6"}[version]
		t.Run(name, func(t *testing.T) {
			for _, table := range []string{"evidence_exchanges", "finding_evidence", "oast_planting_receipts"} {
				t.Run(table, func(t *testing.T) {
					db := openPGTestDB(t)
					if version == 0 {
						dropPGSchema(t, db)
					} else {
						stripUpstreamPreV6LineageAdditions(t, db)
					}
					assertLineageInterruptedMigrationRetry(t, db, table, version)
				})
			}
		})
	}
}

// Cancel only the matching query's child context. The caller's context remains
// usable, so this models a single read/DDL failure rather than canceling every
// subsequent query and accidentally hiding a zero-on-error backfill fallback.
type lineageQueryFaultHook struct {
	query     string
	faults    int
	mutations lineageMutationHook
}

func (h *lineageQueryFaultHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	if normalizedLineageQuery(event.Query) != normalizedLineageQuery(h.query) {
		return ctx
	}
	h.faults++
	failed, cancel := context.WithCancel(ctx)
	cancel()
	return failed
}

func (h *lineageQueryFaultHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	h.mutations.AfterQuery(ctx, event)
}

func TestSchemaLineagePrerequisiteDDLFailureDoesNotCreateReceipts(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		name := map[bool]string{true: "fresh", false: "upstream-pre-v6"}[fresh]
		t.Run(name, func(t *testing.T) {
			db := newEmptyDB(t)
			if !fresh {
				if err := db.CreateSchema(context.Background()); err != nil {
					t.Fatal(err)
				}
				stripUpstreamPreV6LineageAdditions(t, db)
			}
			hook := &lineageQueryFaultHook{query: "ALTER TABLE scans ADD COLUMN coverage_modules TEXT"}
			failed := &DB{DB: db.WithQueryHook(hook), driver: db.driver}
			if err := failed.CreateSchema(context.Background()); !errors.Is(err, context.Canceled) {
				t.Fatalf("failed prerequisite DDL = %v, want query failure", err)
			}
			if hook.faults == 0 {
				t.Fatal("prerequisite DDL fault did not fire")
			}
			present, err := db.listSchemaObjects(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"evidence_exchanges", "finding_evidence", "oast_planting_receipts"} {
				if present[table] {
					t.Fatalf("failed prerequisite committed receipts table %s", table)
				}
			}
			if err := db.CreateSchema(context.Background()); err != nil {
				t.Fatalf("retry after failed prerequisite: %v", err)
			}
			if err := db.CheckSchema(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSchemaLineageValidatedVersionReadFailureClosed(t *testing.T) {
	db := newTestDB(t)
	before := lineageSnapshot(t, db)
	hook := &lineageQueryFaultHook{query: "SELECT version, min_reader_version, written_by, updated_at FROM schema_meta WHERE id = 1"}
	failed := &DB{DB: db.WithQueryHook(hook), driver: db.driver}
	if err := failed.CreateSchema(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("failed validated version query = %v, want read failure", err)
	}
	if hook.faults != 1 {
		t.Fatalf("metadata read faults = %d, want 1", hook.faults)
	}
	if len(hook.mutations.queries) != 0 {
		t.Fatalf("failed metadata read attempted schema mutation: %v", hook.mutations.queries)
	}
	if !reflect.DeepEqual(before, lineageSnapshot(t, db)) {
		t.Fatal("failed metadata read changed schema or historical values")
	}
}

func TestSchemaLineageBackfillsUseValidatedVersion(t *testing.T) {
	db := newTestDB(t)
	// Deliberately leave a current finding without finding_records links and
	// retain legacy-looking values. Current schema opens must not reconstruct
	// links, normalize the project/status, or relabel evidence on a failed reread.
	mustExec(t, db, `INSERT INTO findings
		(id, project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash, status)
		VALUES (71, '', '["record"]', 'm', 'M', 'high', 'historical-hash', 'open')`)
	mustExec(t, db, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, source, raw_request)
		VALUES ('record', '', 'https', 'example.test', 443, 'GET', '/', 'https://example.test/', 'HTTP/1.1', 'request-hash', 'spa', ?)`,
		[]byte{0, 255, 128, 65})
	data := func() map[string][][]any {
		return map[string][][]any{
			"findings":             lineageRows(t, db, "SELECT * FROM findings ORDER BY id"),
			"http_records":         lineageRows(t, db, "SELECT * FROM http_records ORDER BY uuid"),
			"finding_records":      lineageRows(t, db, "SELECT * FROM finding_records ORDER BY finding_id, record_uuid"),
			"finding_observations": lineageRows(t, db, "SELECT * FROM finding_observations ORDER BY finding_id, scan_uuid"),
			"finding_hash_aliases": lineageRows(t, db, "SELECT * FROM finding_hash_aliases ORDER BY project_uuid, alias_hash"),
		}
	}
	before := data()
	hook := &lineageQueryFaultHook{query: "SELECT version FROM schema_meta WHERE id = 1"}
	guarded := &DB{DB: db.WithQueryHook(hook), driver: db.driver}
	if err := guarded.CreateSchema(context.Background()); err != nil {
		t.Fatalf("current CreateSchema with obsolete version-query fault: %v", err)
	}
	if !reflect.DeepEqual(before, data()) {
		t.Fatal("current schema open ran historical backfills after a version-query fault")
	}
	if hook.faults != 0 {
		t.Fatalf("CreateSchema still reread the version through the zero-on-error query (%d faults)", hook.faults)
	}
}
