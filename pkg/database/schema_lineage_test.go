package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// These seeds deliberately include invalid UTF-8/NUL binary messages, NULL
// versus empty bodies, sparse finding/association IDs and shared project-scoped
// hashes. The fence must not decode, rekey, merge or stamp any of them.
func seedLocalLineageFixture(t *testing.T, db *DB) {
	t.Helper()
	fixture, err := os.ReadFile("testdata/schema_local_v9.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Strip SQL comments before splitting; the fixture has no literal semicolons.
	var lines []string
	for _, line := range strings.Split(string(fixture), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	ddl := strings.Join(lines, "\n")
	primary := any(1)
	if db.driver == driverPostgres {
		// Independently spell the old fixture's dialect-sensitive types; do not
		// render it through current schema definitions or migrations.
		ddl = strings.NewReplacer(
			"INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY",
			"BLOB", "BYTEA",
			"is_primary INTEGER NOT NULL DEFAULT 0", "is_primary BOOLEAN NOT NULL DEFAULT FALSE",
		).Replace(ddl)
		primary = true
	}
	for _, statement := range strings.Split(ddl, ";") {
		if strings.TrimSpace(statement) != "" {
			mustExec(t, db, statement)
		}
	}
	mustExec(t, db, `INSERT INTO schema_meta VALUES (1, 9, 1, 'local-v9', '2026-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`)
	for i, project := range []string{"project-a", "project-b"} {
		id := []int{7, 9001}[i]
		mustExec(t, db, `INSERT INTO scans (uuid, project_uuid, status) VALUES (?, ?, 'completed')`, project+"-scan", project)
		mustExec(t, db, `INSERT INTO http_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'complete', 'truncated')`,
			project+"-record", project, project+"-scan", []byte{0, 255, 128, 65}, strings.Repeat("a", 64), []byte{}, strings.Repeat("b", 64), strings.Repeat("c", 64))
		mustExec(t, db, `INSERT INTO findings
			(id, project_uuid, http_record_uuids, scan_uuid, module_id, module_name, severity, finding_hash)
			VALUES (?, ?, '[]', ?, 'local-module', 'Local module', 'high', ?)`, id, project, project+"-scan", strings.Repeat("d", 64))
		mustExec(t, db, `INSERT INTO evidence_exchanges VALUES (?, 'exchange', 'https://local.test/', 'https://local.test:443', ?, NULL, 'complete', 'not_captured', 'captured', ?, '2026-01-01T00:00:00.123456789Z')`,
			project, []byte{255, 0, 254, 66}, strings.Repeat("e", 64))
		mustExec(t, db, `INSERT INTO finding_evidence VALUES (?, ?, ?, 'exchange', 'attack', ?, 'proof', 'occurrence', 'https://local.test/', ?)`,
			id+20000, id, strings.Repeat("f", 64), primary, project+"-scan")
		mustExec(t, db, `INSERT INTO oast_planting_receipts VALUES (?, 'nonce', ?, 'exchange')`, project, project+"-scan")
		mustExec(t, db, `INSERT INTO finding_observations VALUES (?, ?, ?, ?, '2026-01-01T00:00:00Z')`, project, id, strings.Repeat("d", 64), project+"-scan")
	}
}

// lineageRows preserves all columns and binary values, not just row counts.
func lineageRows(t *testing.T, db *DB, query string) [][]any {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]any
	for rows.Next() {
		values, pointers := make([]any, len(columns)), make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		for i, value := range values {
			if binary, ok := value.([]byte); ok {
				values[i] = slices.Clone(binary)
			}
		}
		out = append(out, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func lineageSnapshot(t *testing.T, db *DB) map[string]any {
	t.Helper()
	ctx := context.Background()
	objects, err := db.listSchemaObjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	columns, err := listAllColumns(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{"objects": objects, "columns": columns}
	if db.driver == driverSQLite {
		out["catalog"] = lineageRows(t, db, `SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name`)
		out["schema_cookie"] = lineageRows(t, db, `PRAGMA schema_version`)
		out["changes"] = lineageRows(t, db, `SELECT total_changes()`)
		if objects["sqlite_sequence"] {
			out["sequences"] = lineageRows(t, db, `SELECT name, seq FROM sqlite_sequence ORDER BY name`)
		}
	} else {
		out["indexes"] = lineageRows(t, db, `SELECT tablename, indexname, indexdef FROM pg_catalog.pg_indexes WHERE schemaname = 'public' ORDER BY tablename, indexname`)
	}
	for table, order := range map[string]string{
		"schema_meta": "id", "scans": "uuid", "http_records": "uuid", "findings": "id",
		"evidence_exchanges": "project_uuid, id", "finding_evidence": "id",
		"oast_planting_receipts": "project_uuid, nonce", "finding_observations": "finding_id, scan_uuid",
	} {
		if objects[table] {
			out[table] = lineageRows(t, db, "SELECT * FROM "+table+" ORDER BY "+order)
		}
	}
	return out
}

type lineageMutationHook struct{ queries []string }

func (h *lineageMutationHook) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (h *lineageMutationHook) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	query := strings.ToUpper(strings.TrimSpace(event.Query))
	if !strings.HasPrefix(query, "SELECT ") && !strings.HasPrefix(query, "PRAGMA ") {
		h.queries = append(h.queries, event.Query)
	}
}

func lineageGuardCalls(db *DB) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"CreateSchema": db.CreateSchema, "EnsureSchemaReady": db.EnsureSchemaReady,
		"EnsureSchemaCurrent": db.EnsureSchemaCurrent, "CheckSchema": db.CheckSchema,
		"Migrate": func(ctx context.Context) error { _, err := db.Migrate(ctx); return err },
	}
}

func assertLineageRefusedWithoutMutation(t *testing.T, db *DB) {
	t.Helper()
	before := lineageSnapshot(t, db)
	hook := &lineageMutationHook{}
	guarded := &DB{DB: db.WithQueryHook(hook), driver: db.driver, reader: db.reader, readOnly: db.readOnly}
	for name, call := range lineageGuardCalls(guarded) {
		err := call(context.Background())
		var refusal *SchemaLineageRequiresConversionError
		if !errors.As(err, &refusal) || !errors.Is(err, ErrSchemaLineageRequiresConversion) {
			t.Fatalf("%s = %v, want lineage conversion refusal", name, err)
		}
		if errors.Is(err, ErrSchemaOutdated) || refusal.Code() != apicontract.CodeSchemaLineageRequiresConversion {
			t.Fatalf("%s returned an auto-migratable/incorrectly coded refusal: %v", name, err)
		}
		if after := lineageSnapshot(t, db); !reflect.DeepEqual(before, after) {
			t.Fatalf("%s changed catalog, stamp or historical data", name)
		}
	}
	if len(hook.queries) != 0 {
		t.Fatalf("refused calls attempted non-catalog work: %v", hook.queries)
	}
}

func TestSchemaLineageLocalV9Fixture(t *testing.T) {
	for _, version := range []int{0, 5, 6, 7, 8, 9, 10, 99} {
		t.Run("stamp-v"+strconv.Itoa(version), func(t *testing.T) {
			db := openDBFile(t, filepath.Join(t.TempDir(), "local.sqlite"), false)
			t.Cleanup(func() { _ = db.Close() })
			seedLocalLineageFixture(t, db)
			mustExec(t, db, `UPDATE schema_meta SET version = ?, written_by = 'v0.5.7'`, version)
			assertLineageRefusedWithoutMutation(t, db)
		})
	}
}

func TestSchemaLineageLocalMixedAndPartialFixtures(t *testing.T) {
	for _, variant := range []string{"unstamped", "v6-receipts", "v7-legacy-json", "v8-bindings", "mixed", "exchange-only", "association-only", "binding-only"} {
		t.Run(variant, func(t *testing.T) {
			db := openDBFile(t, filepath.Join(t.TempDir(), "local.sqlite"), false)
			t.Cleanup(func() { _ = db.Close() })
			seedLocalLineageFixture(t, db)
			switch variant {
			case "unstamped":
				mustExec(t, db, "DROP TABLE schema_meta")
			case "v6-receipts", "v7-legacy-json", "v8-bindings":
				version := map[string]int{"v6-receipts": 6, "v7-legacy-json": 7, "v8-bindings": 8}[variant]
				mustExec(t, db, "UPDATE schema_meta SET version = ?", version)
				mustExec(t, db, "ALTER TABLE http_records DROP COLUMN capture_request_state")
				mustExec(t, db, "ALTER TABLE http_records DROP COLUMN capture_response_state")
				if variant != "v8-bindings" {
					mustExec(t, db, "DROP TABLE oast_planting_receipts")
				}
				if variant == "v7-legacy-json" {
					mustExec(t, db, `CREATE TABLE oast_planting_receipts (
						project_uuid TEXT NOT NULL, nonce TEXT NOT NULL, scan_uuid TEXT NOT NULL,
						receipt TEXT NOT NULL, PRIMARY KEY (project_uuid, nonce))`)
					mustExec(t, db, `INSERT INTO oast_planting_receipts VALUES ('project-a', 'legacy-nonce', 'project-a-scan', '{"historical":"do-not-convert"}')`)
				}
			case "mixed":
				// Partial prior contamination, even if it was already stamped v10.
				mustExec(t, db, "CREATE TABLE finding_hash_aliases (finding_id INTEGER, project_uuid TEXT, alias_hash TEXT)")
				mustExec(t, db, "ALTER TABLE findings ADD COLUMN last_seen_at TEXT")
				mustExec(t, db, "ALTER TABLE scans ADD COLUMN module_stats TEXT")
				mustExec(t, db, "UPDATE schema_meta SET version = 10")
			default:
				keep := map[string]string{"exchange-only": "evidence_exchanges", "association-only": "finding_evidence", "binding-only": "oast_planting_receipts"}[variant]
				for _, table := range []string{"evidence_exchanges", "finding_evidence", "oast_planting_receipts"} {
					if table != keep {
						mustExec(t, db, "DROP TABLE "+table)
					}
				}
			}
			assertLineageRefusedWithoutMutation(t, db)
		})
	}
}

func TestSchemaLineageReadPoolsRefuseLocalV9(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.sqlite")
	writer := openDBFile(t, path, false)
	t.Cleanup(func() { _ = writer.Close() })
	seedLocalLineageFixture(t, writer)
	before := lineageSnapshot(t, writer)
	for _, reader := range []*DB{openReaderFile(t, path), openDBFile(t, path, true)} {
		for name, call := range lineageGuardCalls(reader) {
			if name == "Migrate" { // A read-only migration is rejected for intent first.
				continue
			}
			if err := call(context.Background()); !errors.Is(err, ErrSchemaLineageRequiresConversion) || errors.Is(err, ErrSchemaOutdated) {
				t.Fatalf("read pool %s = %v", name, err)
			}
		}
		_ = reader.Close()
	}
	if !reflect.DeepEqual(before, lineageSnapshot(t, writer)) {
		t.Fatal("read refusals changed schema or historical data")
	}
}

func TestSchemaLineageOrdinaryUpstreamPreV6Compatible(t *testing.T) {
	// Model an ordinary upstream pre-v6 store, NOT the local fixture: it has no
	// receipts lineage. New upstream identity columns are legitimately migratable.
	db := newTestDB(t)
	for _, statement := range []string{
		"DROP TABLE evidence_exchanges", "DROP TABLE finding_evidence", "DROP TABLE oast_planting_receipts",
		"DROP TABLE finding_hash_aliases", "ALTER TABLE findings DROP COLUMN last_seen_at",
		"ALTER TABLE scans DROP COLUMN module_stats", "ALTER TABLE scans DROP COLUMN coverage_modules",
		"UPDATE schema_meta SET version = 5, min_reader_version = 1",
	} {
		mustExec(t, db, statement)
	}
	if err := db.CheckSchema(context.Background()); !errors.Is(err, ErrSchemaOutdated) {
		t.Fatalf("ordinary upstream v5 CheckSchema = %v", err)
	}
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("ordinary upstream v5 Migrate = %v", err)
	}
	if err := db.CheckSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaLineageFreshAndCurrentCompatible(t *testing.T) {
	db := openDBFile(t, filepath.Join(t.TempDir(), "fresh.sqlite"), false)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CheckSchema(context.Background()); !errors.Is(err, ErrSchemaNotInitialized) {
		t.Fatalf("fresh CheckSchema = %v", err)
	}
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, call := range lineageGuardCalls(db) {
		if err := call(context.Background()); err != nil {
			t.Fatalf("current %s = %v", name, err)
		}
	}
}

func TestSchemaLineageCombinedShapeCannotAttestProvenance(t *testing.T) {
	db := openDBFile(t, filepath.Join(t.TempDir(), "contaminated.sqlite"), false)
	t.Cleanup(func() { _ = db.Close() })
	seedLocalLineageFixture(t, db)
	for _, statement := range []string{
		"CREATE TABLE finding_hash_aliases (finding_id INTEGER, project_uuid TEXT, alias_hash TEXT)",
		"ALTER TABLE findings ADD COLUMN last_seen_at TEXT", "ALTER TABLE scans ADD COLUMN module_stats TEXT",
		"ALTER TABLE scans ADD COLUMN coverage_modules TEXT", "UPDATE schema_meta SET version = 10",
	} {
		mustExec(t, db, statement)
	}
	// Explicit limit: the fence cannot tell who added these markers or whether
	// local hashes were safely converted. Do not assert that migration is safe.
	if err := db.guardSchemaLineage(context.Background()); err != nil {
		t.Fatalf("combined marker set must not require adoption for all upstream stores: %v", err)
	}
}

func TestSchemaLineageCatalogAndMetadataFailuresClosed(t *testing.T) {
	db := openDBFile(t, filepath.Join(t.TempDir(), "metadata.sqlite"), false)
	t.Cleanup(func() { _ = db.Close() })
	// Full metadata columns but an unreadable version must not use the v1
	// fallback or be treated as a fresh schema. No receipts signature is needed.
	mustExec(t, db, "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, version TEXT, min_reader_version INTEGER, written_by TEXT, updated_at TEXT)")
	mustExec(t, db, "INSERT INTO schema_meta VALUES (1, 'unreadable', 1, 'test', 'unchanged')")
	before := lineageSnapshot(t, db)
	for name, call := range lineageGuardCalls(db) {
		err := call(context.Background())
		if err == nil || errors.Is(err, ErrSchemaOutdated) || errors.Is(err, ErrSchemaNotInitialized) {
			t.Fatalf("malformed metadata %s = %v", name, err)
		}
	}
	if !reflect.DeepEqual(before, lineageSnapshot(t, db)) {
		t.Fatal("malformed metadata authorized schema mutation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, call := range lineageGuardCalls(db) {
		if err := call(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled catalog %s = %v", name, err)
		}
	}
	if _, err := db.SchemaInfo(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled SchemaInfo = %v", err)
	}
}

func TestPg_SchemaLineageLocalV9Fixture(t *testing.T) {
	// The existing integration helper supplies the disposable PostgreSQL store;
	// remove its initialized tables and build ONLY the fixed historical fixture.
	// This skips without VIGOLIUM_PG_DSN; catalog equivalence is not claimed from
	// SQLite coverage alone.
	db := openPGTestDB(t)
	dropPGSchema(t, db)
	seedLocalLineageFixture(t, db)
	assertLineageRefusedWithoutMutation(t, db)
	mustExec(t, db, "CREATE TABLE finding_hash_aliases (finding_id INTEGER, project_uuid TEXT, alias_hash TEXT)")
	mustExec(t, db, "ALTER TABLE findings ADD COLUMN last_seen_at TEXT")
	mustExec(t, db, "ALTER TABLE scans ADD COLUMN module_stats TEXT")
	mustExec(t, db, "UPDATE schema_meta SET version = 10, written_by = 'v0.5.7'")
	assertLineageRefusedWithoutMutation(t, db)
}
