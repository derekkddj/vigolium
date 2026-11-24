package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func sqliteDBConfig(path string) *config.DatabaseConfig {
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	return cfg
}

func requireServerDatabaseInitFailure(t *testing.T, cfg *config.DatabaseConfig) error {
	t.Helper()
	db, repo, err := initServerDatabase(cfg, true)
	if db != nil {
		_ = db.Close()
	}
	if err == nil || db != nil || repo != nil {
		t.Fatalf("initialization failure must return nil dependencies and an error; db!=nil=%v repo!=nil=%v err=%v", db != nil, repo != nil, err)
	}
	return err
}

func openServerSeedDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open(sqliteshim.ShimName, path)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// A fresh file must contain the mandatory defaults, not just empty tables.
func TestInitServerDatabase_FreshPathSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.sqlite")

	db, repo, err := initServerDatabase(sqliteDBConfig(path), true)
	if err != nil || db == nil || repo == nil {
		t.Fatalf("fresh database should initialize; db!=nil=%v repo!=nil=%v err=%v", db != nil, repo != nil, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, row := range []struct {
		table string
		uuid  string
	}{
		{"users", database.DefaultUserUUID},
		{"projects", database.DefaultProjectUUID},
	} {
		var count int
		if err := db.NewRaw("SELECT count(*) FROM "+row.table+" WHERE uuid = ?", row.uuid).Scan(context.Background(), &count); err != nil || count != 1 {
			t.Fatalf("default %s row: count=%d err=%v", row.table, count, err)
		}
	}
}

// An incompatible pre-existing table must be a startup error, never a live DB
// with a nil repo or a silently DB-less server.
func TestInitServerDatabase_SchemaFailureReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	seed := openServerSeedDB(t, path)
	if _, err := seed.Exec(`CREATE TABLE findings (project_uuid TEXT, finding_hash TEXT)`); err != nil {
		t.Fatalf("seed legacy findings table: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	err := requireServerDatabaseInitFailure(t, sqliteDBConfig(path))
	if !strings.Contains(err.Error(), "initialize database schema") {
		t.Fatalf("want schema initialization error, got %v", err)
	}
}

func TestInitServerDatabase_CorruptFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.sqlite")
	contents := []byte("this is not a sqlite database\n")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	err := requireServerDatabaseInitFailure(t, sqliteDBConfig(path))
	if !strings.Contains(err.Error(), "open database") {
		t.Fatalf("want database open error, got %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, contents) {
		t.Fatalf("corrupt designated file must not be replaced; contents=%q err=%v", got, readErr)
	}
}

func TestInitServerDatabase_DirectoryPathReturnsError(t *testing.T) {
	err := requireServerDatabaseInitFailure(t, sqliteDBConfig(t.TempDir()))
	if !strings.Contains(err.Error(), "open database") {
		t.Fatalf("want database path/open error, got %v", err)
	}
}

// The schema fast path and a ping can succeed while another writer holds the
// write lock. Even when all defaults already exist, startup must not claim that
// persistence works in this state.
func TestInitServerDatabase_LockedCurrentStoreReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.sqlite")
	cfg := sqliteDBConfig(path)
	cfg.SQLite.BusyTimeout = 1
	db, _, err := initServerDatabase(cfg, true)
	if err != nil {
		t.Fatalf("initialize fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	locker := openServerSeedDB(t, path)
	if _, err := locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("lock fixture: %v", err)
	}
	defer func() { _, _ = locker.Exec("ROLLBACK") }()
	err = requireServerDatabaseInitFailure(t, cfg)
	if message := strings.ToLower(err.Error()); !strings.Contains(message, "locked") && !strings.Contains(message, "busy") {
		t.Fatalf("want underlying lock error, got %v", err)
	}
	if _, err := locker.Exec("ROLLBACK"); err != nil {
		t.Fatalf("unlock fixture: %v", err)
	}

	// Failure must release its handle; a retry after unlocking should work.
	db, repo, err := initServerDatabase(cfg, true)
	if err != nil || db == nil || repo == nil {
		t.Fatalf("retry after unlocking: db!=nil=%v repo!=nil=%v err=%v", db != nil, repo != nil, err)
	}
	t.Cleanup(func() { _ = db.Close() })
}

func TestInitServerDatabase_ReadOnlyCurrentStoreReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readonly.sqlite")
	cfg := sqliteDBConfig(path)
	db, _, err := initServerDatabase(cfg, true)
	if err != nil {
		t.Fatalf("initialize fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	cfg.SQLite.ReadOnly = true
	err = requireServerDatabaseInitFailure(t, cfg)
	if !strings.Contains(err.Error(), "verify database") {
		t.Fatalf("current read-only store must fail persistence validation, got %v", err)
	}
}

// SeedDefaults currently logs and swallows insertion errors. Verify the required
// rows so those failures cannot masquerade as successful server initialization.
func TestInitServerDatabase_SeedFailureReturnsError(t *testing.T) {
	for _, row := range []struct {
		table string
		uuid  string
	}{
		{"users", database.DefaultUserUUID},
		{"projects", database.DefaultProjectUUID},
	} {
		t.Run(row.table, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seed-failure.sqlite")
			cfg := sqliteDBConfig(path)
			db, _, err := initServerDatabase(cfg, true)
			if err != nil {
				t.Fatalf("initialize fixture: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatalf("close fixture: %v", err)
			}
			seed := openServerSeedDB(t, path)
			if _, err := seed.Exec("DELETE FROM "+row.table+" WHERE uuid = ?", row.uuid); err != nil {
				t.Fatalf("remove default row: %v", err)
			}
			if _, err := seed.Exec("CREATE TRIGGER reject_default BEFORE INSERT ON " + row.table + " BEGIN SELECT RAISE(ABORT, 'default seeding blocked'); END"); err != nil {
				t.Fatalf("block seeding: %v", err)
			}
			if err := seed.Close(); err != nil {
				t.Fatalf("close seed db: %v", err)
			}

			err = requireServerDatabaseInitFailure(t, cfg)
			if !errors.Is(err, sql.ErrNoRows) || !strings.Contains(err.Error(), "verify database default") {
				t.Fatalf("missing mandatory default must propagate an error, got %v", err)
			}
		})
	}
}

func TestInitServerDatabase_NewerSchemaReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.sqlite")
	cfg := sqliteDBConfig(path)
	db, _, err := initServerDatabase(cfg, true)
	if err != nil {
		t.Fatalf("initialize fixture: %v", err)
	}
	info, err := db.SchemaInfo(context.Background())
	if err != nil {
		_ = db.Close()
		t.Fatalf("read fixture schema: %v", err)
	}
	if _, err := db.NewRaw("UPDATE schema_meta SET version = ? WHERE id = 1", info.Version+1).Exec(context.Background()); err != nil {
		_ = db.Close()
		t.Fatalf("stamp newer schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	err = requireServerDatabaseInitFailure(t, cfg)
	var tooNew *database.SchemaTooNewError
	if !errors.As(err, &tooNew) {
		t.Fatalf("newer schema error must survive wrapping, got %v", err)
	}
}

// Use the existing CLI child helper with a temporary HOME and explicit config.
// Holding the API port makes a regression fail at Bind rather than run forever;
// the asserted database error proves startup stops before that listener step.
func TestServerDatabaseFailureBeforeBindAndReady(t *testing.T) {
	for _, mode := range []struct {
		name  string
		flags []string
	}{
		{"default", nil},
		{"view-only", []string{"--view-only"}},
		{"demo-only", []string{"--demo-only"}},
		{"bridge", []string{"--burp-bridge-url", "http://127.0.0.1:9876"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			home := t.TempDir()
			stateDir := filepath.Join(home, ".vigolium")
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, "corrupt.sqlite")
			if err := os.WriteFile(path, []byte("not a sqlite database\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(stateDir, "vigolium-configs.yaml")
			if err := os.WriteFile(configPath, []byte(fmt.Sprintf("database:\n  enabled: true\n  driver: sqlite\n  sqlite:\n    path: %q\n    busy_timeout: 1\n", path)), 0o600); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			port := listener.Addr().(*net.TCPAddr).Port
			args := []string{"--offline", "--config", configPath, "--db", path, "server", "-A", "--no-agent", "--host", "127.0.0.1", "--service-port", strconv.Itoa(port), "-j"}
			args = append(args, mode.flags...)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestFindingLifecycleChild$", "-test.v=false")
			cmd.Dir = home
			cmd.Env = []string{c6ChildEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "VIGOLIUM_") {
					cmd.Env = append(cmd.Env, kv)
				}
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("server did not reject invalid persistence promptly: %v\n%s\n%s", ctx.Err(), stdout.String(), stderr.String())
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
				t.Fatalf("server must exit nonzero: %v\n%s\n%s", err, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, "initialize server database") || strings.Contains(combined, "bind API server") {
				t.Fatalf("want database failure before Bind:\n%s", combined)
			}
			if strings.Contains(stdout.String(), "server.ready") {
				t.Fatalf("failed initialization announced ready: %s", stdout.String())
			}
			if _, err := os.Stat(serverPidPathIn(home, port)); !os.IsNotExist(err) {
				t.Fatalf("failed initialization wrote a pidfile: %v", err)
			}
		})
	}
}
