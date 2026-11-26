package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The reader floor is authoritative even if a damaged or incorrectly stamped
// schema version is low. Refusal must not turn into ordinary migration advice.
func TestSchemaGuardReaderFloorIndependentOfVersion(t *testing.T) {
	for _, version := range []int{0, currentSchemaVersion - 1, currentSchemaVersion, currentSchemaVersion + 1} {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			info := SchemaInfo{Version: version, MinReaderVersion: currentSchemaVersion + 1, WrittenBy: "future-writer"}
			for name, check := range map[string]func(SchemaInfo) error{"read": guardRead, "write": guardWrite} {
				err := check(info)
				var tooNew *SchemaTooNewError
				if !errors.As(err, &tooNew) || tooNew.Write != (name == "write") {
					t.Fatalf("%s guard = %v, want matching schema-too-new intent", name, err)
				}
				if tooNew.MinReaderVersion != info.MinReaderVersion || tooNew.DBVersion != version {
					t.Fatalf("%s guard lost stored metadata: %+v", name, tooNew)
				}
				if version <= currentSchemaVersion && !strings.Contains(err.Error(), "needs a reader of at least") {
					t.Fatalf("%s guard misdiagnosed reader floor as a newer version: %v", name, err)
				}
			}
		})
	}
	// A genuinely newer but additive store can still be read, never written.
	info := SchemaInfo{Version: currentSchemaVersion + 1, MinReaderVersion: currentSchemaVersion}
	if err := guardRead(info); err != nil {
		t.Fatalf("additive newer reader = %v", err)
	}
	if err := guardWrite(info); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("additive newer writer = %v", err)
	}
	if err := guardRead(SchemaInfo{}); err != nil {
		t.Fatalf("absent metadata reader = %v", err)
	}
	if err := guardWrite(SchemaInfo{}); err != nil {
		t.Fatalf("absent metadata writer = %v", err)
	}
}

func TestSchemaMutationsRefuseIncompatibleReaderFloor(t *testing.T) {
	path := currentFileDB(t)
	// Retain a handle admitted before the external metadata change to exercise
	// mutation guards separately from constructor refusal.
	writer := openDBFile(t, path, false)
	t.Cleanup(func() { _ = writer.Close() })
	stampSchemaMeta(t, path, currentSchemaVersion, currentSchemaVersion+1)
	ctx := context.Background()
	reader := openReaderFile(t, path)
	var readError *SchemaTooNewError
	if err := reader.CheckSchema(ctx); !errors.As(err, &readError) || readError.Write {
		t.Fatalf("reader floor CheckSchema = %v", err)
	}
	before := sha256File(t, path)
	for name, mutate := range map[string]func(context.Context) error{
		"create":  writer.CreateSchema,
		"ensure":  writer.EnsureSchemaCurrent,
		"migrate": func(ctx context.Context) error { _, err := writer.Migrate(ctx); return err },
	} {
		if err := mutate(ctx); !errors.Is(err, ErrSchemaTooNew) {
			t.Fatalf("%s with incompatible reader floor = %v", name, err)
		}
	}
	if sha256File(t, path) != before {
		t.Fatal("refused schema mutations changed the main artifact")
	}
	// Compare the WAL-visible values as well; a main-file hash alone does not
	// establish that a live SQLite store was untouched.
	info, err := writer.SchemaInfo(ctx)
	if err != nil || info.Version != currentSchemaVersion || info.MinReaderVersion != currentSchemaVersion+1 {
		t.Fatalf("refusal restamped metadata: %+v, %v", info, err)
	}
}
