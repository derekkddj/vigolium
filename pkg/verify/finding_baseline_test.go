package verify

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestFindingLinkageVerifyJunctionOnlyScoped(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	base := withResponse(modtest.Request(t, "http://app.test/item?id=1"), "own baseline")
	own := saveRecord(t, repo, base, "scanner")
	foreign, err := repo.SaveRecord(ctx, base, "scanner", "foreign-project")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ref  string
		want bool
	}{{"own", own, true}, {"foreign", foreign, false}, {"missing", "ghost-baseline", false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := saveFinding(t, repo, &database.Finding{FindingHash: "junction-" + tc.name, ModuleID: sqliModule, ModuleName: "SQLi"})
			if _, err := repo.DB().ExecContext(ctx, "INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)", f.ID, tc.ref); err != nil {
				t.Fatal(err)
			}
			if len(f.HTTPRecordUUIDs) != 0 || f.Request != "" || f.OriginRecordUUID != "" {
				t.Fatal("fixture is not junction-only")
			}
			p := Reconstruct(ctx, repo, "", f, nil)
			if !slices.Contains(f.HTTPRecordUUIDs, tc.ref) {
				t.Fatal("junction identity not hydrated")
			}
			if tc.want {
				if p.Verdict != "" || p.Baseline == nil || p.Baseline.Source != BaselineLinkedRecord || p.Baseline.RecordUUID != own {
					t.Fatalf("own junction baseline unavailable: %+v", p)
				}
				wrong := &database.Finding{ID: f.ID, ProjectUUID: "foreign-project", ModuleID: sqliModule}
				p = Reconstruct(ctx, repo, "", wrong, nil)
				if p.Verdict != database.VerdictInconclusive || p.Baseline != nil || len(wrong.HTTPRecordUUIDs) != 0 {
					t.Fatal("junction hydrated using a wrong-project finding ID")
				}
			} else if p.Verdict != database.VerdictInconclusive || p.Baseline != nil || p.item != nil {
				t.Fatalf("unavailable junction used as baseline: %+v", p)
			}
		})
	}
}

func TestFindingLinkageVerifyHydrationFailure(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	f := saveFinding(t, repo, &database.Finding{ModuleID: sqliModule, ModuleName: "SQLi"})
	if _, err := repo.DB().ExecContext(ctx, "DROP TABLE finding_records"); err != nil {
		t.Fatal(err)
	}
	p := Reconstruct(ctx, repo, "", f, nil)
	if p.Verdict != database.VerdictInconclusive || !strings.Contains(p.Reason, "could not load finding record references") {
		t.Fatalf("reference lookup failure hidden as absent proof: %+v", p)
	}
}

func TestFindingLinkageVerifyBaselineOrderAndMerge(t *testing.T) {
	ctx := context.Background()
	cfg := config.DefaultDatabaseConfig()
	cfg.Driver = "sqlite"
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "baseline-source.sqlite")
	sourceDB, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sourceDB.Close() })
	if err := sourceDB.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	source := database.NewRepository(sourceDB)
	base := withResponse(modtest.Request(t, "http://app.test/item?id=1&q=x"), "baseline")
	baseUUID := saveRecord(t, source, base, "scanner")
	// Two changed points deliberately prevent inferred one-point matching from
	// masking a lost exact baseline link.
	attack := withResponse(modtest.Request(t, "http://app.test/item?id=1%27&q=y"), mysqlErrText)
	attackUUID := saveRecord(t, source, attack, database.RecordKindFinding)
	for old, replacement := range map[string]string{baseUUID: "z-baseline", attackUUID: "a-attack"} {
		if _, err := sourceDB.ExecContext(ctx, "UPDATE http_records SET uuid = ? WHERE uuid = ?", replacement, old); err != nil {
			t.Fatal(err)
		}
	}
	if singleDifferingPoint(base.Request().Raw(), attack.Request().Raw()) != nil {
		t.Fatal("fixture accidentally permits inferred baseline matching")
	}
	f := saveFinding(t, source, &database.Finding{FindingHash: "baseline-order", ModuleID: sqliModule, ModuleName: "SQLi", HTTPRecordUUIDs: []string{"z-baseline", "a-attack"}})
	assertBaseline := func(repo *database.Repository, f *database.Finding, source, uuid string) {
		t.Helper()
		p := Reconstruct(ctx, repo, "", f, nil)
		if p.Verdict != "" || p.Baseline == nil || p.Baseline.Source != source || p.Baseline.RecordUUID != uuid {
			t.Fatalf("wrong baseline: %+v", p)
		}
	}
	assertBaseline(source, f, BaselineLinkedRecord, "z-baseline")
	f.HTTPRecordUUIDs = []string{"a-attack", "z-baseline"}
	assertBaseline(source, f, BaselineLinkedRecord, "z-baseline")
	origin := saveRecord(t, source, withResponse(modtest.Request(t, "http://app.test/item?id=2&q=z"), "origin"), "scanner")
	f.OriginRecordUUID = origin
	assertBaseline(source, f, BaselineOriginRecord, origin)

	dest := newRepo(t)
	for i := 0; i < 2; i++ {
		if _, err := database.MergeSQLiteFileWithOptions(ctx, dest.DB(), cfg.SQLite.Path, database.MergeOptions{}); err != nil {
			t.Fatal(err)
		}
		var merged database.Finding
		if err := dest.DB().NewSelect().Model(&merged).Where("finding_hash = ?", f.FindingHash).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(merged.HTTPRecordUUIDs, []string{"z-baseline", "a-attack"}) {
			t.Fatalf("merge %d changed exact reference order: %v", i, merged.HTTPRecordUUIDs)
		}
		assertBaseline(dest, &merged, BaselineLinkedRecord, "z-baseline")
	}
}
