package verify

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestFindingLinkageVerifyProjectChecks(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	rr := withResponse(modtest.Request(t, "http://app.test/item?id=1"), "FOREIGN-SECRET-BODY")
	foreign, err := repo.SaveRecord(ctx, rr, "scanner", "foreign-project")
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []bool{false, true} {
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, ModuleID: sqliModule, ModuleName: "SQLi", HTTPRecordUUIDs: []string{foreign}}
		if origin {
			f.OriginRecordUUID = foreign
		}
		p := Reconstruct(ctx, repo, "", f, nil)
		if p.Verdict != database.VerdictInconclusive || p.Baseline != nil || p.item != nil {
			t.Fatalf("foreign baseline loaded: %+v", p)
		}
	}
	f := &database.Finding{ProjectUUID: "foreign-project", ModuleID: sqliModule, OriginRecordUUID: foreign}
	p := Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
	if p.Verdict != database.VerdictInconclusive || p.Baseline != nil {
		t.Fatal("finding outside selected project verified")
	}
}
