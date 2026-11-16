package cli

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestFindingSelectedEvidenceStreamingExportSingleConnection(t *testing.T) {
	db := newInventoryTestDB(t)
	db.DB.SetMaxOpenConns(1)
	repo := database.NewRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for i := range 3 {
		x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte(fmt.Sprintf("request-%d\x00\xff", i)), []byte(fmt.Sprintf("response-%d\xff\x00", i)), evidence.ProvenanceCaptured)
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprint("stream-evidence-", i), ModuleID: "test", ModuleName: "Test", EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "proof")}, Request: "legacy request", Response: "legacy response", FoundAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	q := db.NewSelect().Model((*database.Finding)(nil)).OrderExpr("found_at DESC, id DESC")
	seen := map[int64]bool{}
	if err := iterateEvidenceFindings(ctx, db, q, false, 0, func(f *database.Finding) error {
		if seen[f.ID] {
			t.Fatal("keyset duplicated finding")
		}
		seen[f.ID] = true
		if len(f.Evidence) != 1 || f.Evidence[0].Exchange == nil || !bytes.HasSuffix(f.Evidence[0].Exchange.Response, []byte{'\xff', 0}) || f.Request != "legacy request" {
			t.Fatal("streaming export lost raw selected evidence or legacy strings")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("equal timestamps lost findings: %v", seen)
	}
}
