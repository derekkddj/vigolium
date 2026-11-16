package database

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func callbackReceiptFinding(hash, occurrence string) *Finding {
	x := evidence.NewExchange("https://example.com:443", "https://example.com/a",
		[]byte("request\x00\xff"), []byte("response-"+occurrence+"\x00\xfe"), evidence.ProvenanceCaptured)
	e := evidence.Select(x, evidence.RoleAttack, true, occurrence)
	e.OccurrenceID = occurrence
	return &Finding{FindingHash: hash, ModuleID: "occurrence-callback", ModuleName: "Occurrence callback",
		Severity: "high", URL: x.URL, EvidenceStatus: "selected", Evidence: []evidence.Entry{e}}
}

func TestFindingOccurrenceSavedDirectOwnsSnapshot(t *testing.T) {
	r, ctx := NewRepository(newTestDB(t)), context.Background()
	f := callbackReceiptFinding("owned", "first")
	at := time.Now().UTC()
	f.HTTPRecordUUIDs, f.Tags, f.MatchedAt = []string{"record"}, []string{"tag"}, []string{"match"}
	f.ExtractedResults, f.AdditionalEvidence = []string{"result"}, []string{"support"}
	f.InsertionPoint = &FindingInsertionPoint{Type: "URL_PARAM", Name: "id"}
	f.Verification = &FindingVerification{Verdict: VerdictConfirmed, Reason: "original"}
	verifiedAt, statusAt := at, at
	f.VerifiedAt, f.StatusUpdatedAt = &verifiedAt, &statusAt
	var snapshot *Finding
	var newHits int
	r.OnFindingSaved = func(saved *Finding) {
		newHits++
		// The old hook still receives its original model, but cannot corrupt
		// the separately owned occurrence notification.
		saved.Evidence[0].Label = "legacy-hook mutation"
	}
	r.OnFindingOccurrenceSaved = func(saved *Finding) {
		snapshot = saved
		// Re-entering the database verifies the hook runs after COMMIT rather
		// than inside the transaction (the test DB uses one connection).
		readCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		got, err := r.GetEvidenceExchange(readCtx, saved.Evidence[0].ExchangeID, saved.ProjectUUID)
		if err != nil || !bytes.Equal(got.Response, saved.Evidence[0].Exchange.Response) {
			t.Errorf("callback did not observe committed receipt: %v", err)
		}
	}
	inserted, err := r.SaveFindingReported(ctx, f)
	if err != nil || !inserted || newHits != 1 || snapshot == nil {
		t.Fatalf("direct notification: inserted=%v new=%d snapshot=%v err=%v", inserted, newHits, snapshot, err)
	}
	f.HTTPRecordUUIDs[0], f.Tags[0], f.MatchedAt[0] = "changed", "changed", "changed"
	f.ExtractedResults[0], f.AdditionalEvidence[0] = "changed", "changed"
	f.Evidence[0].Exchange.Request[0] = 'X'
	f.InsertionPoint.Name, f.Verification.Reason = "changed", "changed"
	*f.VerifiedAt = at.Add(time.Hour)
	if snapshot.ID != f.ID || snapshot.ProjectUUID != DefaultProjectUUID || snapshot.Evidence[0].Label != "first" ||
		snapshot.HTTPRecordUUIDs[0] != "record" || snapshot.Tags[0] != "tag" || snapshot.MatchedAt[0] != "match" ||
		snapshot.ExtractedResults[0] != "result" || snapshot.AdditionalEvidence[0] != "support" ||
		string(snapshot.Evidence[0].Exchange.Request) != "request\x00\xff" || snapshot.InsertionPoint.Name != "id" ||
		snapshot.Verification.Reason != "original" || !snapshot.VerifiedAt.Equal(at) || !snapshot.StatusUpdatedAt.Equal(at) {
		t.Fatalf("occurrence snapshot retained caller-owned fields: %+v", snapshot)
	}
	// Mutating the callback-owned object must likewise not alter the caller.
	snapshot.Evidence[0].Exchange.Response[0] = 'X'
	if f.Evidence[0].Exchange.Response[0] == 'X' {
		t.Fatal("callback receipt aliases the saved model")
	}
}

func TestFindingOccurrenceSavedBatchIncludesDedup(t *testing.T) {
	r, ctx := NewRepository(newTestDB(t)), context.Background()
	var callbacks []*Finding
	var newHits int
	r.OnFindingSaved = func(*Finding) { newHits++ }
	r.OnFindingOccurrenceSaved = func(f *Finding) { callbacks = append(callbacks, f) }
	first := callbackReceiptFinding("same-hash", "original")
	if err := r.SaveFindingDirect(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, third := callbackReceiptFinding("same-hash", "later-1"), callbackReceiptFinding("same-hash", "later-2")
	fresh := callbackReceiptFinding("new-hash", "new")
	invalid := callbackReceiptFinding("invalid", "invalid")
	invalid.Evidence[0].Exchange.Request[0] = 'X' // preparation error: no hook
	results, err := r.SaveFindingsDirectBatch(ctx, []*Finding{second, third, fresh, nil, invalid})
	if err == nil || results[0].Err != nil || results[0].Inserted || results[1].Err != nil || results[1].Inserted ||
		results[2].Err != nil || !results[2].Inserted || results[4].Err == nil {
		t.Fatalf("batch outcomes: %+v %v", results, err)
	}
	if newHits != 2 || len(callbacks) != 4 {
		t.Fatalf("new/occurrence hooks = %d/%d, want 2/4", newHits, len(callbacks))
	}
	for i, want := range []string{"original", "later-1", "later-2", "new"} {
		got := callbacks[i]
		if len(got.Evidence) != 1 || got.Evidence[0].OccurrenceID != want || got.Evidence[0].Exchange == nil {
			t.Fatalf("callback %d contains aggregate/lost receipt: %+v", i, got.Evidence)
		}
		if i < 3 && got.ID != first.ID {
			t.Fatalf("dedup callback ID %d, want canonical %d", got.ID, first.ID)
		}
	}
	manifest, err := r.GetFindingByID(ctx, first.ID)
	if err != nil || len(manifest.Evidence) != 3 {
		t.Fatalf("durable occurrence history: %+v %v", manifest, err)
	}
	second.Evidence[0].Exchange.Response[0] = 'X'
	if callbacks[1].Evidence[0].Exchange.Response[0] == 'X' {
		t.Fatal("batch callback receipt aliases caller")
	}
	// A valid receipt reusing an existing immutable identity fails only AFTER
	// dedup has appended its observation/links. None may escape rollback and no
	// occurrence notification may be emitted for that rejected receipt.
	bad := callbackReceiptFinding("same-hash", "rejected-duplicate")
	changed := callbacks[0].Evidence[0].Exchange.Clone()
	changed.Response = []byte("different immutable response")
	changed.ContentHash = changed.Hash()
	bad.Evidence[0].Exchange, bad.Evidence[0].ExchangeID = changed, changed.ID
	bad.HTTPRecordUUIDs, bad.ScanUUID = []string{"rolled-back-ref"}, "rolled-back-duplicate-scan"
	results, err = r.SaveFindingsDirectBatch(ctx, []*Finding{bad})
	if err == nil || results[0].Err == nil || len(callbacks) != 4 || newHits != 2 {
		t.Fatalf("failed duplicate notified: %+v callbacks=%d new=%d err=%v", results, len(callbacks), newHits, err)
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM finding_records WHERE record_uuid = 'rolled-back-ref'",
		"SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'rolled-back-duplicate-scan'",
		"SELECT COUNT(*) FROM finding_evidence WHERE occurrence_id = 'rejected-duplicate'",
	} {
		if n := scalarInt(t, r.DB(), query); n != 0 {
			t.Fatalf("failed duplicate leaked %d rows: %s", n, query)
		}
	}
}

func TestFindingOccurrenceSavedCommitRollbackAndRetry(t *testing.T) {
	db := newTestDB(t)
	r, ctx := NewRepository(db), context.Background()
	// Deferred FK failure happens at COMMIT, after every INSERT succeeded. This
	// distinguishes a post-commit hook from a post-statement hook without adding
	// a persistence seam to production code.
	for _, sql := range []string{
		"PRAGMA foreign_keys = ON",
		"CREATE TABLE occurrence_commit_parent (id TEXT PRIMARY KEY)",
		"CREATE TABLE occurrence_commit_guard (id TEXT REFERENCES occurrence_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)",
		`CREATE TRIGGER occurrence_fail_commit AFTER INSERT ON findings
		 WHEN NEW.finding_hash = 'commit-failure'
		 BEGIN INSERT INTO occurrence_commit_guard (id) VALUES ('missing-parent'); END`,
	} {
		if _, err := db.ExecContext(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	var callbacks []*Finding
	var newHits int
	r.OnFindingSaved = func(*Finding) { newHits++ }
	r.OnFindingOccurrenceSaved = func(f *Finding) { callbacks = append(callbacks, f) }
	first := callbackReceiptFinding("retry-good", "first")
	bad := callbackReceiptFinding("commit-failure", "rolled-back")
	bad.ScanUUID = "rolled-back-scan"
	later := callbackReceiptFinding("retry-good", "later")
	results, err := r.SaveFindingsDirectBatch(ctx, []*Finding{first, bad, later})
	if err == nil || results[0].Err != nil || !results[0].Inserted || results[1].Err == nil || results[1].Inserted || results[2].Err != nil || results[2].Inserted {
		t.Fatalf("commit rollback/retry outcomes: %+v %v", results, err)
	}
	if newHits != 1 || len(callbacks) != 2 || callbacks[0].Evidence[0].OccurrenceID != "first" || callbacks[1].Evidence[0].OccurrenceID != "later" || callbacks[0].ID != callbacks[1].ID {
		t.Fatalf("rolled-back attempt notified or successful retry missed: new=%d callbacks=%+v", newHits, callbacks)
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM findings WHERE finding_hash = 'commit-failure'",
		"SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'rolled-back-scan'",
		"SELECT COUNT(*) FROM finding_evidence WHERE occurrence_id = 'rolled-back'",
		"SELECT COUNT(*) FROM occurrence_commit_guard",
	} {
		if n := scalarInt(t, db, query); n != 0 {
			t.Fatalf("rollback leaked %d rows: %s", n, query)
		}
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM evidence_exchanges WHERE id = ?", bad.Evidence[0].ExchangeID); n != 0 {
		t.Fatal("rolled-back receipt became durable")
	}
	// A failed single-save COMMIT must not notify either hook, either.
	if err := r.SaveFindingDirect(ctx, callbackReceiptFinding("commit-failure", "single-rollback")); err == nil || newHits != 1 || len(callbacks) != 2 {
		t.Fatalf("single commit failure notified: new=%d occurrences=%d err=%v", newHits, len(callbacks), err)
	}
}

func TestFindingOccurrenceSavedEventAndWriterPaths(t *testing.T) {
	for _, path := range []string{"event", "event-batch", "writer", "writer-inline"} {
		t.Run(path, func(t *testing.T) {
			r, ctx := NewRepository(newTestDB(t)), context.Background()
			var callbacks []*Finding
			var newHits int
			r.OnFindingSaved = func(*Finding) { newHits++ }
			r.OnFindingOccurrenceSaved = func(f *Finding) { callbacks = append(callbacks, f) }
			first, second := makeFindingEvent("callback-event", "/a", severity.High), makeFindingEvent("callback-event", "/a", severity.High)
			first.Evidence = callbackReceiptFinding("", "first").Evidence
			second.Evidence = callbackReceiptFinding("", "later").Evidence
			first.EvidenceStatus, second.EvidenceStatus = "selected", "selected"
			switch path {
			case "event":
				for _, ev := range []FindingWrite{{Event: first}, {Event: second}} {
					if err := r.SaveFinding(ctx, ev.Event, nil, "scan", ""); err != nil {
						t.Fatal(err)
					}
				}
			case "event-batch":
				results := r.SaveFindingsBatchResults(ctx, []FindingWrite{{Event: first}, {Event: second}})
				if results[0].Err != nil || !results[0].Inserted || results[1].Err != nil || results[1].Inserted {
					t.Fatalf("event batch: %+v", results)
				}
			default:
				w := NewFindingWriter(r, FindingWriterConfig{BatchSize: 64, FlushInterval: time.Hour})
				t.Cleanup(w.Close)
				if path == "writer-inline" {
					w.Close() // closed writer intentionally persists inline
				}
				if err := w.Save(ctx, first, nil, "scan", ""); err != nil {
					t.Fatal(err)
				}
				if err := w.Save(ctx, second, nil, "scan", ""); err != nil {
					t.Fatal(err)
				}
				if outcome := w.Shutdown(); !outcome.Clean() {
					t.Fatalf("writer persistence outcome: %+v", outcome)
				}
			}
			if newHits != 1 || len(callbacks) != 2 || callbacks[0].ID != callbacks[1].ID || len(callbacks[1].Evidence) != 1 || callbacks[1].Evidence[0].OccurrenceID != "later" {
				t.Fatalf("path %s missed later occurrence: new=%d callbacks=%+v", path, newHits, callbacks)
			}
			second.Evidence[0].Exchange.Response[0] = 'X'
			if callbacks[1].Evidence[0].Exchange.Response[0] == 'X' {
				t.Fatal("event/writer callback aliases producer bytes")
			}
		})
	}
}
