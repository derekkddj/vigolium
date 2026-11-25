package verify

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestSelectedEvidenceReplayBaselineAndUnknownNoProof(t *testing.T) {
	x := evidence.NewExchange("http://app.test:80", "http://app.test/item?id=1", []byte("GET /item?id=1 HTTP/1.1\r\nHost: app.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nobservation"), evidence.ProvenanceCaptured)
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "attack"), evidence.Select(x, evidence.RoleBaseline, false, "baseline")}}
	p := &Plan{finding: f}
	if !p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, false) || p.Baseline == nil || p.Baseline.Role != evidence.RoleBaseline || p.Baseline.ExchangeID != x.ID {
		t.Fatalf("explicit baseline not used: %+v", p)
	}
	f.Evidence = []evidence.Entry{evidence.Select(x, evidence.RoleUnknown, true, "unknown")}
	p = &Plan{finding: f}
	if p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, true) || p.Verdict != database.VerdictInconclusive {
		t.Fatal("unknown selected response used as passive proof")
	}
	f.Evidence = []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "observation")}
	p = &Plan{finding: f}
	if !p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, true) || p.Baseline.Role != evidence.RoleObservation {
		t.Fatal("primary observation unavailable")
	}
	f.Evidence[0].Exchange = nil
	p = &Plan{finding: f}
	if p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, true) || p.item != nil {
		t.Fatal("missing selected receipt replaced")
	}
	f.Evidence[0].Exchange = x
	f.ProjectUUID = ""
	p = &Plan{finding: f}
	if p.useSelectedExchange(context.Background(), nil, database.DefaultProjectUUID, true) {
		t.Fatal("missing captured project recovered into default")
	}
}

func TestSelectedEvidenceReplayPreservesDestinationAndBinaryLengthMismatch(t *testing.T) {
	for _, passive := range []bool{false, true} {
		for _, target := range []string{"/proof", "https://absolute-target.example/proof"} {
			raw := []byte("POST " + target + " HTTP/1.1\r\nHost: virtual-host.example\r\nContent-Length: 900\r\n\r\n\x00\xffBINARY\r\n")
			response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 700\r\n\r\n\xff\x00response")
			x := evidence.NewExchange("http://destination.example:8080", "https://finding-url.example/proof", raw, response, evidence.ProvenanceCaptured)
			role := evidence.RoleBaseline
			if passive {
				role = evidence.RoleObservation
			}
			f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, Evidence: []evidence.Entry{evidence.Select(x, role, passive, "receipt")}}
			p := &Plan{finding: f}
			if !passive && strings.HasPrefix(target, "https://") {
				if p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, passive) || p.item != nil || p.Verdict != database.VerdictInconclusive {
					t.Fatalf("normalized absolute-form replay was accepted as exact reproduction: %+v", p)
				}
				continue
			}
			if !p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, passive) {
				t.Fatalf("receipt restore failed: %+v", p)
			}
			svc := p.item.Service()
			if svc.Host() != "destination.example" || svc.Port() != 8080 || svc.Protocol() != "http" {
				t.Fatalf("URL/Host replaced captured destination: %v", svc)
			}
			if !bytes.Equal(p.item.Request().Raw(), raw) || !bytes.Equal(p.item.Response().Raw(), response) {
				t.Fatal("receipt bytes or declared Content-Length reconciled")
			}
			// The plan owns its bytes rather than borrowing the receipt's buffers.
			f.Evidence[0].Exchange.Request[0], f.Evidence[0].Exchange.Response[0] = 'X', 'X'
			if !bytes.Equal(p.item.Request().Raw(), raw) || !bytes.Equal(p.item.Response().Raw(), response) {
				t.Fatal("plan aliases receipt bytes")
			}
		}
	}
}

func TestSelectedEvidenceReplayPassiveRequiresCompleteResponse(t *testing.T) {
	for _, state := range []evidence.State{evidence.StateUnknown, evidence.StateTruncated, evidence.StateMissing} {
		x := evidence.NewExchange("http://destination.example:8080", "https://finding-url.example/proof", []byte("GET / HTTP/1.1\r\nHost: app.test\r\n\r\n"), []byte("partial response"), evidence.ProvenanceCaptured)
		x.ResponseState = state
		if state == evidence.StateMissing {
			x.Response = nil
		}
		x.ContentHash = x.Hash()
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleObservation, true, "receipt")}}
		p := &Plan{finding: f}
		if p.useSelectedExchange(context.Background(), nil, f.ProjectUUID, true) || p.item != nil {
			t.Fatalf("passive %s response accepted", state)
		}
	}
}

func TestSelectedEvidenceReplayMissingBaselineNeverSubstitutesExactOrigin(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	base := withResponse(modtest.Request(t, "http://app.test/item?id=1"), "legacy baseline")
	origin := saveRecord(t, repo, base, "scanner")
	x := evidence.NewExchange("http://app.test:80", "http://app.test/item?id=1", base.Request().Raw(), base.Response().Raw(), evidence.ProvenanceCaptured)
	f := saveFinding(t, repo, &database.Finding{ModuleID: sqliModule, ModuleName: "SQLi", OriginRecordUUID: origin, EvidenceStatus: "unclassified", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "later attack")}})
	p := Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
	if p.Verdict != "" || p.Baseline == nil || p.Baseline.Source != BaselineOriginRecord || p.Baseline.Role != evidence.RoleUnknown || p.EvidenceStatus != "unclassified" {
		t.Fatalf("exact origin was not kept as independent unknown-role replay context: %+v", p)
	}
	// Baseline receipt identity is positive selection intent; its absence must
	// not be concealed by otherwise usable legacy origin or URL-matching traffic.
	f = saveFinding(t, repo, &database.Finding{FindingHash: "missing-selected-baseline", ModuleID: sqliModule, ModuleName: "SQLi", OriginRecordUUID: origin, Evidence: []evidence.Entry{{ExchangeID: "missing-baseline", Role: evidence.RoleBaseline}}})
	p = Reconstruct(ctx, repo, database.DefaultProjectUUID, f, nil)
	if p.Verdict != database.VerdictInconclusive || p.item != nil || p.Baseline != nil {
		t.Fatalf("missing selected baseline was replaced with origin context: %+v", p)
	}
}

func TestSelectedEvidenceEmptyNonlegacyManifestFailsClosedBeforeLegacyReplay(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	base := withResponse(modtest.Request(t, "http://app.test/item?id=1"), "legacy response")
	origin := saveRecord(t, repo, base, "scanner")
	for _, status := range []string{"selected", "missing", "future-nonlegacy-status"} {
		for _, passive := range []bool{false, true} {
			f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, EvidenceStatus: status, OriginRecordUUID: origin, HTTPRecordUUIDs: []string{origin}, Request: string(base.Request().Raw()), Response: string(base.Response().Raw())}
			p := &Plan{finding: f, EvidenceStatus: status}
			if p.findBaseline(ctx, repo, f.ProjectUUID, passive) || p.Verdict != database.VerdictInconclusive || p.item != nil || p.Baseline != nil {
				t.Fatalf("status %q with empty manifest replayed legacy context: %+v", status, p)
			}
			// Stateless inline requests must fail closed too.
			p = &Plan{finding: f}
			if p.findBaseline(ctx, nil, f.ProjectUUID, passive) || p.item != nil {
				t.Fatalf("stateless status %q replayed inline legacy data", status)
			}
		}
	}
	for _, status := range []string{"", "unclassified", "legacy_unknown"} {
		f := &database.Finding{EvidenceStatus: status, OriginRecordUUID: origin}
		p := &Plan{finding: f}
		if !p.findBaseline(ctx, repo, database.DefaultProjectUUID, false) || p.Baseline.Role != evidence.RoleUnknown {
			t.Fatalf("genuine legacy status %q lost unknown-role replay context", status)
		}
	}
}

func TestSelectedEvidenceVerifyMatchesDowngradedOccurrenceAsContext(t *testing.T) {
	p := &Plan{finding: &database.Finding{ModuleID: "test", RecordKind: database.RecordKindFinding, URL: "https://app.test/item?id=1"}}
	for _, kind := range []output.RecordKind{output.RecordKindCandidate, output.RecordKindObservation} {
		r := &output.ResultEvent{ModuleID: "test", RecordKind: kind, URL: "https://app.test/item?id=1"}
		if !p.matches(r) || r.IsFinding() {
			t.Fatalf("downgraded matching occurrence was ignored or treated as a finding: %s", kind)
		}
	}
}

func TestSelectedEvidenceSameOccurrenceAmbiguityFailsClosedButDistinctHistoryIsValid(t *testing.T) {
	x := evidence.NewExchange("http://app.test:80", "http://app.test/", []byte("GET / HTTP/1.1\r\nHost: app.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nresponse"), evidence.ProvenanceCaptured)
	one := evidence.Select(x, evidence.RoleAttack, true, "one")
	two := evidence.Select(x, evidence.RoleConfirmation, true, "two")
	for _, occurrence := range []string{"", "same-occurrence"} {
		one.OccurrenceID, two.OccurrenceID = occurrence, occurrence
		entries := []evidence.Entry{one, two}
		if usableSelectedResult(entries) {
			t.Fatal("same-occurrence declarations were resolved by first usable bytes")
		}
		p := &Plan{finding: &database.Finding{ProjectUUID: database.DefaultProjectUUID, EvidenceStatus: "missing", Request: string(x.Request), Response: string(x.Response), Evidence: entries}}
		if p.findBaseline(context.Background(), nil, database.DefaultProjectUUID, false) || p.Verdict != database.VerdictInconclusive {
			t.Fatal("ambiguous occurrence replayed inline context")
		}
	}
	one.OccurrenceID, two.OccurrenceID = "first-occurrence", "later-occurrence"
	if !usableSelectedResult([]evidence.Entry{one, two}) {
		t.Fatal("distinct historical primaries were falsely made one ambiguous occurrence")
	}
}

func TestSelectedEvidenceVerdictRequiresCapturedPrimaryNotBaselineOrUnknown(t *testing.T) {
	x := evidence.NewExchange("http://app.test:80", "http://app.test/", []byte("request"), []byte("response"), evidence.ProvenanceCaptured)
	cached := x.Clone()
	cached.Provenance = evidence.ProvenanceCached
	cached.RequestState, cached.ResponseState = evidence.StateUnknown, evidence.StateUnknown
	cached.ContentHash = cached.Hash()
	if usableSelectedResult([]evidence.Entry{evidence.Select(cached, evidence.RoleObservation, true, "cached observation")}) {
		t.Fatal("explicit cached primary observation promoted unknown fidelity to proof")
	}
	legacy := x.Clone()
	legacy.Provenance = evidence.ProvenanceLegacy
	legacy.ContentHash = legacy.Hash()
	if usableSelectedResult([]evidence.Entry{evidence.Select(legacy, evidence.RoleAttack, true, "legacy")}) {
		t.Fatal("legacy-unknown capture promoted to proof by an association label")
	}
	for _, role := range []evidence.Role{evidence.RoleBaseline, evidence.RoleUnknown, evidence.RoleControl} {
		if usableSelectedResult([]evidence.Entry{evidence.Select(x, role, true, "context")}) {
			t.Fatalf("role %s counted as proof", role)
		}
	}
	for _, role := range []evidence.Role{evidence.RoleAttack, evidence.RoleConfirmation, evidence.RoleObservation} {
		e := evidence.Select(x.Clone(), role, true, "selected")
		if !usableSelectedResult([]evidence.Entry{e}) {
			t.Fatalf("selected role %s unavailable", role)
		}
		e.Exchange.ResponseState = evidence.StateTruncated
		e.Exchange.ContentHash = e.Exchange.Hash()
		if usableSelectedResult([]evidence.Entry{e}) {
			t.Fatal("truncated capture counted as complete proof")
		}
		e.Exchange = nil
		if usableSelectedResult([]evidence.Entry{e}) {
			t.Fatal("manifest without bytes counted as proof")
		}
	}
}
