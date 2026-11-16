package modkit

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestEvidenceCollector_NilSafe(t *testing.T) {
	var c *EvidenceCollector // nil
	// None of these may panic on a nil collector.
	c.Add("baseline", "req", "resp")
	c.AddSupplied(evidence.RoleBaseline, "input", "req", "resp")
	c.AddExchange(evidence.NewExchange("", "", []byte("req"), []byte("resp"), evidence.ProvenanceCaptured), evidence.RoleControl, "control")
	require.Nil(t, c.Evidence())
	if got := c.Entries(); got != nil {
		t.Fatalf("nil collector Entries() = %v, want nil", got)
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("nil collector Len() = %d, want 0", got)
	}
}

func TestEvidenceCollector_AddAndEntries(t *testing.T) {
	c := NewEvidenceCollector()
	c.Add("baseline", "GET / HTTP/1.1", "HTTP/1.1 403 Forbidden")
	c.Add("attack", "GET /admin HTTP/1.1", "HTTP/1.1 200 OK")

	entries := c.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if c.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", c.Len())
	}
	if !strings.HasPrefix(entries[0], "# [baseline]\n") {
		t.Fatalf("entry 0 missing baseline marker: %q", entries[0])
	}
	if !strings.HasPrefix(entries[1], "# [attack]\n") {
		t.Fatalf("entry 1 missing attack marker: %q", entries[1])
	}
	if !strings.Contains(entries[0], output.EvidenceSeparator) {
		t.Fatalf("entry 0 missing separator: %q", entries[0])
	}
}

func TestEvidenceCollector_IgnoresEmptyPairs(t *testing.T) {
	c := NewEvidenceCollector()
	c.Add("baseline", "", "") // empty pair — must be ignored
	c.Add("attack", "req", "resp")
	if c.Len() != 1 {
		t.Fatalf("expected empty pair to be ignored, Len() = %d", c.Len())
	}
}

func TestEvidenceCollector_CapsAtMax(t *testing.T) {
	c := NewEvidenceCollector()
	for i := 0; i < MaxEvidencePairs+5; i++ {
		c.Add("confirm", "req", "resp")
	}
	if c.Len() != MaxEvidencePairs {
		t.Fatalf("expected cap at %d, got %d", MaxEvidencePairs, c.Len())
	}
	if got := len(c.Entries()); got != MaxEvidencePairs {
		t.Fatalf("Entries() length = %d, want %d", got, MaxEvidencePairs)
	}
	require.Len(t, c.Evidence(), MaxEvidencePairs)
}

func TestEvidenceCollector_EntriesIsCopy(t *testing.T) {
	c := NewEvidenceCollector()
	c.Add("baseline", "req", "resp")
	entries := c.Entries()
	entries[0] = "mutated"
	// Mutating the returned slice must not affect the collector's internal state.
	if again := c.Entries(); again[0] == "mutated" {
		t.Fatalf("Entries() returned a live reference, not a copy")
	}
}

func TestEvidenceCollectorRolesRequireExplicitIntent(t *testing.T) {
	c := NewEvidenceCollector()
	// No heuristic reading of informal labels, even convincing ones.
	c.Add("attack at https://target/confirmed", "req", "resp")
	require.Len(t, c.Evidence(), 1)
	require.Equal(t, evidence.RoleUnknown, c.Evidence()[0].Role)
	require.Equal(t, evidence.ProvenanceSupplied, c.Evidence()[0].Exchange.Provenance)
	c.AddSupplied(evidence.RoleControl, "attack (arbitrary label)", "control req", "")
	c.AddSupplied(evidence.RoleConfirmation, "baseline (arbitrary label)", "confirm req", "confirm resp")
	entries := c.Evidence()
	require.Len(t, entries, 3)
	require.Equal(t, evidence.RoleUnknown, entries[0].Role)
	require.Equal(t, evidence.RoleControl, entries[1].Role)
	require.Equal(t, evidence.RoleConfirmation, entries[2].Role)
	for _, e := range entries {
		require.False(t, e.Primary)
		require.Equal(t, evidence.ProvenanceSupplied, e.Exchange.Provenance)
		require.Empty(t, e.Exchange.URL, "a label does not identify the execution URL")
		require.NoError(t, e.Exchange.Validate())
	}
	require.Equal(t, evidence.StateMissing, entries[1].Exchange.ResponseState)
	require.Len(t, c.Entries(), 3, "legacy text compatibility remains additive")
}

func TestEvidenceCollectorReceiptOwnershipAndCap(t *testing.T) {
	c := NewEvidenceCollector()
	x := evidence.NewExchange("http://target", "http://target/probe", []byte("req"), []byte("partial resp"), evidence.ProvenanceCaptured)
	x.ResponseState = evidence.StateTruncated
	x.ContentHash = x.Hash()
	c.AddExchange(x, evidence.RoleConfirmation, "round 1")
	x.Response[0] = 'X'
	entries := c.Evidence()
	require.Equal(t, "partial resp", string(entries[0].Exchange.Response))
	require.Equal(t, x.ID, entries[0].ExchangeID)
	require.Equal(t, evidence.StateTruncated, entries[0].Exchange.ResponseState)
	require.Equal(t, evidence.ProvenanceCaptured, entries[0].Exchange.Provenance)
	entries[0].Exchange.Response[0] = 'Y'
	entries[0].Label = "mutated"
	require.Equal(t, "partial resp", string(c.Evidence()[0].Exchange.Response))
	require.Equal(t, "round 1", c.Evidence()[0].Label)
	for i := 0; i < MaxEvidencePairs+5; i++ {
		c.AddSupplied(evidence.RoleBaseline, "baseline", "req", "resp")
	}
	require.Len(t, c.Evidence(), MaxEvidencePairs)
	require.Len(t, c.Entries(), MaxEvidencePairs)
}

func TestEvidenceCollectorRejectsInvalidSelections(t *testing.T) {
	c := NewEvidenceCollector()
	x := evidence.NewExchange("", "", []byte("req"), []byte("resp"), evidence.ProvenanceLegacy)
	c.AddExchange(nil, evidence.RoleControl, "nil")
	c.AddExchange(x, evidence.Role("not-a-role"), "invalid role")
	c.AddSupplied(evidence.RoleAttack, "empty", "", "")
	c.AddSupplied(evidence.Role("not-a-role"), "invalid role", "req", "resp")
	x.Request[0] = 'X' // sealed identity must not silently be reused
	c.AddExchange(x, evidence.RoleControl, "modified")
	require.Zero(t, c.Len())
	require.Nil(t, c.Evidence())
}

func TestSetPrimaryEvidenceSelectsOwnedReceiptNotBaseline(t *testing.T) {
	c := NewEvidenceCollector()
	c.AddSupplied(evidence.RoleBaseline, "baseline", "base req", "base resp")
	x := evidence.NewExchange("http://target", "http://target/attack", []byte("sent attack"), []byte("attack resp"), evidence.ProvenanceCaptured)
	r := &output.ResultEvent{Request: "base req", Response: "base resp", Evidence: c.Evidence()}
	require.True(t, SetPrimaryEvidence(r, x, evidence.RoleAttack, "selected probe"))
	require.Equal(t, "selected", r.EvidenceStatus)
	require.False(t, r.BaselineEvidence)
	require.Equal(t, "sent attack", r.Request)
	require.Equal(t, "attack resp", r.Response)
	require.Len(t, r.Evidence, 2)
	require.True(t, r.Evidence[0].Primary)
	require.False(t, r.Evidence[1].Primary)
	require.Equal(t, evidence.RoleBaseline, r.Evidence[1].Role)
	x.Response[0] = 'X'
	require.Equal(t, "attack resp", string(r.Evidence[0].Exchange.Response))
	require.NoError(t, r.Evidence[0].Exchange.Validate())
}

func TestSetPrimaryEvidenceMissingAndLegacyFidelity(t *testing.T) {
	r := &output.ResultEvent{}
	x := evidence.NewExchange("", "", []byte("request only"), nil, evidence.ProvenanceSupplied)
	require.False(t, SetPrimaryEvidence(nil, x, evidence.RoleAttack, "nil result"))
	require.False(t, SetPrimaryEvidence(r, nil, evidence.RoleAttack, "nil receipt"))
	require.False(t, SetPrimaryEvidence(r, x, evidence.RoleBaseline, "context only"))
	require.Empty(t, r.Evidence)
	require.True(t, SetPrimaryEvidence(r, x, evidence.RoleAttack, "explicit supplied attack"))
	require.Equal(t, "missing", r.EvidenceStatus)
	require.Empty(t, r.Response)
	require.Equal(t, evidence.StateMissing, r.Evidence[0].Exchange.ResponseState)
	require.Equal(t, evidence.ProvenanceSupplied, r.Evidence[0].Exchange.Provenance)
	legacy := evidence.NewExchange("", "", []byte("legacy req"), []byte("legacy resp"), evidence.ProvenanceLegacy)
	require.True(t, SetPrimaryEvidence(r, legacy, evidence.RoleObservation, "legacy observation"))
	require.Equal(t, evidence.ProvenanceLegacy, r.Evidence[0].Exchange.Provenance)
	require.False(t, r.Evidence[1].Primary, "reselection leaves exactly one primary")
}

func TestEvidenceCollectorForResultPreservesUnconvertedPrimary(t *testing.T) {
	c := NewEvidenceCollector()
	c.AddBaseline("input", "base req", "base resp")
	c.AddControl("benign", "control req", "control resp")
	c.AddAttack("mutation", "supporting req", "supporting resp")
	c.AddConfirmation("replay", "confirm req", "confirm resp")
	entries := c.ForResult("legacy primary req", "")
	require.Len(t, entries, 5)
	require.True(t, entries[0].Primary)
	require.Equal(t, evidence.RoleUnknown, entries[0].Role)
	require.Equal(t, evidence.ProvenanceSupplied, entries[0].Exchange.Provenance)
	require.Equal(t, evidence.StateMissing, entries[0].Exchange.ResponseState)
	for i, role := range []evidence.Role{evidence.RoleBaseline, evidence.RoleControl, evidence.RoleAttack, evidence.RoleConfirmation} {
		require.Equal(t, role, entries[i+1].Role)
		require.False(t, entries[i+1].Primary)
	}
	entries[1].Exchange.Response[0] = 'X'
	require.Equal(t, "base resp", string(c.Evidence()[0].Exchange.Response))
	require.Len(t, c.ForResult("", ""), 4)
	var nilCollector *EvidenceCollector
	require.Len(t, nilCollector.ForResult("primary req", "primary resp"), 1)
}
