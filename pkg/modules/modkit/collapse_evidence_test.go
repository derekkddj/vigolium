package modkit_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func collapseReceipt(path string) *evidence.Exchange {
	return evidence.NewExchange("https://example.com", "https://example.com"+path,
		[]byte("GET "+path+" HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nX-Proof: "+path+"\r\n\r\nfull body"), evidence.ProvenanceCaptured)
}

func TestCollapseRetainsRelatedReceiptsRolesMetadataAndOnePrimary(t *testing.T) {
	main := &output.ResultEvent{Host: "group", Info: output.Info{Severity: severity.High}}
	folded := &output.ResultEvent{Host: "group", Info: output.Info{Severity: severity.Low}}
	mainReceipt, foldedReceipt, control := collapseReceipt("/main"), collapseReceipt("/related"), collapseReceipt("/control")
	modkit.SetPrimaryEvidence(main, mainReceipt, evidence.RoleObservation, "original main")
	modkit.SetPrimaryEvidence(folded, foldedReceipt, evidence.RoleAttack, "related attack")
	folded.Evidence[0].OccurrenceID = "original-occurrence"
	folded.Evidence[0].FindingURL = "https://example.com/related"
	folded.Evidence[0].ScanUUID = "original-scan"
	folded.Evidence = append(folded.Evidence, evidence.Select(control, evidence.RoleControl, false, "related clean control"))
	// Manifest-only context also must survive folding; hydration is not required.
	manifest := evidence.Select(collapseReceipt("/replay"), evidence.RoleConfirmation, false, "related replay").Manifest()
	folded.Evidence = append(folded.Evidence, manifest)
	out := modkit.CollapseFindings([]*output.ResultEvent{folded, main}, modkit.CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 1)
	require.Same(t, main, out[0])
	require.Equal(t, string(mainReceipt.Request), main.Request)
	require.Equal(t, string(mainReceipt.Response), main.Response)
	require.Len(t, main.Evidence, 4)
	require.True(t, main.Evidence[0].Primary)
	require.Equal(t, mainReceipt.ID, main.Evidence[0].ExchangeID)
	for _, entry := range main.Evidence[1:] {
		require.False(t, entry.Primary)
	}
	related := main.Evidence[1]
	require.Equal(t, evidence.RoleConfirmation, related.Role)
	require.Equal(t, foldedReceipt.ID, related.ExchangeID)
	require.Equal(t, foldedReceipt.ContentHash, related.Exchange.ContentHash)
	require.Equal(t, foldedReceipt.CapturedAt, related.Exchange.CapturedAt)
	require.Equal(t, "original-occurrence", related.OccurrenceID)
	require.Equal(t, "https://example.com/related", related.FindingURL)
	require.Equal(t, "original-scan", related.ScanUUID)
	require.Equal(t, evidence.RoleControl, main.Evidence[2].Role)
	require.Equal(t, manifest, main.Evidence[3])
	related.Exchange.Response[0] = 'X'
	require.True(t, folded.Evidence[0].Primary, "folding must not mutate related finding selections")
	require.Equal(t, evidence.RoleAttack, folded.Evidence[0].Role)
	require.NoError(t, folded.Evidence[0].Exchange.Validate())
}

func TestCollapseSupportingContextDoesNotHideLegacySurvivorPrimary(t *testing.T) {
	main := &output.ResultEvent{Host: "group", Request: "legacy main request", Response: "legacy main response", Info: output.Info{Severity: severity.High}}
	control := collapseReceipt("/control")
	main.Evidence = []evidence.Entry{evidence.Select(control, evidence.RoleControl, false, "survivor control")}
	folded := &output.ResultEvent{Host: "group", Info: output.Info{Severity: severity.Low}}
	modkit.SetPrimaryEvidence(folded, collapseReceipt("/related"), evidence.RoleAttack, "related attack")
	out := modkit.CollapseFindings([]*output.ResultEvent{main, folded}, modkit.CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 1)
	require.Len(t, main.Evidence, 3)
	primary := main.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleUnknown, primary.Role)
	require.Equal(t, evidence.ProvenanceSupplied, primary.Exchange.Provenance)
	// ForResult, like executor legacy normalization, snapshots the supplied
	// strings completely at the producer boundary. This does not certify a
	// transport capture: provenance stays supplied and the role stays unknown.
	require.Equal(t, evidence.StateComplete, primary.Exchange.RequestState)
	require.Equal(t, evidence.StateComplete, primary.Exchange.ResponseState)
	require.Empty(t, primary.Exchange.Service)
	require.Empty(t, primary.Exchange.URL)
	require.False(t, evidence.HasSelectedEvidence(main.Evidence), "related proof cannot promote the legacy survivor")
	require.NoError(t, primary.Exchange.Validate())
	require.Equal(t, main.Request, string(primary.Exchange.Request))
	require.Equal(t, main.Response, string(primary.Exchange.Response))
	require.False(t, main.Evidence[1].Primary)
	require.Equal(t, evidence.RoleControl, main.Evidence[1].Role)
	require.Equal(t, control.ID, main.Evidence[1].ExchangeID)
	require.False(t, main.Evidence[2].Primary)
	require.Equal(t, evidence.RoleConfirmation, main.Evidence[2].Role)
}

func TestCollapseTypedContextIsBoundedAndLegacyPrimaryStaysHonest(t *testing.T) {
	main := &output.ResultEvent{Host: "group", Request: "legacy main request", Response: "legacy main response", Info: output.Info{Severity: severity.High}}
	in := []*output.ResultEvent{main}
	for i := 0; i < 20; i++ {
		other := &output.ResultEvent{Host: "group", Info: output.Info{Severity: severity.Low}}
		modkit.SetPrimaryEvidence(other, collapseReceipt(fmt.Sprintf("/related-%d", i)), evidence.RoleObservation, "related observation")
		in = append(in, other)
	}
	out := modkit.CollapseFindings(in, modkit.CollapseSpec{Key: func(r *output.ResultEvent) string { return r.Host }})
	require.Len(t, out, 1)
	require.Len(t, main.Evidence, 1+modkit.MaxEvidencePairs)
	require.True(t, main.Evidence[0].Primary)
	require.Equal(t, evidence.RoleUnknown, main.Evidence[0].Role)
	require.Equal(t, evidence.ProvenanceSupplied, main.Evidence[0].Exchange.Provenance)
	for _, entry := range main.Evidence[1:] {
		require.False(t, entry.Primary)
		require.Equal(t, evidence.RoleObservation, entry.Role)
		require.NoError(t, entry.Exchange.Validate())
	}
}
