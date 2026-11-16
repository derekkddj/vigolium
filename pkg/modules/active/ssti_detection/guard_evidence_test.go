package ssti_detection

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
)

func TestSSTISelectionBoundsWholePairsAndReservesGuardSpace(t *testing.T) {
	makeSnap := func(name string) *diffscan.ResponseSnapshot {
		return &diffscan.ResponseSnapshot{Exchange: evidence.NewExchange("http://test", "http://test/"+name,
			[]byte("GET /"+name+" HTTP/1.1\r\nHost: test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n"+name), evidence.ProvenanceCaptured)}
	}
	var attacks []*diffscan.Attack
	for i := 0; i < 20; i++ {
		attacks = append(attacks,
			&diffscan.Attack{FirstSnapshot: makeSnap(fmt.Sprintf("break-%d", i)), LastSnapshot: makeSnap(fmt.Sprintf("break-confirm-%d", i))},
			&diffscan.Attack{FirstSnapshot: makeSnap(fmt.Sprintf("escape-%d", i)), LastSnapshot: makeSnap(fmt.Sprintf("escape-confirm-%d", i))})
	}
	baseline := &diffscan.Attack{FirstSnapshot: makeSnap("baseline")}
	for _, budget := range []int{modkit.MaxEvidencePairs, modkit.MaxEvidencePairs - 4} {
		entries := selectAttackEvidence(attacks, baseline, budget)
		require.LessOrEqual(t, len(entries), budget+1)
		require.True(t, entries[0].Primary)
		require.Equal(t, attacks[0].FirstSnapshot.Exchange.ID, entries[0].ExchangeID)
		require.Equal(t, baseline.FirstSnapshot.Exchange.ID, entries[len(entries)-1].ExchangeID)
		sparse := append([]*diffscan.Attack{{LastSnapshot: makeSnap("missing-first")}, {FirstSnapshot: makeSnap("earlier-control"), LastSnapshot: makeSnap("earlier-control-confirm")}}, attacks...)
		sparseEntries := selectAttackEvidence(sparse, baseline, budget)
		require.Equal(t, attacks[0].FirstSnapshot.Exchange.ID, sparseEntries[0].ExchangeID, "earlier missing probe context cannot displace the selected primary")
		// Complete groups stay in attack, attack-confirm, escape, escape-confirm order.
		require.Equal(t, 0, (len(entries)-1)%4)
		for i := 0; i < len(entries)-1; i += 4 {
			require.Equal(t, evidence.RoleAttack, entries[i].Role)
			require.Equal(t, evidence.RoleConfirmation, entries[i+1].Role)
			require.Equal(t, evidence.RoleControl, entries[i+2].Role)
			require.Equal(t, evidence.RoleConfirmation, entries[i+3].Role)
		}
	}
}
