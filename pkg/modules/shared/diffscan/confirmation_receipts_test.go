package diffscan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestVerificationReceiptListIgnoresBaselineMergesAndIsBounded(t *testing.T) {
	probe := NewProbe("test", 0, "break")
	proof := evidence.NewExchange("", "", []byte("proof request"), []byte("proof response"), evidence.ProvenanceSupplied)
	control := evidence.NewExchange("", "", []byte("baseline request"), []byte("baseline response"), evidence.ProvenanceSupplied)
	attack := NewAttackFromSnapshot(&ResponseSnapshot{Exchange: proof}, probe, "escape", "", nil, 5, "")
	baseline := NewAttackFromSnapshot(&ResponseSnapshot{Exchange: control}, nil, "base", "", nil, 5, "")
	attack.AddAttack(baseline)
	assert.Equal(t, proof.ID, attack.FirstSnapshot.Exchange.ID)
	assert.Empty(t, attack.ConfirmationReceipts)
	for i := 0; i < 12; i++ {
		x := evidence.NewExchange("", "", []byte("reproduction request"), []byte("reproduction response"), evidence.ProvenanceSupplied)
		attack.recordConfirmation(&Attack{FirstSnapshot: &ResponseSnapshot{Exchange: x}})
	}
	require.Len(t, attack.ConfirmationReceipts, 10)
	for _, x := range attack.ConfirmationReceipts {
		assert.NotEqual(t, control.ID, x.ID)
		assert.NotEqual(t, proof.ID, x.ID)
	}
}
