package servicenow_kb_widget_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	sn "github.com/vigolium/vigolium/pkg/modules/infra/servicenow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestKnowledgeEvidenceIsBoundedAndSelectsSuccessfulArticle(t *testing.T) {
	exposed := map[string]bool{}
	for i := 1; i <= kbBruteCount; i++ {
		exposed[fmt.Sprintf("KB%07d", i)] = true
	}
	srv := snServer(t, exposed, false)
	results, err := New().ScanPerHost(modtest.Request(t, srv.URL), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.False(t, r.BaselineEvidence)
	require.Equal(t, kbBruteCount, r.Metadata["exposed_kb_count"])
	require.Len(t, r.Evidence, modkit.MaxEvidencePairs+1)
	require.Len(t, r.AdditionalEvidence, modkit.MaxEvidencePairs)
	require.True(t, r.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, r.Evidence[0].Role)
	require.Contains(t, r.Request, "?sys_id=KB0000001")
	require.Contains(t, r.Response, "Internal procedure")
	seen := map[string]bool{}
	controls := 0
	for _, entry := range r.Evidence {
		require.NotNil(t, entry.Exchange)
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, seen[entry.ExchangeID])
		seen[entry.ExchangeID] = true
		if entry.Role == evidence.RoleControl {
			controls++
			require.Contains(t, string(entry.Exchange.Request), "?sys_id="+bogusKB)
		}
	}
	require.Equal(t, 1, controls)
}

func TestFailedKnowledgeConfirmationDiscardsAttemptReceipts(t *testing.T) {
	// One positive and one replay are not enough when the last replay is empty.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < confirmRounds+1 {
			_, _ = w.Write([]byte(`{"data":{"text":"first positive"}}`))
		} else {
			_, _ = w.Write([]byte(`{"data":{"text":""}}`))
		}
	}))
	defer srv.Close()
	r := New().confirmKBCapture(modtest.Request(t, srv.URL), modtest.Requester(t), "KB0000001", sn.Session{})
	require.False(t, r.OK)
	require.Empty(t, r.Exchanges)
	require.EqualValues(t, confirmRounds+1, calls.Load())
}
