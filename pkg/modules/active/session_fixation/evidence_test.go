package session_fixation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestSessionReceiptDoesNotInventRawHTTPBuiltRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := "server-generated-123"
		if cookie, err := r.Cookie("SESSIONID"); err == nil {
			value = cookie.Value
		}
		http.SetCookie(w, &http.Cookie{Name: "SESSIONID", Value: value})
		w.Header().Set("X-Receipt", "session")
	}))
	defer srv.Close()
	results, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/app"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	require.False(t, result.BaselineEvidence)
	require.Equal(t, "missing", result.EvidenceStatus)
	require.Empty(t, result.Request, "RawRequest without RawBytes has no authoritative emitted request")
	require.Contains(t, result.Response, "Set-Cookie: SESSIONID=vigfix")
	require.True(t, result.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	for _, entry := range result.Evidence {
		if entry.Role == evidence.RoleBaseline {
			continue // supplied input is context, never repaired primary proof
		}
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.StateMissing, entry.Exchange.RequestState)
		require.Empty(t, entry.Exchange.Request)
		require.NotEmpty(t, entry.Exchange.Response)
	}
}
