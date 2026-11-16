package xpath_injection

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestBooleanReceiptsRetainBothFunctionRoundsWithinCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", "xpath")
		_, _ = fmt.Fprint(w, xpathRender(r.URL.Query().Get("id")))
	}))
	defer srv.Close()
	ctx := modtest.Request(t, srv.URL+"/lookup?id=admin")
	ip := modtest.InsertionPoint(t, ctx, "id")
	result := New().scanBoolean(ctx, ip, modtest.Requester(t), ctx.Target(), "admin")
	require.NotNil(t, result)
	require.False(t, result.BaselineEvidence)
	require.Len(t, result.AdditionalEvidence, modkit.MaxEvidencePairs)
	require.Len(t, result.Evidence, modkit.MaxEvidencePairs+1)
	require.True(t, result.Evidence[0].Primary)
	require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
	require.NotEqual(t, string(ctx.Request().Raw()), result.Request)
	ids := map[string]bool{}
	functionRoles := map[evidence.Role]int{}
	for _, entry := range result.Evidence {
		require.NoError(t, entry.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		require.False(t, ids[entry.ExchangeID], "each retained send has its own identity")
		ids[entry.ExchangeID] = true
		require.Contains(t, string(entry.Exchange.Response), "X-Receipt: xpath")
		if strings.Contains(entry.Label, "core function") {
			functionRoles[entry.Role]++
		}
	}
	require.Equal(t, 2, functionRoles[evidence.RoleConfirmation])
	require.Equal(t, 2, functionRoles[evidence.RoleControl])
}
