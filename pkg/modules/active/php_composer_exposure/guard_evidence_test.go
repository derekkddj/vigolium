package php_composer_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestComposerGuardReceiptsKeepCandidatePrimaryAndSendCount(t *testing.T) {
	for _, tc := range []struct {
		probe probe
		body  string
	}{
		{probes[0], `{"require":{"vendor/package":"1.0"}}`},
		{probes[1], `{"_readme":"Composer lock","packages":[{"dist":{"reference":"abc"}}]}`},
	} {
		t.Run(tc.probe.path, func(t *testing.T) {
			var sends atomic.Int64
			controlBody := strings.Repeat("actual missing sibling body ", 12000)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Send", fmt.Sprint(sends.Add(1)))
				w.Header().Set("X-Actual-Path", r.URL.Path)
				if r.URL.Path == tc.probe.path {
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprint(w, tc.body)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, controlBody)
			}))
			defer srv.Close()

			result := New().probeFile(modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), tc.probe, nil)
			require.NotNil(t, result)
			require.Equal(t, int64(1+decoyRounds), sends.Load(), "support selection must not add requests")
			require.Len(t, result.Evidence, 1+decoyRounds)
			require.LessOrEqual(t, len(result.Evidence)-1, modkit.MaxEvidencePairs)
			require.Len(t, result.AdditionalEvidence, decoyRounds)
			require.Equal(t, "PHP Composer Exposure: "+tc.probe.name, result.Info.Name)
			require.Equal(t, tc.probe.sev, result.Info.Severity)
			require.Equal(t, ModuleConfidence, result.Info.Confidence)

			primary := result.Evidence[0]
			require.True(t, primary.Primary)
			require.Equal(t, evidence.RoleObservation, primary.Role)
			require.NoError(t, primary.Exchange.Validate())
			require.Equal(t, string(primary.Exchange.Request), result.Request)
			require.Equal(t, string(primary.Exchange.Response), result.Response)
			require.Contains(t, result.Request, "GET "+tc.probe.path+" HTTP/")
			require.Contains(t, result.Response, "X-Send: 1")
			require.True(t, strings.HasSuffix(result.Response, tc.body))

			ids := map[string]bool{primary.ExchangeID: true}
			for i, control := range result.Evidence[1:] {
				require.False(t, control.Primary)
				require.Equal(t, evidence.RoleControl, control.Role)
				require.False(t, ids[control.ExchangeID], "each sibling must retain its own execution identity")
				ids[control.ExchangeID] = true
				require.NoError(t, control.Exchange.Validate())
				require.Contains(t, string(control.Exchange.Request), "GET /vigolium-decoy-")
				require.Contains(t, string(control.Exchange.Request), "."+strings.TrimPrefix(tc.probe.path, "/composer.")+" HTTP/")
				require.Contains(t, string(control.Exchange.Response), fmt.Sprintf("X-Send: %d", i+2))
				require.Contains(t, string(control.Exchange.Response), "X-Actual-Path: /vigolium-decoy-")
				require.True(t, strings.HasSuffix(string(control.Exchange.Response), controlBody), "retain full receipts, not comparison-body caps")
			}
		})
	}
}
