package aem_sensitive_servlet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestServletGuardEvidencePreservesPrimaryAndShortCircuits(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		siblingGuard bool
		wantControl  bool
	}{
		{"guarded JSON", "/bin/querybuilder.json?type=rep:User", true, true},
		{"guard disabled", "/bin/querybuilder.json?type=rep:User", false, false},
		{"root-level guard no-op", "/querybuilder.json?type=rep:User", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var received []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = append(received, r.RequestURI)
				operation := len(received)
				mu.Unlock()
				w.Header().Set("X-Evidence-Operation", fmt.Sprint(operation))
				w.Header().Set("Content-Type", "application/json")
				if r.RequestURI == tc.path {
					_, _ = fmt.Fprintf(w, `{"success":true,"hits":[{"rep:password":"{SHA-256}deadbeef"}],"operation":%d}`, operation)
					return
				}
				// A 200 with nonmatching JSON decides "not catch-all", and must
				// still be attached as the actual negative control.
				_, _ = fmt.Fprintf(w, `{"success":false,"control_path":%q}`, r.RequestURI)
			}))
			t.Cleanup(srv.Close)
			s := servlets[0]
			s.paths = []string{tc.path}
			s.siblingGuard = tc.siblingGuard
			seed := modtest.Request(t, srv.URL+"/input-only")
			result := New().probeServlet(seed, modtest.Requester(t), &modkit.ScanContext{}, s, srv.URL)
			require.NotNil(t, result)
			require.Equal(t, "AEM QueryBuilder Password Hash Disclosure", result.Info.Name)
			require.Equal(t, severity.Critical, result.Info.Severity)
			require.Equal(t, severity.Certain, result.Info.Confidence)
			controlCount := 0
			if tc.wantControl {
				controlCount = 1
			}
			require.Len(t, result.Evidence, 1+reproduceRounds+controlCount)
			require.Len(t, result.AdditionalEvidence, reproduceRounds+controlCount)
			primary := result.Evidence[0]
			require.True(t, primary.Primary)
			require.Equal(t, evidence.RoleObservation, primary.Role)
			require.Equal(t, string(primary.Exchange.Request), result.Request)
			require.Equal(t, string(primary.Exchange.Response), result.Response)
			require.Contains(t, result.Response, "X-Evidence-Operation: 1", "the initial disclosure remains primary after appending guard evidence")
			require.Empty(t, result.Payload)
			parsedPrimary, err := httpmsg.FromEvidenceExchange(primary.Exchange)
			require.NoError(t, err)
			require.Equal(t, tc.path, parsedPrimary.Request().Path())
			for i, entry := range result.Evidence[1 : 1+reproduceRounds] {
				require.False(t, entry.Primary)
				require.Equal(t, evidence.RoleConfirmation, entry.Role)
				require.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Evidence-Operation: %d", 2+controlCount+i))
			}
			mu.Lock()
			actual := append([]string(nil), received...)
			mu.Unlock()
			require.Len(t, actual, 1+reproduceRounds+controlCount, "guard attachment must not send extra requests or bypass a no-op guard")
			if !tc.wantControl {
				require.Equal(t, []string{tc.path, tc.path, tc.path}, actual)
				return
			}
			control := result.Evidence[1+reproduceRounds]
			require.False(t, control.Primary)
			require.Equal(t, evidence.RoleControl, control.Role)
			parsedControl, err := httpmsg.FromEvidenceExchange(control.Exchange)
			require.NoError(t, err)
			require.Equal(t, []string{tc.path, parsedControl.Request().Path(), tc.path, tc.path}, actual)
			require.NotEqual(t, primary.ExchangeID, control.ExchangeID)
			require.Equal(t, seed.Service().Port(), parsedControl.Service().Port())
			require.Contains(t, string(control.Exchange.Response), "X-Evidence-Operation: 2")
			require.Contains(t, string(control.Exchange.Response), `{"success":false,"control_path":"`+parsedControl.Request().Path()+`"}`)
			require.Contains(t, result.AdditionalEvidence[reproduceRounds], string(control.Exchange.Response))
		})
	}
}
