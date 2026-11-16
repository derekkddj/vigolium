package aem_rce

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestUIGuardEvidenceIsCandidateLocalAndPreservesPrimary(t *testing.T) {
	for _, rejectFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject-first=%t", rejectFirst), func(t *testing.T) {
			const path = "/etc/groovyconsole.html"
			const rejectedPath = "/rejected/groovyconsole.html"
			var mu sync.Mutex
			var received []string
			var rejectedRounds int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				received = append(received, r.RequestURI)
				operation := len(received)
				if r.URL.Path == rejectedPath {
					rejectedRounds++
				}
				failedConfirmation := r.URL.Path == rejectedPath && rejectedRounds > 1
				mu.Unlock()
				w.Header().Set("X-Evidence-Operation", fmt.Sprint(operation))
				w.Header().Set("Content-Type", "text/html")
				if (r.URL.Path == path || r.URL.Path == rejectedPath) && !failedConfirmation {
					_, _ = fmt.Fprintf(w, "%s<p>operation %d</p>", groovyBody, operation)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprintf(w, "negative control or failed confirmation: %s", r.RequestURI)
			}))
			t.Cleanup(srv.Close)
			surface := uiSurfaces[0]
			surface.paths = []string{path}
			if rejectFirst {
				surface.paths = append([]string{rejectedPath}, surface.paths...)
			}
			seed := modtest.Request(t, srv.URL+"/input-only")
			result := New().probeUI(seed, modtest.Requester(t), surface, srv.URL)
			require.NotNil(t, result)
			require.Equal(t, severity.Critical, result.Info.Severity)
			require.Equal(t, severity.Firm, result.Info.Confidence)
			require.Contains(t, result.ExtractedResults, "detection-only: no script/JSP was executed")
			require.Len(t, result.Evidence, 1+reproduceRounds+1)
			require.Len(t, result.AdditionalEvidence, reproduceRounds+1)
			primary := result.Evidence[0]
			require.True(t, primary.Primary)
			require.Equal(t, evidence.RoleObservation, primary.Role)
			require.Equal(t, string(primary.Exchange.Request), result.Request)
			require.Equal(t, string(primary.Exchange.Response), result.Response)
			require.Empty(t, result.Payload)
			parsedPrimary, err := httpmsg.FromEvidenceExchange(primary.Exchange)
			require.NoError(t, err)
			require.Equal(t, path, parsedPrimary.Request().Path())
			mu.Lock()
			actual := append([]string(nil), received...)
			mu.Unlock()
			offset := 0
			if rejectFirst {
				offset = 3 // initial rejected candidate, sibling, failed first reproduction
			}
			require.Len(t, actual, offset+4, "each successful candidate sends its initial probe, one guard and two confirmations only")
			if rejectFirst {
				require.Equal(t, rejectedPath, actual[0])
				require.Equal(t, rejectedPath, actual[2])
			}
			require.Contains(t, result.Response, fmt.Sprintf("X-Evidence-Operation: %d", offset+1), "the initial successful probe remains primary, not a later guard or confirmation")
			for i, entry := range result.Evidence[1 : 1+reproduceRounds] {
				require.False(t, entry.Primary)
				require.Equal(t, evidence.RoleConfirmation, entry.Role)
				require.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Evidence-Operation: %d", offset+3+i))
			}
			control := result.Evidence[1+reproduceRounds]
			require.False(t, control.Primary)
			require.Equal(t, evidence.RoleControl, control.Role)
			parsedControl, err := httpmsg.FromEvidenceExchange(control.Exchange)
			require.NoError(t, err)
			require.Equal(t, []string{path, parsedControl.Request().Path(), path, path}, actual[offset:])
			require.Equal(t, seed.Service().Port(), parsedControl.Service().Port())
			require.Contains(t, string(control.Exchange.Response), fmt.Sprintf("X-Evidence-Operation: %d", offset+2))
			require.Contains(t, string(control.Exchange.Response), "negative control or failed confirmation: "+parsedControl.Request().Path())
			for _, entry := range result.Evidence {
				require.NotContains(t, string(entry.Exchange.Request), "/rejected/", "a rejected candidate's deciding control must not leak into the emitted candidate")
			}
			require.Contains(t, result.AdditionalEvidence[reproduceRounds], string(control.Exchange.Response))
		})
	}
}
