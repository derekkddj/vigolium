package aem_console_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestConsoleGuardEvidencePreservesPrimaryAndCachedControl(t *testing.T) {
	paths := []string{"/crx/de/index.jsp", "/crx/de/alternate.jsp"}
	var mu sync.Mutex
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.RequestURI)
		operation := len(received)
		mu.Unlock()
		w.Header().Set("X-Evidence-Operation", fmt.Sprint(operation))
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == paths[0] || r.URL.Path == paths[1] {
			_, _ = fmt.Fprintf(w, "<title>CRXDE Lite</title><p>panel operation %d</p>", operation)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w, "nonexistent sibling: %s", r.RequestURI)
	}))
	t.Cleanup(srv.Close)
	seed, client := modtest.Request(t, srv.URL+"/input-only"), modtest.Requester(t)
	scanCtx := &modkit.ScanContext{}
	m, p := New(), panels[0]
	var cachedControl *evidence.Exchange
	for i, path := range paths {
		initial := aem.Get(seed, client, path, nil)
		require.True(t, initial.OK)
		require.NotNil(t, initial.Exchange)
		primaryBefore := initial.Exchange.Clone()
		proof := aem.NewProof(initial)
		result := m.confirm(seed, client, scanCtx, p, path, srv.URL, "", proof)
		require.NotNil(t, result)
		require.Equal(t, severity.High, result.Info.Severity)
		require.Equal(t, severity.Firm, result.Info.Confidence)
		require.Len(t, result.Evidence, 1+reproduceRounds+1)
		require.Len(t, result.AdditionalEvidence, reproduceRounds+1)
		require.Equal(t, primaryBefore, result.Evidence[0].Exchange, "appending the guard must not replace or mutate the selected panel receipt")
		require.Equal(t, primaryBefore.ID, result.Evidence[0].ExchangeID)
		require.True(t, result.Evidence[0].Primary)
		require.Equal(t, evidence.RoleObservation, result.Evidence[0].Role)
		require.Equal(t, string(primaryBefore.Request), result.Request)
		require.Equal(t, string(primaryBefore.Response), result.Response)
		require.Empty(t, result.Payload)
		for _, entry := range result.Evidence[1 : 1+reproduceRounds] {
			require.False(t, entry.Primary)
			require.Equal(t, evidence.RoleConfirmation, entry.Role)
		}
		control := result.Evidence[1+reproduceRounds]
		require.False(t, control.Primary)
		require.Equal(t, evidence.RoleControl, control.Role)
		parsed, err := httpmsg.FromEvidenceExchange(control.Exchange)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(parsed.Request().Path(), "/crx/de/"))
		require.NotContains(t, paths, parsed.Request().Path())
		require.Equal(t, seed.Service().Port(), parsed.Service().Port())
		require.Contains(t, string(control.Exchange.Response), "X-Evidence-Operation: 2")
		require.Contains(t, string(control.Exchange.Response), "nonexistent sibling: "+parsed.Request().Path())
		require.Contains(t, result.AdditionalEvidence[reproduceRounds], string(control.Exchange.Response))
		mu.Lock()
		actual := append([]string(nil), received...)
		mu.Unlock()
		if i == 0 {
			require.Equal(t, []string{path, parsed.Request().Path(), path, path}, actual, "initial probe + one guard + two confirmations; no evidence-only traffic")
			cachedControl = control.Exchange.Clone()
		} else {
			require.Len(t, actual, 7, "the second candidate reuses the existing sibling guard and sends only its probe + two confirmations")
			require.Equal(t, []string{path, path, path}, actual[4:])
			require.Equal(t, cachedControl, control.Exchange, "cache reuse must retain the original receipt, identity, capture states and stamp")
		}
	}
}

func TestConsoleBypassGuardAppendsAfterBlockedControlAndPrimary(t *testing.T) {
	const path = "/crx/de/index.jsp"
	bypass := aem.TraversalBypasses(path)[0]
	var mu sync.Mutex
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.RequestURI)
		operation := len(received)
		mu.Unlock()
		w.Header().Set("X-Evidence-Operation", fmt.Sprint(operation))
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case path:
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "dispatcher denied direct path")
		case bypass:
			_, _ = fmt.Fprintf(w, "<title>CRXDE Lite</title><p>bypass operation %d</p>", operation)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprintf(w, "nonexistent bypass sibling: %s", r.RequestURI)
		}
	}))
	t.Cleanup(srv.Close)
	result := New().probePanel(modtest.Request(t, srv.URL+"/input-only"), modtest.Requester(t), &modkit.ScanContext{}, panels[0], srv.URL)
	require.NotNil(t, result)
	require.Equal(t, severity.High, result.Info.Severity)
	require.Equal(t, severity.Firm, result.Info.Confidence)
	require.Equal(t, output.RecordKindFinding, result.RecordKind)
	require.Equal(t, output.EvidenceGradeBypass, result.EvidenceGrade)
	require.Len(t, result.Evidence, 5)
	require.Len(t, result.AdditionalEvidence, 4)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.Equal(t, string(primary.Exchange.Request), result.Request)
	require.Equal(t, string(primary.Exchange.Response), result.Response)
	parsedPrimary, err := httpmsg.FromEvidenceExchange(primary.Exchange)
	require.NoError(t, err)
	require.Equal(t, bypass, parsedPrimary.Request().Path())
	require.Contains(t, result.Response, "X-Evidence-Operation: 2")
	blocked := result.Evidence[1]
	require.False(t, blocked.Primary)
	require.Equal(t, evidence.RoleControl, blocked.Role)
	require.Contains(t, string(blocked.Exchange.Response), "dispatcher denied direct path")
	for _, entry := range result.Evidence[2:4] {
		require.False(t, entry.Primary)
		require.Equal(t, evidence.RoleConfirmation, entry.Role)
	}
	guard := result.Evidence[4]
	require.False(t, guard.Primary)
	require.Equal(t, evidence.RoleControl, guard.Role)
	parsedGuard, err := httpmsg.FromEvidenceExchange(guard.Exchange)
	require.NoError(t, err)
	require.Contains(t, string(guard.Exchange.Response), "X-Evidence-Operation: 3")
	require.Contains(t, string(guard.Exchange.Response), "nonexistent bypass sibling: "+parsedGuard.Request().Path())
	mu.Lock()
	actual := append([]string(nil), received...)
	mu.Unlock()
	require.Equal(t, []string{path, bypass, parsedGuard.Request().Path(), bypass, bypass}, actual, "bypass detection sends the same five operations; guard evidence is append-only")
}
