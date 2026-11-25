package dependency_confusion

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestDeferredDependencyConfusionOwnsTargetAndRegistryReceipts(t *testing.T) {
	reg := newRecordingRegistry(t)
	m := reg.module()
	body := `import x from "@acme/one"; require("@acme/two");`
	input := modtest.Response(modtest.Request(t, "http://app.example.com/first.js"), "application/javascript", body)
	original := evidence.NewExchange("http://app.example.com", input.Target(), input.Request().Raw(), []byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+body+"\n// original, before analysis"), evidence.ProvenanceSupplied)
	input = input.WithEvidence(original)
	_, err := m.ScanPerRequest(input, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Empty(t, reg.queriedNames())

	// One receipt per candidate, shared for the two names from this bundle.
	first := m.observed["@acme/one"].observation
	require.Same(t, first, m.observed["@acme/two"].observation)
	original.Request[0] = 'X'
	original.Response[0] = 'X'
	require.NoError(t, first.Validate()) // independent of the caller's receipt

	for i := 0; i < maxObservedURLs+3; i++ {
		later := modtest.Response(modtest.Request(t, fmt.Sprintf("http://app.example.com/later-%d.js", i)), "application/javascript", `import "@acme/one";`)
		_, err := m.ScanPerRequest(later, &modkit.ScanContext{})
		require.NoError(t, err)
	}
	require.Same(t, first, m.observed["@acme/one"].observation)
	require.Len(t, m.observed["@acme/one"].urls, maxObservedURLs)

	results, err := m.FlushFindings(&modkit.ScanContext{ExternalFetcher: http.DefaultClient})
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Nil(t, m.observed)
	sortedEq(t, reg.queriedNames(), []string{"@acme/one", "@acme/two"})
	registryIDs := map[string]bool{}
	for _, result := range results {
		require.Equal(t, ModuleSeverity, result.Info.Severity)
		require.Equal(t, ModuleConfidence, result.Info.Confidence)
		require.Contains(t, result.Info.Description, "If the build resolves")
		require.Equal(t, input.Target(), result.URL)
		require.Equal(t, "selected", result.EvidenceStatus)
		require.Len(t, result.Evidence, 2)
		observation, confirmation := result.Evidence[0], result.Evidence[1]
		require.True(t, observation.Primary)
		require.Equal(t, evidence.RoleObservation, observation.Role)
		require.Equal(t, first.ID, observation.ExchangeID)
		require.Equal(t, "http://app.example.com", observation.Exchange.Service)
		require.Equal(t, evidence.ProvenanceSupplied, observation.Exchange.Provenance)
		require.Contains(t, result.Response, "original, before analysis")
		require.Equal(t, string(observation.Exchange.Request), result.Request)
		require.Equal(t, string(observation.Exchange.Response), result.Response)
		require.False(t, confirmation.Primary)
		require.Equal(t, evidence.RoleConfirmation, confirmation.Role)
		require.NoError(t, confirmation.Exchange.Validate())
		require.Equal(t, evidence.ProvenanceCaptured, confirmation.Exchange.Provenance)
		require.Equal(t, reg.srv.URL, confirmation.Exchange.Service)
		name := result.ExtractedResults[0]
		require.Equal(t, reg.srv.URL+"/"+strings.ReplaceAll(name, "/", "%2f"), confirmation.Exchange.URL)
		require.Contains(t, string(confirmation.Exchange.Request), "HEAD /"+strings.ReplaceAll(name, "/", "%2f")+" HTTP/1.1")
		require.Contains(t, string(confirmation.Exchange.Response), "404 Not Found")
		require.Equal(t, evidence.StateComplete, confirmation.Exchange.RequestState)
		require.Equal(t, evidence.StateComplete, confirmation.Exchange.ResponseState)
		require.Len(t, result.AdditionalEvidence, 1)
		require.False(t, registryIDs[confirmation.ExchangeID])
		registryIDs[confirmation.ExchangeID] = true
	}
	// Result selections are owned too, even when candidates shared an input.
	results[0].Evidence[0].Exchange.Response[0] = 'X'
	require.NoError(t, results[1].Evidence[0].Exchange.Validate())
	next, err := m.FlushFindings(&modkit.ScanContext{ExternalFetcher: http.DefaultClient})
	require.NoError(t, err)
	require.Empty(t, next)
	require.Len(t, reg.queriedNames(), 2)
}

func TestDeferredDependencyConfusionDirectInputIsSuppliedNotCaptured(t *testing.T) {
	reg := newRecordingRegistry(t)
	results := scanJS(t, reg.module(), "/bundle.js", `import "@acme/direct";`)
	require.Len(t, results, 1)
	require.Len(t, results[0].Evidence, 2)
	x := results[0].Evidence[0].Exchange
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
	require.Equal(t, "http://app.example.com/bundle.js", x.URL)
	require.Contains(t, string(x.Response), `import "@acme/direct";`)
}
