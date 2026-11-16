package salesforce_aura_apex_execution

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sf "github.com/vigolium/vigolium/pkg/modules/infra/salesforce"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmRounds is the number of additional independent SUCCESS observations of
// the benign Apex probe (on top of the first) required before reporting.
const confirmRounds = 2

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("salesforce_aura_apex_execution"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	// Tech gate: locating a live Aura gateway + harvesting its context IS the
	// fail-closed presence check (a non-Salesforce host has no gateway).
	collector := modkit.NewEvidenceCollector()
	endpoint, auraContext, ok := sf.Prepare(ctx, httpClient, scanCtx, collector)
	if !ok {
		return nil, nil
	}

	// Catch-all negative control (round 1): a bogus class/method must NOT succeed.
	// If it does, ApexActionController.execute rubber-stamps anything, so any
	// positive would be a false positive — skip the host.
	var preControl *evidence.Exchange
	if m.apexSucceeds(ctx, httpClient, endpoint, auraContext, bogusProbePre, &preControl) {
		return nil, nil
	}
	collector.AddExchange(preControl, evidence.RoleControl, "Bogus Apex before positive rounds")

	// The benign, read-only probe must return SUCCESS across every independent
	// round. A single ERROR/invalidSession round means the guest cannot (reliably)
	// invoke Apex and we do not report.
	var primary *evidence.Exchange
	for i := range confirmRounds + 1 {
		var exchange *evidence.Exchange
		if !m.apexSucceeds(ctx, httpClient, endpoint, auraContext, benignProbe, &exchange) {
			return nil, nil
		}
		if i == 0 {
			primary = exchange
		} else {
			collector.AddExchange(exchange, evidence.RoleConfirmation, fmt.Sprintf("Benign Apex confirmation %d", i))
		}
	}

	// Re-check the catch-all with a second, distinct bogus triple after the benign
	// rounds so a transient endpoint fluke cannot masquerade as a real positive.
	var postControl *evidence.Exchange
	if m.apexSucceeds(ctx, httpClient, endpoint, auraContext, bogusProbePost, &postControl) {
		return nil, nil
	}
	collector.AddExchange(postControl, evidence.RoleControl, "Bogus Apex after positive rounds")

	matchedURL := urlx.Scheme + "://" + urlx.Host + endpoint
	result := m.build(host, matchedURL, endpoint)
	result.AdditionalEvidence, result.Evidence = collector.Entries(), collector.Evidence()
	result.EvidenceStatus = "missing"
	modkit.SetPrimaryEvidence(result, primary, evidence.RoleAttack, "Guest benign Apex execution")
	return []*output.ResultEvent{result}, nil
}

// apexSucceeds invokes one ApexActionController.execute probe and reports whether
// the batch reached state SUCCESS (i.e. the server-side method ran). A non-JSON /
// framework-error / invalidSession body is treated as a non-success.
func (m *Module) apexSucceeds(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpoint, auraContext string,
	p apexProbe,
	receipts ...**evidence.Exchange,
) bool {
	resp := sf.InvokeAction(ctx, httpClient, endpoint, sf.BuildApexExecute(p.namespace, p.classname, p.method), auraContext)
	for _, receipt := range receipts {
		if receipt != nil {
			*receipt = resp.Exchange
		}
	}
	parsed, ok := sf.ParseAuraResponse(resp.Body)
	if !ok {
		return false
	}
	return parsed.HasSuccessAction()
}

func (m *Module) build(host, matchedURL, endpoint string) *output.ResultEvent {
	probeName := benignProbe.namespace + "." + benignProbe.classname + "." + benignProbe.method
	evidence := []string{
		"aura gateway: " + endpoint,
		"action: aura://ApexActionController/ACTION$execute",
		"benign probe (SUCCESS): " + probeName,
		"bogus class/method probes returned non-success (no catch-all)",
	}

	desc := fmt.Sprintf(
		"The Salesforce Experience Cloud Guest user can invoke @AuraEnabled Apex through the ApexActionController.execute action at %s with a null "+
			"(guest) token. The benign read-only method %s returned state:SUCCESS across %d independent rounds, while two distinct bogus class/method "+
			"probes returned a non-success state (ruling out a catch-all endpoint). Guest Apex reachability is the pivot for SSRF, bulk SOQL data "+
			"exfiltration, content injection and phishing — only the read-only capability was confirmed here, no side-effecting method was invoked.",
		endpoint, probeName, confirmRounds+1,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "Salesforce Aura Guest Apex Execution",
			Description: desc,
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"platform": "salesforce", "action": "ApexActionController.execute"},
	}
}
