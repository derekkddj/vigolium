package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `finding --curl` renders explicitly selected primary requests for reproduction.
// Legacy requests have unknown roles and are never described as proof. Nothing is sent.

var (
	findingCurl       bool
	findingCurlAll    bool
	findingRedactAuth bool
)

func init() {
	// Registered here rather than in finding.go's init: findingCmd is a
	// package-level value, so its flag set exists before any init runs.
	f := findingCmd.Flags()
	f.BoolVar(&findingCurl, "curl", false, "Render the explicitly selected primary request as curl (legacy inline fallback is role unknown, not proof); nothing is sent")
	f.BoolVar(&findingCurlAll, "curl-all", false, "Render all selected exchanges and linked context requests with their roles; nothing is sent")
	f.BoolVar(&findingRedactAuth, "redact-auth", false, "With --curl/--curl-all: replace Authorization/Cookie/API-key header values with <redacted>")
}

// findingCurlConflicts are the finding modes --curl cannot be combined with.
var findingCurlConflicts = []string{"raw", "burp", "markdown", "tree", "tui", "push-to-burp", "to-repeater", "with-records"}

// validateFindingCurlFlags rejects what is knowable from the flags alone.
func validateFindingCurlFlags(cmd *cobra.Command) error {
	if !findingCurl && !findingCurlAll {
		if findingRedactAuth {
			return usageErrorf("--redact-auth only applies with --curl or --curl-all")
		}
		return nil
	}
	for _, name := range findingCurlConflicts {
		if flagOn(cmd, name) {
			return usageErrorf("--curl cannot be combined with --%s: one renders curl commands, the other a different view of the findings", name)
		}
	}
	return nil
}

// renderFindingCurl renders the selected findings' requests.
func renderFindingCurl(ctx context.Context, cmd *cobra.Command, db *database.DB, findings []*database.Finding, total int64, projectUUID string) error {
	byUUID := loadFindingRecordsOrWarn(ctx, db, findings)
	items := make([]curlItem, 0, len(findings))
	var skipped []int64
	for _, f := range findings {
		var rendered []curlItem
		if findingCurlAll {
			for _, entry := range f.Evidence {
				if it, ok := selectedExchangeCurl(entry); ok {
					rendered = append(rendered, it)
				}
			}
			rendered = append(rendered, findingRecordCurls(f, byUUID)...)
			if len(f.Evidence) == 0 && len(rendered) == 0 {
				if it, ok := findingEvidenceCurl(f); ok {
					rendered = append(rendered, it)
				}
			}
		} else if it, ok := findingEvidenceCurl(f); ok {
			rendered = append(rendered, it)
		}
		if len(rendered) == 0 {
			skipped = append(skipped, f.ID)
			continue
		}
		for i := range rendered {
			rendered[i].ID = f.ID
			rendered[i].FindingHash = f.FindingHash
			rendered[i].EvidenceStatus = f.EvidenceStatus
		}
		items = append(items, rendered...)
	}
	noteCurlCredentials(items)
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d finding(s) have no stored request to render: %v\n",
			terminal.WarningSymbol(), len(skipped), skipped)
	}

	if globalJSON {
		opts := []envOpt{
			withProjectScope(projectUUID),
			withDBPath(resolvedReadDBPath()),
			withExtra("findings_total", total),
			withExtra("skipped", len(skipped)),
			withRedacted(curlItemsRedacted(items)),
		}
		if len(items) > 0 {
			opts = append(opts, withQuery("finding", "--id", fmt.Sprint(items[0].ID), "--json", "--with-records"))
		}
		return emitRead(cmd, "", items, int64(len(items)), 0, len(items), opts...)
	}
	if len(items) == 0 {
		fmt.Fprintf(os.Stderr, "%s No finding requests to render.\n", terminal.InfoSymbol())
		return nil
	}
	printCurlItems(items, func(it curlItem) string {
		label := fmt.Sprintf("finding #%d", it.ID)
		if it.RecordUUID != "" {
			label += " record " + it.RecordUUID
		}
		if it.ExchangeID != "" {
			label += " exchange " + it.ExchangeID
		}
		if it.OccurrenceID != "" {
			label += " occurrence=" + it.OccurrenceID
		}
		label += " role=" + it.EvidenceRole + " (reproduction request, not a vulnerability verdict)"
		return label
	})
	return nil
}

// findingEvidenceCurl prefers a single explicitly selected primary entry. An
// unavailable or ambiguous selection never falls back to legacy/linked traffic.
func findingEvidenceCurl(f *database.Finding) (curlItem, bool) {
	if len(f.Evidence) > 0 {
		entry := primaryFindingEntry(f)
		if entry == nil {
			return curlItem{}, false
		}
		return selectedExchangeCurl(*entry)
	}
	if f.EvidenceStatus != "" && f.EvidenceStatus != "legacy_unknown" && f.EvidenceStatus != "unclassified" {
		return curlItem{}, false
	}
	if strings.TrimSpace(f.Request) == "" {
		return curlItem{}, false
	}
	target := findingURLValue(f)
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return curlItem{}, false
	}
	raw := []byte(f.Request)
	cmd, err := httpmsg.ToCurl(raw, u.Scheme+"://"+u.Host, httpmsg.CurlOptions{RedactAuth: findingRedactAuth})
	if err != nil {
		return curlItem{}, false
	}
	method, _ := httpmsg.GetMethod(raw)
	it := curlItemFrom(cmd, method, cmd.Argv[len(cmd.Argv)-1])
	it.EvidenceRole, it.RequestSource = string(evidence.RoleUnknown), "legacy_inline"
	return it, true
}

func selectedExchangeCurl(entry evidence.Entry) (curlItem, bool) {
	x := entry.Exchange
	if x == nil || x.ID != entry.ExchangeID || x.Validate() != nil || len(x.Request) == 0 || x.RequestState != evidence.StateComplete {
		return curlItem{}, false
	}
	u, err := selectedReceiptURL(x)
	if err != nil {
		return curlItem{}, false
	}
	cmd, err := httpmsg.ToCurl(x.Request, u.Scheme+"://"+u.Host, httpmsg.CurlOptions{RedactAuth: findingRedactAuth})
	if err != nil {
		return curlItem{}, false
	}
	method, _ := httpmsg.GetMethod(x.Request)
	it := curlItemFrom(cmd, method, cmd.Argv[len(cmd.Argv)-1])
	it.ExchangeID, it.EvidenceRole, it.RequestSource = entry.ExchangeID, string(entry.Role), "selected_exchange"
	it.OccurrenceID, it.FindingURL, it.ScanUUID, it.EvidenceLabel, it.EvidencePrimary = entry.OccurrenceID, entry.FindingURL, entry.ScanUUID, entry.Label, entry.Primary
	return it, true
}

// findingRecordCurls renders every linked record that holds a request.
func findingRecordCurls(f *database.Finding, byUUID map[string]*database.HTTPRecord) []curlItem {
	var out []curlItem
	for _, rec := range recordsForFinding(byUUID, f) {
		if len(rec.RawRequest) == 0 {
			continue
		}
		it, err := recordCurl(rec, findingRedactAuth || jsonRedactOn)
		if err != nil {
			continue
		}
		it.RecordUUID = rec.UUID
		it.EvidenceRole, it.RequestSource = string(evidence.RoleUnknown), "linked_context"
		if rec.UUID == f.OriginRecordUUID {
			it.RequestSource = "origin_replay_context"
		}
		out = append(out, it)
	}
	return out
}
