package cli

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
)

// printSelectedEvidence renders a non-authoritative text view without relabeling
// baseline/control/unknown receipts as proof. Machine exports carry exact bytes.
func printSelectedEvidence(f *database.Finding, burp bool) {
	status := f.EvidenceStatus
	if status == "" {
		status = "missing / unclassified"
	}
	fmt.Printf("Stored finding evidence status: %s\n", status)
	fmt.Println("Original finding metadata; each occurrence retains its own role/primary flag. Later selections do not reclassify legacy evidence.")
	if primaryFindingEntry(f) == nil {
		fmt.Println("No single explicitly selected primary proof / observation (missing, unclassified or multiple occurrences).")
	}
	for _, e := range f.Evidence {
		fmt.Printf("Exchange %s role=%s primary=%t occurrence=%s label=%s\n", e.ExchangeID, e.Role, e.Primary, e.OccurrenceID, e.Label)
		if e.Exchange == nil {
			fmt.Println("Selected bytes unavailable; no fallback substituted.")
			continue
		}
		x := e.Exchange
		fmt.Printf("URL=%s request_state=%s response_state=%s provenance=%s hash=%s\nText preview only; JSON/export contains authoritative base64 bytes.\n", x.URL, x.RequestState, x.ResponseState, x.Provenance, x.ContentHash)
		if burp {
			printBurpRequest(x.Request)
			printBurpResponse(x.Response, 0)
		} else {
			fmt.Println(string(x.Request))
			fmt.Println(string(x.Response))
		}
	}
}
