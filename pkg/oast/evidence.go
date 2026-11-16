package oast

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

func attachOASTBaseline(result *output.ResultEvent, origin *database.HTTPRecord) {
	if len(origin.RawRequest) == 0 && len(origin.RawResponse) == 0 {
		return
	}
	service := ""
	if u, err := url.Parse(origin.URL); err == nil && u.Host != "" {
		service = u.Scheme + "://" + u.Host
	}
	x := evidence.NewExchange(service, origin.URL, origin.RawRequest, origin.RawResponse, evidence.ProvenanceLegacy)
	x.CapturedAt = time.Time{} // historical raw row has no receipt capture metadata
	if len(x.Request) > 0 {
		x.RequestState = evidence.StateUnknown
	}
	if len(x.Response) > 0 {
		x.ResponseState = evidence.StateUnknown
	}
	x.ContentHash = x.Hash()
	result.Evidence = append(result.Evidence, evidence.Select(x, evidence.RoleBaseline, false, "original scan input; not planting proof"))
}

func attachOASTCallback(result *output.ResultEvent, in *server.Interaction, pctx PayloadContext) {
	proto := strings.ToLower(in.Protocol)
	// Non-HTTP interactions, including web access-log lines labelled HTTP, are
	// forensic data, not fabricated HTTP request/response pairs. All raw fields
	// also remain independently retained in oast_interactions.
	isHTTP := proto == "http" || proto == "https"
	messageStart := requestLineRe.FindStringIndex(in.RawRequest)
	isMessage := in.RawRequest == "" || messageStart != nil && messageStart[0] == 0
	if !isHTTP || !isMessage {
		if in.RawRequest != "" || in.RawResponse != "" {
			result.AdditionalEvidence = append(result.AdditionalEvidence,
				"OAST interaction data ("+proto+"; not an HTTP exchange):\n"+strconv.Quote(in.RawRequest)+"\nCollector data:\n"+strconv.Quote(in.RawResponse))
		}
		return
	}
	if in.RawRequest == "" && in.RawResponse == "" {
		return
	}
	// The locator names the collaborator, not the victim/scan input. Prefer the
	// actual callback request's host/path when present; no target response is
	// inferred from it. The receipt has only the supplied collector bytes.
	locator := pctx.CallbackURL
	locations := httpRequestLocations(in.RawRequest)
	if len(locations) > 1 && locations[1] != "" {
		locator = locations[1]
	}
	if !strings.Contains(locator, "://") {
		locator = proto + "://" + locator
	}
	service := ""
	if u, err := url.Parse(locator); err == nil && u.Host != "" {
		service = u.Scheme + "://" + u.Host
	}
	x := evidence.NewExchange(service, locator, []byte(in.RawRequest), []byte(in.RawResponse), evidence.ProvenanceSupplied)
	// Collector export formats do not declare capture completeness. Presence
	// does not imply complete fidelity, and missing halves stay explicitly absent.
	if len(x.Request) > 0 {
		x.RequestState = evidence.StateUnknown
	}
	if len(x.Response) > 0 {
		x.ResponseState = evidence.StateUnknown
	}
	if !in.Timestamp.IsZero() && in.Timestamp.Year() >= 0 && in.Timestamp.Year() <= 9999 {
		x.CapturedAt = in.Timestamp
	} else {
		result.ExtractedResults = append(result.ExtractedResults, "callback_capture_time=unavailable (receipt time is import time)")
	}
	x.ContentHash = x.Hash()
	// Without a planting receipt this is supporting callback observation only,
	// not a selected target-response pair. The missing status remains explicit.
	result.Evidence = append(result.Evidence, evidence.Select(x, evidence.RoleObservation, false,
		"OAST HTTP callback at collaborator; not target response"))
	if ev := output.BuildEvidence("OAST HTTP callback (producer supplied; not target response)", in.RawRequest, in.RawResponse); ev != "" {
		result.AdditionalEvidence = append(result.AdditionalEvidence, ev)
	}
}

func (s *Service) attachPlantingReceipt(result *output.ResultEvent, nonce string) {
	x := s.plantingReceipt(nonce)
	if x == nil {
		result.ExtractedResults = append(result.ExtractedResults, "planting_receipt=missing")
		result.Info.Description += " Actual planting exchange unavailable; callback retained separately. Reconstructed intent is not captured evidence."
		return
	}
	result.Evidence = append(result.Evidence, evidence.Select(x, evidence.RoleAttack, true,
		"actual OAST planting exchange (sender receipt)"))
	result.Request, result.Response = string(x.Request), string(x.Response)
	result.EvidenceStatus = "selected"
	result.ExtractedResults = append(result.ExtractedResults, "planting_exchange="+x.ID)
}

func attributeOASTEvidence(result *output.ResultEvent, scan string) {
	occurrence := uuid.NewString()
	for i := range result.Evidence {
		result.Evidence[i].OccurrenceID = occurrence
		result.Evidence[i].FindingURL = result.URL
		result.Evidence[i].ScanUUID = scan
	}
}
