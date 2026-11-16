package modkit

import (
	"regexp"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// The WithEvidence guard APIs preserve the original guard's requests, caching,
// short-circuiting and verdict. A nil sink disables selection. Sinks are local to
// an operation/candidate, never global last-response stores. Cached probes retain
// their actual execution identity; reusing them does not claim a new execution.

func SiblingPathCatchAll(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, match func(string) bool) bool {
	return SiblingPathCatchAllWithEvidence(sc, ctx, client, path, match, nil)
}

func DecoyFileBaseline(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string) (int, string, bool) {
	return DecoyFileBaselineWithEvidence(sc, ctx, client, path, nil)
}

func RandomDirCatchAll(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester, match func(string) bool) bool {
	return RandomDirCatchAllWithEvidence(sc, ctx, client, match, nil)
}

func RootPageCatchAll(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester, match func(string) bool) bool {
	return RootPageCatchAllWithEvidence(sc, ctx, client, match, nil)
}

func ResemblesCatchAllShell(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester, body string) bool {
	return ResemblesCatchAllShellWithEvidence(sc, ctx, client, body, nil)
}

func MultiRoundExtDecoyCatchAll(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path, body string, status, rounds int, match func(string) bool) bool {
	return MultiRoundExtDecoyCatchAllWithEvidence(ctx, client, path, body, status, rounds, match, nil)
}

func FetchPath(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string) (int, string, bool) {
	return FetchPathWithEvidence(ctx, client, path, nil)
}

func fetchGET(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, opts http.Options) (int, string, bool) {
	return fetchGETWithEvidence(ctx, client, path, opts, nil, evidence.RoleControl, "")
}

func SiblingServesAnyMarker(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, markers []string) bool {
	return SiblingServesAnyMarkerWithEvidence(sc, ctx, client, path, markers, nil)
}

func MatchAndConfirmSibling(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path, body string, markers [][]string) ([]string, bool) {
	return MatchAndConfirmSiblingWithEvidence(ctx, client, path, body, markers, nil)
}

func PathSegmentReflected(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string) bool {
	return PathSegmentReflectedWithEvidence(ctx, client, path, nil)
}

func SlugReflectionFP(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path string, markers []string) bool {
	return SlugReflectionFPWithEvidence(ctx, client, path, markers, nil)
}

func ConfirmNotSoft404(sc *ScanContext, client *http.Requester, req *httpmsg.HttpRequestResponse, status int, body []byte, location string) bool {
	return ConfirmNotSoft404WithEvidence(sc, client, req, status, body, location, nil)
}

func ConfirmMatchReproduces(ctx *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint, client *http.Requester, payload []byte, re *regexp.Regexp) bool {
	return ConfirmMatchReproducesWithEvidence(ctx, ip, client, payload, re, nil)
}

func EndpointVolatile(sc *ScanContext, ctx *httpmsg.HttpRequestResponse, client *http.Requester) bool {
	return EndpointVolatileWithEvidence(sc, ctx, client, nil)
}

// WildcardProbeWithEvidence selects the receipt that produced this cached
// fingerprint, not a request inferred from its host key or the candidate path.
func (sc *ScanContext) WildcardProbeWithEvidence(ctx *httpmsg.HttpRequestResponse, client *http.Requester, sink *EvidenceCollector) (*WildcardEntry, error) {
	entry, err := sc.WildcardProbe(ctx, client)
	if entry != nil {
		sink.AddExchange(entry.Receipt, evidence.RoleControl, "wildcard/soft-404 probe")
	}
	return entry, err
}

// AppendEvidence adds bounded context without replacing a producer-selected
// primary or changing classification. It deduplicates only explicit receipt
// identity+role, never endpoint/request hashes. Existing selections are preserved.
func AppendEvidence(result *output.ResultEvent, sink *EvidenceCollector) {
	if result == nil || sink == nil {
		return
	}
	selected, rendered := sink.Evidence(), sink.Entries()
	if len(selected) == 0 {
		return
	}
	// Context must not hide an as-yet-unmigrated producer's legacy primary.
	// This is supplied/unknown intent, never an inferred captured proof role.
	hasPrimary := false
	for _, entry := range result.Evidence {
		hasPrimary = hasPrimary || entry.Primary
	}
	if !hasPrimary && (result.Request != "" || result.Response != "") {
		legacy := NewEvidenceCollector().ForResult(result.Request, result.Response)
		result.Evidence = append(legacy, result.Evidence...)
	}
	contextCount := 0
	for _, entry := range result.Evidence {
		if !entry.Primary {
			contextCount++
		}
	}
	for i, entry := range selected {
		if contextCount >= MaxEvidencePairs {
			break
		}
		duplicate := false
		for _, existing := range result.Evidence {
			if existing.ExchangeID == entry.ExchangeID && existing.Role == entry.Role {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		entry.Primary = false
		result.Evidence = append(result.Evidence, entry)
		if i < len(rendered) && len(result.AdditionalEvidence) < MaxEvidencePairs {
			result.AdditionalEvidence = append(result.AdditionalEvidence, rendered[i])
		}
		contextCount++
	}
}
