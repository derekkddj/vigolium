package iis_shortname_discovery

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"go.uber.org/zap"
)

// oracle holds the detection parameters for a vulnerable IIS server.
type oracle struct {
	method    string
	suffix    string
	statusPos int // status code when a tilde pattern matches
	statusNeg int // status code when it doesn't match
	tildes    []int
	primary   *evidence.Exchange
	context   *modkit.EvidenceCollector
}

// httpMethods to test during vulnerability detection, ordered by likelihood of success.
var httpMethods = []string{
	"OPTIONS", "HEAD", "TRACE", "DEBUG", "GET", "POST",
	"PUT", "PATCH", "DELETE",
}

// pathSuffixes to append after the wildcard pattern.
var pathSuffixes = []string{
	"/", "", "/.aspx", "?aspxerrorpath=/", "/.aspx?aspxerrorpath=/",
}

// pathEscape encodes a string for use in URL paths, using %20 instead of + for spaces.
func pathEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// sendProbe sends a single probe request and returns the HTTP status code.
func sendProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	method, path string,
	receiptOut ...**evidence.Exchange,
) (int, error) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return 0, err
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return 0, err
	}

	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return 0, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return 0, fmt.Errorf("nil response")
	}

	if len(receiptOut) > 0 && receiptOut[0] != nil {
		*receiptOut[0] = http.CaptureEvidence(resp)
	}
	return resp.Response().StatusCode, nil
}

// detectVulnerability probes the target to determine if it is vulnerable to
// IIS shortname enumeration. Returns nil if not vulnerable.
func detectVulnerability(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	basePath string,
	reqBudget *requestBudget,
) *oracle {
	for _, method := range httpMethods {
		for _, suffix := range pathSuffixes {
			if reqBudget.exhausted() {
				return nil
			}

			o := testMethodSuffix(ctx, httpClient, method, suffix, basePath, reqBudget)
			if o != nil {
				return o
			}
		}
	}
	return nil
}

// testMethodSuffix tests a specific HTTP method + path suffix combination.
func testMethodSuffix(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	method, suffix, basePath string,
	reqBudget *requestBudget,
) *oracle {
	// Negative probe: tilde level 5+ should never exist
	negPath := basePath + pathEscape(fmt.Sprintf("*%d*~5*", rand.Intn(90000)+10000)) + suffix
	reqBudget.inc()
	context := modkit.NewEvidenceCollector()
	var negative *evidence.Exchange
	statusNeg, err := sendProbe(ctx, httpClient, method, negPath, &negative)
	context.AddExchange(negative, evidence.RoleControl, "Nonexistent tilde-level negative")
	if err != nil {
		return nil
	}

	// Stability check: send a few more negative probes to confirm consistency
	for i := 0; i < 3; i++ {
		if reqBudget.exhausted() {
			return nil
		}
		checkPath := basePath + pathEscape(fmt.Sprintf("*%d*~5*", rand.Intn(90000)+10000)) + suffix
		reqBudget.inc()
		var stability *evidence.Exchange
		checkStatus, err := sendProbe(ctx, httpClient, method, checkPath, &stability)
		context.AddExchange(stability, evidence.RoleControl, fmt.Sprintf("Negative stability round %d", i+1))
		if err != nil || checkStatus != statusNeg {
			return nil // unstable
		}
	}

	// Positive probes: test tilde levels 1-4
	var activeTildes []int
	var statusPos int
	var primary *evidence.Exchange

	for tildeLevel := 1; tildeLevel <= 4; tildeLevel++ {
		if reqBudget.exhausted() {
			break
		}

		posPath := basePath + pathEscape(fmt.Sprintf("*~%d*", tildeLevel)) + suffix
		reqBudget.inc()
		var positive *evidence.Exchange
		status, err := sendProbe(ctx, httpClient, method, posPath, &positive)
		if err != nil {
			continue
		}

		if status != statusNeg {
			activeTildes = append(activeTildes, tildeLevel)
			statusPos = status
			if primary == nil {
				primary = positive
			} else {
				context.AddExchange(positive, evidence.RoleAttack, "Additional positive tilde level")
			}
		}
	}

	if len(activeTildes) == 0 {
		return nil
	}

	zap.L().Debug("IISShortname: vulnerability detected",
		zap.String("method", method),
		zap.String("suffix", suffix),
		zap.Int("statusPos", statusPos),
		zap.Int("statusNeg", statusNeg),
		zap.Ints("tildes", activeTildes),
	)

	return &oracle{
		method:    method,
		suffix:    suffix,
		statusPos: statusPos,
		statusNeg: statusNeg,
		tildes:    activeTildes,
		primary:   primary,
		context:   context,
	}
}
