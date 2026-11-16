package dependency_confusion

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/evidence"
	gohttp "github.com/vigolium/vigolium/pkg/http"
)

// defaultRegistryBase is the public npm registry. A referenced package name that
// 404s here is unclaimed and therefore a dependency-confusion candidate.
const defaultRegistryBase = "https://registry.npmjs.org"

// registryClient resolves package names against an npm-compatible registry. The
// base URL is a field so tests can point it at an httptest server and so a future
// caller can target a private registry.
type registryClient struct {
	baseURL string
	client  *http.Client
}

// newRegistryClient builds a client with a per-request timeout. It does not
// follow the target's proxy/rate-limit config: these are read-only HEAD probes to
// a fixed third-party host, unrelated to the scan target. The idle-connection
// pool is sized to the flush concurrency so all lookups reuse warm keep-alive
// connections instead of re-dialing.
func newRegistryClient(baseURL string, perRequestTimeout time.Duration) *registryClient {
	if baseURL == "" {
		baseURL = defaultRegistryBase
	}
	return &registryClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: perRequestTimeout,
			Transport: &http.Transport{
				// Preserve http.DefaultTransport's env-proxy support (a custom
				// transport otherwise disables it, breaking egress behind a proxy).
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        registryConcurrency,
				MaxIdleConnsPerHost: registryConcurrency,
				MaxConnsPerHost:     registryConcurrency,
			},
		},
	}
}

// resolution is the outcome of a registry lookup.
type resolution int

const (
	// resolutionIndeterminate means the registry could not be reached or gave a
	// transient/ambiguous status (network error, 429, 5xx). The caller fails
	// closed and emits nothing to avoid a false positive.
	resolutionIndeterminate resolution = iota
	// resolutionClaimed means the name is registered (HTTP 200) — not a candidate.
	resolutionClaimed
	// resolutionUnclaimed means the name is not registered (HTTP 404) — a
	// dependency-confusion candidate.
	resolutionUnclaimed
)

// lookup queries the registry for a single package name. It uses HEAD — the
// status code is all we need, so no packument body is transferred (a 200 for a
// popular scoped package can be many MB). Scoped names have their "/"
// percent-encoded (registry.npmjs.org expects "@scope%2fname").
func (c *registryClient) lookup(ctx context.Context, name string) (resolution, *evidence.Exchange) {
	escaped := strings.ReplaceAll(name, "/", "%2f")
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.baseURL+"/"+escaped, nil)
	if err != nil {
		return resolutionIndeterminate, nil
	}
	req.Header.Set("Accept", "application/json")

	// Capture this existing HEAD execution, not a reconstructed target request
	// or a second registry query. The final service belongs to the registry.
	chain, err := gohttp.DoCaptured(c.client, req, 1)
	if chain != nil {
		defer chain.Close()
	}
	// Error chains still need releasing, but errors remain indeterminate:
	// partial receipts do not change package declaration classification.
	if err != nil || chain == nil || chain.Response() == nil {
		return resolutionIndeterminate, nil
	}
	receipt := gohttp.CaptureEvidence(chain)

	switch chain.Response().StatusCode {
	case http.StatusOK:
		return resolutionClaimed, receipt
	case http.StatusNotFound:
		return resolutionUnclaimed, receipt
	default:
		// 429/5xx and anything else: treat as unknown, do not accuse.
		return resolutionIndeterminate, receipt
	}
}
