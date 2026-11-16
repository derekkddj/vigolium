package httpmsg

import (
	"context"
	"net/url"

	"github.com/vigolium/vigolium/pkg/evidence"
)

// RequestTargetPolicy describes reproduction of the request line, not the
// completeness of a newly captured exchange. A complete capture of a normalized
// request does not establish exact reproduction of the original absolute form.
type RequestTargetPolicy struct {
	IntendedTarget string         `json:"intended_target"`
	DirectTarget   string         `json:"direct_target"`
	Policy         string         `json:"policy"`
	Fidelity       evidence.State `json:"fidelity"`
	Note           string         `json:"note"`
}

// NativeRequestTargetPolicy reports absolute targets that net/http cannot keep
// independently of its connection URL. Nil leaves ordinary origin-form behavior
// unchanged and does not claim full raw-message/wire fidelity.
func NativeRequestTargetPolicy(raw []byte) *RequestTargetPolicy {
	target, err := GetPath(raw)
	if err != nil || !isAbsoluteFormTarget(target) {
		return nil
	}
	policy := &RequestTargetPolicy{
		IntendedTarget: target, Policy: "absolute_form_normalized", Fidelity: evidence.StateUnknown,
		Note: "native net/http emits origin-form directly, not the original absolute target; HTTP proxies require a destination-aware transport when Host differs and regenerate proxy-form; use a raw-capable sender for exact reproduction",
	}
	if u, err := url.Parse(lowercaseScheme(target)); err == nil {
		policy.DirectTarget = u.RequestURI()
	}
	return policy
}

type requestTargetPolicyKey struct{}

func withRequestTargetPolicy(ctx context.Context, raw []byte) context.Context {
	if policy := NativeRequestTargetPolicy(raw); policy != nil {
		return context.WithValue(ctx, requestTargetPolicyKey{}, *policy)
	}
	return ctx
}

// RequestTargetPolicyFromContext exposes the native builder's explicit target
// normalization. Returning a value keeps callers from changing shared metadata.
func RequestTargetPolicyFromContext(ctx context.Context) (RequestTargetPolicy, bool) {
	policy, ok := ctx.Value(requestTargetPolicyKey{}).(RequestTargetPolicy)
	return policy, ok
}
