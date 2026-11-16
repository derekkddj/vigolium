package jsext

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/grafana/sobek"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

const maxInvocationReceipts = 128
const maxInvocationReceiptBytes = 32 << 20

// The symbol stores a Go object with no exported fields or methods. It cannot be
// replaced from JS, and there is no process-global VM map that could leak VMs.
var receiptRegistrySymbol = sobek.NewSymbol("vigolium invocation receipts")

type receiptRegistry struct {
	opts    APIOptions
	entries map[*sobek.Object]*evidence.Exchange
	context map[*sobek.Object]bool
	order   []*sobek.Object
	bytes   int
}

func receipts(vm *sobek.Runtime) *receiptRegistry {
	if v := vm.GlobalObject().GetSymbol(receiptRegistrySymbol); isSet(v) {
		if r, ok := v.Export().(*receiptRegistry); ok {
			return r
		}
	}
	r := &receiptRegistry{entries: make(map[*sobek.Object]*evidence.Exchange)}
	_ = vm.GlobalObject().DefineDataPropertySymbol(receiptRegistrySymbol, vm.ToValue(r), sobek.FLAG_FALSE, sobek.FLAG_FALSE, sobek.FLAG_FALSE)
	return r
}

func resetReceipts(vm *sobek.Runtime) {
	r := receipts(vm)
	r.entries = make(map[*sobek.Object]*evidence.Exchange)
	r.context = make(map[*sobek.Object]bool)
	r.order = nil
	r.bytes = 0
}

// registerExchange returns inspectable, base64-safe receipt data. Object identity
// is the capture handle: serializing/cloning/forging the displayed ID or bytes
// never creates a selectable receipt. Only this invocation's registry is trusted.
func registerExchange(vm *sobek.Runtime, x *evidence.Exchange) sobek.Value {
	if x == nil {
		return sobek.Undefined()
	}
	r := receipts(vm)
	obj := vm.NewObject()
	_ = obj.Set("id", x.ID)
	_ = obj.Set("url", x.URL)
	_ = obj.Set("service", x.Service)
	_ = obj.Set("request_base64", base64.StdEncoding.EncodeToString(x.Request))
	_ = obj.Set("response_base64", base64.StdEncoding.EncodeToString(x.Response))
	_ = obj.Set("request_state", string(x.RequestState))
	_ = obj.Set("response_state", string(x.ResponseState))
	_ = obj.Set("provenance", string(x.Provenance))
	_ = obj.Set("content_hash", x.ContentHash)
	_ = obj.Set("captured_at", x.CapturedAt.Format("2006-01-02T15:04:05.999999999Z07:00"))
	size := len(x.Request) + len(x.Response)
	if size > maxInvocationReceiptBytes {
		return obj
	}
	for len(r.order) >= maxInvocationReceipts || r.bytes+size > maxInvocationReceiptBytes {
		old := r.order[0]
		r.order = r.order[1:]
		prior := r.entries[old]
		r.bytes -= len(prior.Request) + len(prior.Response)
		delete(r.entries, old)
		delete(r.context, old)
	}
	r.entries[obj] = x.Clone()
	r.order = append(r.order, obj)
	r.bytes += size
	return obj
}

func registerContextExchange(vm *sobek.Runtime, x *evidence.Exchange) sobek.Value {
	v := registerExchange(vm, x)
	if obj, ok := v.(*sobek.Object); ok {
		r := receipts(vm)
		if r.context == nil {
			r.context = make(map[*sobek.Object]bool)
		}
		if r.entries[obj] != nil {
			r.context[obj] = true
		}
	}
	return v
}

func exchangeFromValue(vm *sobek.Runtime, v sobek.Value) *evidence.Exchange {
	obj, ok := v.(*sobek.Object)
	if !ok {
		return nil
	}
	return receipts(vm).entries[obj]
}

func attachResponseExchange(vm *sobek.Runtime, result sobek.Value, x *evidence.Exchange) {
	if x == nil || !isSet(result) {
		return
	}
	obj := result.ToObject(vm)
	_ = obj.Set("request", string(x.Request))
	_ = obj.Set("url", x.URL)
	_ = obj.Set("exchange", registerExchange(vm, x))
}

func parseSelectedEvidence(vm *sobek.Runtime, v sobek.Value, result *output.ResultEvent) {
	if !isSet(v) {
		return
	}
	items := []sobek.Value{v}
	if obj, ok := v.(*sobek.Object); ok {
		if n := obj.Get("length"); isSet(n) {
			items = nil
			for i := 0; i < int(n.ToInteger()) && i < 1024; i++ {
				items = append(items, obj.Get(fmt.Sprint(i)))
			}
		}
	}
	primarySelected := evidence.HasSelectedEvidence(result.Evidence)
	for _, item := range items {
		if !isSet(item) {
			continue
		}
		obj, object := item.(*sobek.Object)
		if !object || !isSet(obj.Get("exchange")) {
			result.AdditionalEvidence = append(result.AdditionalEvidence, jsEvidence(vm, item)...)
			continue
		}
		x := exchangeFromValue(vm, obj.Get("exchange"))
		role := evidence.RoleUnknown
		if v := obj.Get("role"); isSet(v) {
			role = evidence.Role(v.String())
		}
		invalid := ""
		if x == nil {
			invalid = "invalid, expired, or cross-invocation exchange handle"
		} else if !evidence.ValidRole(role) {
			invalid = "invalid evidence role"
		} else if x.Validate() != nil {
			invalid = "invalid captured exchange"
		}
		if handle, ok := obj.Get("exchange").(*sobek.Object); ok && receipts(vm).context[handle] && role != evidence.RoleBaseline && role != evidence.RoleObservation && role != evidence.RoleUnknown {
			invalid = "baseline context is not an invocation attack/control/confirmation"
		}
		if invalid == "" && receipts(vm).opts.ScopeMatcher != nil {
			u, err := url.Parse(x.URL)
			if err != nil || !receipts(vm).opts.ScopeMatcher.InScopeTarget(u.Hostname(), u.Path) {
				invalid = "exchange outside invocation scope"
			}
		}
		primary := false
		if p := obj.Get("primary"); isSet(p) {
			primary = p.ToBoolean()
		}
		if primary && role != evidence.RoleAttack && role != evidence.RoleObservation && role != evidence.RoleConfirmation {
			invalid = "primary evidence must be attack, observation, or confirmation"
		}
		if primary && primarySelected {
			invalid = "multiple primary evidence selections"
		}
		if invalid != "" {
			if result.Metadata == nil {
				result.Metadata = make(map[string]interface{})
			}
			result.Metadata["evidence_error"] = invalid
			continue
		}
		label := ""
		if v := obj.Get("label"); isSet(v) {
			label = v.String()
		}
		result.Evidence = append(result.Evidence, evidence.Select(x, role, primary, label))
		if primary {
			primarySelected = true
			// Compatibility fields are a rendering of the explicitly selected
			// receipt, not the pre-auth request constructed by the producer.
			result.Request, result.Response = string(x.Request), string(x.Response)
		}
	}
}
