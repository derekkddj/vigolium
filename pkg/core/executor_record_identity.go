package core

import (
	"bytes"
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

func (e *Executor) evidenceProjectUUID() string {
	if e.projectUUID == "" {
		return database.DefaultProjectUUID
	}
	return e.projectUUID
}

func (e *Executor) recordMatchesResult(record *database.HTTPRecord, result *output.ResultEvent) bool {
	if record == nil || record.ProjectUUID != e.evidenceProjectUUID() || !bytes.Equal(record.RawRequest, []byte(result.Request)) || !bytes.Equal(record.RawResponse, []byte(result.Response)) {
		return false
	}
	rr, err := resultEvidenceMessages(result, nil)
	if err != nil {
		return false
	}
	return recordMatchesService(record, rr) && recordMatchesCaptureFidelity(record, rr)
}

// resultEvidenceMessages wraps selected receipt bytes directly. Legacy pairs
// retain supplied provenance and use their declared URL only as service fallback.
func resultEvidenceMessages(result *output.ResultEvent, measured *httpmsg.HttpResponse) (*httpmsg.HttpRequestResponse, error) {
	var selected *evidence.Exchange
	typedPrimaryCount := 0
	for _, entry := range result.Evidence {
		if !entry.Primary || !proofRole(entry.Role) {
			continue
		}
		typedPrimaryCount++
		if entry.Exchange != nil && entry.ExchangeID == entry.Exchange.ID && entry.Exchange.Validate() == nil && bytes.Equal(entry.Exchange.Request, []byte(result.Request)) && bytes.Equal(entry.Exchange.Response, []byte(result.Response)) {
			selected = entry.Exchange
		}
	}
	if typedPrimaryCount > 0 {
		if typedPrimaryCount != 1 || selected == nil {
			return nil, fmt.Errorf("selected evidence is ambiguous, unavailable or inconsistent")
		}
		return completeEvidenceRecordMessages(selected, result.Response, measured)
	}
	for _, entry := range result.Evidence {
		if entry.Primary && entry.Role == evidence.RoleUnknown && entry.Exchange != nil && entry.ExchangeID == entry.Exchange.ID && entry.Exchange.Validate() == nil && bytes.Equal(entry.Exchange.Request, []byte(result.Request)) && bytes.Equal(entry.Exchange.Response, []byte(result.Response)) {
			x := entry.Exchange
			if x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete {
				return nil, fmt.Errorf("incomplete evidence cannot be represented as an HTTP record")
			}
			if x.Service == "" && x.URL == "" && x.Provenance == evidence.ProvenanceSupplied && entry.Role == evidence.RoleUnknown {
				// Legacy collectors supply bytes without destination metadata. This
				// temporary compatibility view does not rewrite their stored receipt.
				x = evidence.NewExchange(legacyEvidenceService(string(x.Request), result.URL), result.URL, x.Request, x.Response, evidence.ProvenanceSupplied)
			}
			return completeEvidenceRecordMessages(x, result.Response, measured)
		}
	}
	x := evidence.NewExchange(legacyEvidenceService(result.Request, result.URL), result.URL, []byte(result.Request), []byte(result.Response), evidence.ProvenanceSupplied)
	return completeEvidenceRecordMessages(x, result.Response, measured)
}

// Only complete selected finding receipts get a compatibility traffic row.
// Partial/unknown proof remains canonical evidence, independently of the saved
// fidelity metadata now available on ordinary traffic rows.
func completeEvidenceRecordMessages(x *evidence.Exchange, response string, measured *httpmsg.HttpResponse) (*httpmsg.HttpRequestResponse, error) {
	if x.RequestState != evidence.StateComplete || x.ResponseState != evidence.StateComplete {
		return nil, fmt.Errorf("incomplete evidence cannot be represented as an HTTP record")
	}
	rr, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		return nil, err
	}
	return rr.WithResponse(findingResponse(response, measured)).WithEvidence(x), nil
}

// Legacy bytes have no captured destination; derive only their compatibility
// service metadata. Never use the parser's reconciled bytes as evidence.
func legacyEvidenceService(raw, target string) string {
	var rr *httpmsg.HttpRequestResponse
	var err error
	if target == "" {
		rr, err = httpmsg.ParseRawRequest(raw)
	} else {
		rr, err = httpmsg.ParseRawRequestWithURL(raw, target)
	}
	if err != nil {
		return ""
	}
	return evidenceService(rr)
}

func recordMatchesService(record *database.HTTPRecord, rr *httpmsg.HttpRequestResponse) bool {
	if rr == nil || rr.Service() == nil {
		return false
	}
	svc := rr.Service()
	return record.Hostname == svc.Host() && record.Port == svc.Port() && record.Scheme == svc.Protocol()
}

func sameInputRequest(a, b *httpmsg.HttpRequestResponse) bool {
	if a == nil || b == nil || a.Request() == nil || b.Request() == nil || a.Service() == nil || b.Service() == nil {
		return false
	}
	return evidenceService(a) == evidenceService(b) && bytes.Equal(a.Request().Raw(), b.Request().Raw())
}

func (e *Executor) recordMatchesInput(record *database.HTTPRecord, rr *httpmsg.HttpRequestResponse) bool {
	if snapshot := rr.Evidence(); snapshot != nil {
		if original, err := httpmsg.FromEvidenceExchange(snapshot); err == nil {
			rr = original
		}
	}
	if record == nil || rr == nil || rr.Request() == nil || record.ProjectUUID != e.evidenceProjectUUID() || !recordMatchesService(record, rr) || !bytes.Equal(record.RawRequest, rr.Request().Raw()) {
		return false
	}
	var response []byte
	if rr.HasResponse() {
		response = rr.Response().Raw()
	}
	return bytes.Equal(record.RawResponse, response) && recordMatchesCaptureFidelity(record, rr)
}

// Cached input/finding links must honor the same fidelity boundary as the record
// writer. Identical bytes cannot authorize reusing a different known state pair.
// Preserve complete legacy compatibility, but never erase known partial fidelity
// by reusing a row whose fidelity was not recorded.
func recordMatchesCaptureFidelity(record *database.HTTPRecord, rr *httpmsg.HttpRequestResponse) bool {
	x := rr.Evidence()
	if x != nil && x.Validate() != nil {
		return false
	}
	if record.CaptureRequestState == "" && record.CaptureResponseState == "" {
		return x == nil || x.RequestState == evidence.StateComplete && x.ResponseState == evidence.StateComplete
	}
	if x == nil {
		return false
	}
	request, response, err := record.EffectiveCaptureStates()
	return err == nil && request == x.RequestState && response == x.ResponseState
}
