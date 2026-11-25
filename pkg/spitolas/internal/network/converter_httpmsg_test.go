package network

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func browserReceipt(t *testing.T, rr *httpmsg.HttpRequestResponse) *evidence.Exchange {
	t.Helper()
	x := rr.Evidence()
	if x == nil {
		t.Fatal("browser conversion lost its receipt")
	}
	if err := x.Validate(); err != nil {
		t.Fatalf("invalid browser receipt: %v", err)
	}
	if x.Provenance != evidence.ProvenanceSupplied || x.RequestState != evidence.StateUnknown {
		t.Fatalf("normalized browser request fidelity = %s/%s", x.Provenance, x.RequestState)
	}
	if !bytes.Equal(x.Request, rr.Request().Raw()) {
		t.Fatal("receipt changed the constructed request")
	}
	if rr.HasResponse() {
		if x.ResponseState != evidence.StateUnknown || !bytes.Equal(x.Response, rr.Response().Raw()) {
			t.Fatal("receipt changed the constructed response or upgraded its fidelity")
		}
	} else if x.ResponseState != evidence.StateMissing || len(x.Response) != 0 {
		t.Fatal("receipt manufactured a missing response")
	}
	return x
}

func TestToHttpRequestResponseNormalizedReceipt(t *testing.T) {
	entry := createTestEntry("https://example.com:8443/path%2Fpart?q=%2f")
	entry.Request.Method = "POST"
	entry.Request.Headers = map[string]string{"host": "renderer.invalid", "Content-Length": "1"}
	entry.Request.Body = []byte("decoded request")
	entry.Response.Status = 299 // Preserve the converter's existing unknown reason phrase.
	entry.Response.Headers = map[string]string{"Content-Encoding": "gzip", "Content-Length": "5"}
	entry.Response.Body = []byte(strings.Repeat("decoded browser body\n", 4096))
	entry.BodySource = BodySourceCDP
	entry.DurationMs = 123

	rr, err := ToHttpRequestResponse(entry)
	if err != nil {
		t.Fatal(err)
	}
	x := browserReceipt(t, rr)
	if x.Service != "https://example.com:8443" || x.URL != entry.Request.URL {
		t.Fatalf("receipt changed the service or URL: %q / %q", x.Service, x.URL)
	}
	if !strings.HasPrefix(string(x.Request), "POST /path%2Fpart?q=%2f HTTP/1.1\r\nHost: example.com:8443\r\n") {
		t.Fatal("request construction behavior changed")
	}
	if rr.Request().Header("Content-Length") != "1" || !bytes.Equal(rr.Request().Body(), entry.Request.Body) {
		t.Fatal("request body or inconsistent supplied length was repaired")
	}
	if !strings.HasPrefix(string(x.Response), "HTTP/1.1 299 Unknown\r\n") ||
		rr.Response().Header("Content-Encoding") != "gzip" || rr.Response().Header("Content-Length") != "5" ||
		!bytes.Equal(rr.Response().Body(), entry.Response.Body) {
		t.Fatal("normalized headers, status or full decoded body changed")
	}
	if rr.Response().Duration() != 123*time.Millisecond {
		t.Fatal("receipt attachment lost response timing")
	}

	// The receipt is owned independently of the live messages and each conversion
	// has a fresh identity, not the crawler's endpoint/content dedup hash.
	another, err := ToHttpRequestResponse(entry)
	if err != nil {
		t.Fatal(err)
	}
	if browserReceipt(t, another).ID == x.ID {
		t.Fatal("separate browser conversions reused an exchange identity")
	}
	rr.Request().Raw()[0] = 'X'
	rr.Response().Raw()[0] = 'X'
	if rr.Evidence().ContentHash != x.ContentHash || rr.Evidence().Validate() != nil {
		t.Fatal("live message mutation corrupted the retained receipt")
	}
}

func TestToHttpRequestResponseAbsentAndOmittedResponse(t *testing.T) {
	for _, bodySource := range []string{"absent", BodySourceCDP, BodySourceOmittedPolicy, BodySourceTooLarge, BodySourceFailed} {
		t.Run(bodySource, func(t *testing.T) {
			entry := createTestEntry("http://example.com/response")
			entry.BodySource = bodySource
			entry.Response.Headers = nil
			if bodySource == "absent" {
				entry.Response = nil
				entry.Error = "net::ERR_CERT_AUTHORITY_INVALID"
			}
			rr, err := ToHttpRequestResponse(entry)
			if err != nil {
				t.Fatal(err)
			}
			x := browserReceipt(t, rr)
			if x.Service != "http://example.com:80" {
				t.Fatalf("service = %q", x.Service)
			}
			if bodySource != "absent" && string(x.Response) != "HTTP/1.1 200 OK\r\n\r\n" {
				t.Fatal("empty/omitted body or headers were synthesized")
			}
		})
	}
}

func TestToHttpRequestResponseRequestIDAndRedirectCorrelation(t *testing.T) {
	mock := &mockWriter{}
	c := newRedirectTestCapture(mock)
	c.includeResponseHeaders = true
	const (
		first  = "https://example.com/first"
		last   = "https://example.com/last"
		other  = "https://example.com/other"
		failed = "https://example.com/failed"
	)
	c.onRequestWillBeSent(rwbs("redirect", "POST", first, nil, nil), "s")
	c.onRequestWillBeSent(rwbs("other", "GET", other, nil, nil), "s")
	c.onRequestWillBeSent(rwbs("failed", "GET", failed, nil, nil), "s")
	// A matching URL is not correlation: no request with this ID was observed.
	c.onResponseReceived(&proto.NetworkResponseReceived{RequestID: "unseen", Response: &proto.NetworkResponse{URL: failed, Status: 200}}, "s")
	c.onRequestWillBeSent(rwbs("redirect", "GET", last, nil,
		&proto.NetworkResponse{URL: first, Status: 302, Headers: wireHeaders("Location", last)}), "s")
	c.onResponseReceived(&proto.NetworkResponseReceived{RequestID: "other", Response: &proto.NetworkResponse{URL: other, Status: 201}}, "s")
	c.onResponseReceived(&proto.NetworkResponseReceived{RequestID: "redirect", Response: &proto.NetworkResponse{URL: last, Status: 200}}, "s")
	c.onLoadingFinished(finished("redirect"), "s")
	c.onLoadingFinished(finished("other"), "s")
	c.onLoadingFailed(&proto.NetworkLoadingFailed{RequestID: "failed", ErrorText: "net::ERR_CERT_AUTHORITY_INVALID"})

	if mock.getWriteCount() != 4 {
		t.Fatalf("written entries = %d, want four actual requests", mock.getWriteCount())
	}
	ids := make(map[string]bool)
	for _, want := range []struct {
		url    string
		method string
		status int
	}{{first, "POST", 302}, {last, "GET", 200}, {other, "GET", 201}, {failed, "GET", 0}} {
		rr, err := ToHttpRequestResponse(mock.entryFor(t, want.url))
		if err != nil {
			t.Fatal(err)
		}
		x := browserReceipt(t, rr)
		if ids[x.ID] {
			t.Fatal("redirect hops shared a receipt identity")
		}
		ids[x.ID] = true
		if x.URL != want.url || rr.Request().Method() != want.method {
			t.Fatalf("request changed for %s", want.url)
		}
		if want.status == 0 {
			if rr.HasResponse() {
				t.Fatal("unmatched response or TLS error became a fictitious HTTP response")
			}
		} else if !rr.HasResponse() || rr.Response().StatusCode() != want.status {
			t.Fatalf("response belongs to a different request/hop: %s", want.url)
		}
		if want.url == first && rr.Response().Header("Location") != last {
			t.Fatal("redirect response no longer belongs to the preceding hop")
		}
	}
}
