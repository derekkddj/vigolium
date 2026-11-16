package httpmsg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"unicode/utf8"

	jsoniter "github.com/json-iterator/go"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestFromEvidenceExchangePreservesAuthoritativeBytes(t *testing.T) {
	request := append([]byte("POST /probe HTTP/1.1\r\nHost: vhost.example\r\nContent-Length: 1\r\n\r\n"), 0xff, 0, 'x', 'y')
	response := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"), 0xff, 0, 'a', 'b')
	x := evidence.NewExchange("http://destination.example:8080", "https://finding.example/elsewhere", request, response, evidence.ProvenanceCaptured)
	original := x.Clone()
	rr, err := FromEvidenceExchange(x)
	if err != nil {
		t.Fatal(err)
	}
	if svc := rr.Service(); svc.Host() != "destination.example" || svc.Port() != 8080 || svc.Protocol() != "http" {
		t.Fatalf("finding URL replaced destination: %#v", svc)
	}
	if rr.Request().Header("Host") != "vhost.example" || rr.Request().Header("Content-Length") != "1" || rr.Response().Header("Content-Length") != "1" {
		t.Fatal("captured headers changed")
	}
	if !bytes.Equal(rr.Request().Raw(), request) || !bytes.Equal(rr.Response().Raw(), response) {
		t.Fatal("declared Content-Length reconciled authoritative bytes")
	}
	if !bytes.Equal(rr.Request().Body(), []byte{0xff, 0, 'x', 'y'}) || !bytes.Equal(rr.Response().Body(), []byte{0xff, 0, 'a', 'b'}) {
		t.Fatal("parsing changed binary body")
	}
	if !reflect.DeepEqual(rr.Evidence(), original) {
		t.Fatal("factory changed receipt identity or metadata")
	}

	// Neither caller-owned bytes nor live message mutations can change the receipt.
	x.Request[0], x.Response[0] = 'X', 'Y'
	if !bytes.Equal(rr.Request().Raw(), original.Request) || !bytes.Equal(rr.Response().Raw(), original.Response) {
		t.Fatal("factory aliased caller buffers")
	}
	rr.Request().Raw()[0], rr.Response().Raw()[0] = 'A', 'B'
	selected := rr.Evidence()
	if !reflect.DeepEqual(selected, original) || selected.Validate() != nil {
		t.Fatal("live messages aliased the owned snapshot")
	}
	selected.Request[0], selected.Response[0] = 'C', 'D'
	if !reflect.DeepEqual(rr.Evidence(), original) {
		t.Fatal("Evidence returned a shared snapshot")
	}
}

func TestFromEvidenceExchangeServiceValidation(t *testing.T) {
	request := []byte("GET /probe HTTP/1.1\r\nHost: vhost.example\r\n\r\n")
	tests := []struct {
		name       string
		service    string
		url        string
		provenance evidence.Provenance
		host       string
		port       int
		protocol   string
	}{
		{"http default", "http://destination.example", "", evidence.ProvenanceCaptured, "destination.example", 80, "http"},
		{"https default", "https://destination.example", "", evidence.ProvenanceCaptured, "destination.example", 443, "https"},
		{"explicit port", "https://destination.example:8443", "", evidence.ProvenanceCaptured, "destination.example", 8443, "https"},
		{"IPv6", "http://[::1]:8080", "", evidence.ProvenanceCaptured, "::1", 8080, "http"},
		{"supplied URL fallback", "", "http://supplied.example:9000/probe", evidence.ProvenanceSupplied, "supplied.example", 9000, "http"},
		{"supplied service preferred", "https://destination.example:9443", "http://finding.example:8080/elsewhere", evidence.ProvenanceSupplied, "destination.example", 9443, "https"},
		{"captured no service", "", "http://finding.example/probe", evidence.ProvenanceCaptured, "", 0, ""},
		{"legacy no service", "", "http://finding.example/probe", evidence.ProvenanceLegacy, "", 0, ""},
		{"supplied no destination", "", "", evidence.ProvenanceSupplied, "", 0, ""},
		{"invalid service no fallback", "http://destination.example:bad", "http://finding.example/probe", evidence.ProvenanceSupplied, "", 0, ""},
		{"unsupported scheme", "ftp://destination.example:80", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"relative URL", "destination.example", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"missing host", "https:///probe", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"zero port", "https://destination.example:0", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"negative port", "https://destination.example:-1", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"out of range port", "https://destination.example:65536", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"empty explicit port", "https://destination.example:", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"userinfo", "https://user@destination.example:443", "", evidence.ProvenanceCaptured, "", 0, ""},
		{"unbracketed IPv6", "http://::1:8080", "", evidence.ProvenanceCaptured, "", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			x := evidence.NewExchange(tc.service, tc.url, request, nil, tc.provenance)
			rr, err := FromEvidenceExchange(x)
			if tc.host == "" {
				if err == nil {
					t.Fatal("invalid destination accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if svc := rr.Service(); svc.Host() != tc.host || svc.Port() != tc.port || svc.Protocol() != tc.protocol {
				t.Fatalf("wrong destination: %#v", svc)
			}
			if rr.HasResponse() || !reflect.DeepEqual(rr.Evidence(), x) {
				t.Fatal("missing response or evidence metadata changed")
			}
		})
	}
	if _, err := FromEvidenceExchange(nil); err == nil {
		t.Fatal("nil receipt accepted")
	}
	x := evidence.NewExchange("https://destination.example:443", "", request, nil, evidence.ProvenanceCaptured)
	x.Request[0] = 'X'
	if _, err := FromEvidenceExchange(x); err == nil {
		t.Fatal("changed receipt accepted")
	}
}

func TestHttpRequestResponseEvidenceBinaryJSONRoundTrip(t *testing.T) {
	request := append([]byte("POST /probe HTTP/1.1\r\nHost: destination.example\r\nContent-Length: 1\r\n\r\n"), 0xff, 0, 'x', 'y')
	response := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"), 0xff, 0, 0xfe, 'a', 'b')
	encoders := []struct {
		name string
		fn   func(*HttpRequestResponse) ([]byte, error)
	}{
		{"stdlib", func(rr *HttpRequestResponse) ([]byte, error) { return json.Marshal(rr) }},
		{"jsoniter", func(rr *HttpRequestResponse) ([]byte, error) { return jsoniter.Marshal(rr) }},
		{"MarshalJSON", func(rr *HttpRequestResponse) ([]byte, error) { return rr.MarshalJSON() }},
		{"MarshalBytes", func(rr *HttpRequestResponse) ([]byte, error) { return rr.MarshalBytes() }},
		{"MarshalString", func(rr *HttpRequestResponse) ([]byte, error) { s, err := rr.MarshalString(); return []byte(s), err }},
	}
	for _, provenance := range []evidence.Provenance{evidence.ProvenanceCaptured, evidence.ProvenanceSupplied, evidence.ProvenanceLegacy} {
		for _, state := range []evidence.State{evidence.StateComplete, evidence.StateTruncated, evidence.StateUnknown} {
			x := evidence.NewExchange("http://destination.example:8080", "https://finding.example/elsewhere", request, response, provenance)
			x.RequestState, x.ResponseState = state, state
			x.ContentHash = x.Hash()
			for _, encoder := range encoders {
				t.Run(string(provenance)+"/"+string(state)+"/"+encoder.name, func(t *testing.T) {
					rr, err := FromEvidenceExchange(x)
					if err != nil {
						t.Fatal(err)
					}
					// Analysis truncation must not overwrite the pre-analysis capture.
					rr.Request().TruncateBody(2)
					rr.Response().TruncateBody(2)
					encoded, err := encoder.fn(rr)
					if err != nil {
						t.Fatal(err)
					}
					if !json.Valid(encoded) || !utf8.Valid(encoded) || !bytes.Contains(encoded, []byte(`"raw_base64"`)) || !bytes.Contains(encoded, []byte(`"evidence"`)) {
						t.Fatal("JSON lacks valid binary/evidence fields")
					}
					var decoded HttpRequestResponse
					if err := json.Unmarshal(encoded, &decoded); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(decoded.Request().Raw(), rr.Request().Raw()) || !bytes.Equal(decoded.Response().Raw(), rr.Response().Raw()) {
						t.Fatal("binary live message changed during JSON round trip")
					}
					if decoded.Service().Host() != "destination.example" || decoded.Service().Port() != 8080 || decoded.Service().Protocol() != "http" {
						t.Fatal("round trip changed service")
					}
					if snapshot := decoded.Evidence(); !reflect.DeepEqual(snapshot, x) || snapshot.Validate() != nil {
						t.Fatalf("round trip changed receipt identity/provenance/states: %#v", snapshot)
					}
					clone := decoded.Clone()
					decoded.Request().Raw()[0], decoded.Response().Raw()[0] = 'X', 'Y'
					if !reflect.DeepEqual(clone.Evidence(), x) || !bytes.Equal(clone.Request().Raw(), rr.Request().Raw()) || !bytes.Equal(clone.Response().Raw(), rr.Response().Raw()) {
						t.Fatal("Clone shared live bytes or lost the evidence receipt")
					}
				})
			}
		}
	}
}

func TestHttpRequestResponseEvidenceJSONMissingResponse(t *testing.T) {
	x := evidence.NewExchange("https://destination.example:443", "https://finding.example/elsewhere", []byte("GET /probe HTTP/1.1\r\nHost: destination.example\r\n\r\n"), nil, evidence.ProvenanceSupplied)
	rr, err := FromEvidenceExchange(x)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := rr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded HttpRequestResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.HasResponse() || !reflect.DeepEqual(decoded.Evidence(), x) {
		t.Fatal("round trip invented a missing response or changed its capture state")
	}
}

func TestHttpRequestResponseEvidenceJSONMissingRequest(t *testing.T) {
	response := append([]byte("HTTP/1.1 200 OK\r\n\r\n"), 0xff, 0, 0xfe)
	x := evidence.NewExchange("http://destination.example:8080", "https://finding.example/elsewhere", nil, response, evidence.ProvenanceSupplied)
	rr, err := FromEvidenceExchange(x)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := rr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded HttpRequestResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Request().Raw()) != 0 || !bytes.Equal(decoded.Response().Raw(), response) || !reflect.DeepEqual(decoded.Evidence(), x) {
		t.Fatal("round trip invented a missing request or changed its receipt")
	}
	if svc := decoded.Service(); svc.Host() != "destination.example" || svc.Port() != 8080 || svc.Protocol() != "http" {
		t.Fatal("response-only round trip changed destination")
	}
}

func TestHttpRequestResponseJSONPreservesServiceForAbsoluteRequest(t *testing.T) {
	request := []byte("GET https://finding.example/probe HTTP/1.1\r\nHost: vhost.example\r\n\r\n")
	x := evidence.NewExchange("http://destination.example:8080", "https://finding.example/elsewhere", request, nil, evidence.ProvenanceCaptured)
	rr, err := FromEvidenceExchange(x)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := rr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded HttpRequestResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if svc := decoded.Service(); svc.Host() != "destination.example" || svc.Port() != 8080 || svc.Protocol() != "http" {
		t.Fatal("request-line URL replaced the original service")
	}
	if !bytes.Equal(decoded.Request().Raw(), request) || !reflect.DeepEqual(decoded.Evidence(), x) {
		t.Fatal("absolute-form request or evidence changed")
	}
}

func TestHttpRequestResponseJSONLegacyStringAndBinaryPrecedence(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: legacy.example\r\n\r\n")
	tests := []struct {
		name     string
		response map[string]any
		want     []byte
		wantErr  bool
	}{
		{"legacy string", map[string]any{"raw": "HTTP/1.1 200 OK\r\n\r\nlegacy\x00"}, []byte("HTTP/1.1 200 OK\r\n\r\nlegacy\x00"), false},
		{"binary wins", map[string]any{"raw": "lossy preview", "raw_base64": []byte{0xff, 0, 0xfe}}, []byte{0xff, 0, 0xfe}, false},
		{"empty binary wins", map[string]any{"raw": "stale preview", "raw_base64": []byte{}}, []byte{}, false},
		{"null binary wins", map[string]any{"raw": "stale preview", "raw_base64": nil}, nil, false},
		{"invalid binary no fallback", map[string]any{"raw": "preview", "raw_base64": "!not-base64!"}, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(map[string]any{"url": "http://legacy.example:8080/", "request": map[string]any{"raw": request}, "response": tc.response})
			if err != nil {
				t.Fatal(err)
			}
			// Exercise reuse: decoding a legacy payload must drop an old capture.
			x := evidence.NewExchange("http://old.example:80", "http://old.example/", request, []byte("HTTP/1.1 200 OK\r\n\r\nold"), evidence.ProvenanceCaptured)
			rr, err := FromEvidenceExchange(x)
			if err != nil {
				t.Fatal(err)
			}
			err = json.Unmarshal(encoded, rr)
			if tc.wantErr {
				if err == nil {
					t.Fatal("invalid binary fell back to a text preview")
				}
				if !reflect.DeepEqual(rr.Evidence(), x) || !bytes.Equal(rr.Response().Raw(), x.Response) {
					t.Fatal("failed decode partially replaced receiver")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rr.Response().Raw(), tc.want) || !bytes.Equal(rr.Request().Raw(), request) {
				t.Fatal("legacy/binary bytes decoded incorrectly")
			}
			if rr.Evidence() != nil {
				t.Fatal("legacy JSON claimed a captured receipt")
			}
			if svc := rr.Service(); svc.Host() != "legacy.example" || svc.Port() != 8080 || svc.Protocol() != "http" {
				t.Fatalf("legacy service changed: %#v", svc)
			}
		})
	}
}

func TestHttpRequestResponseJSONLegacyReuseClearsResponse(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: legacy.example\r\n\r\n")
	for _, response := range []json.RawMessage{nil, json.RawMessage("null")} {
		encoded, err := json.Marshal(struct {
			URL      string          `json:"url"`
			Request  map[string]any  `json:"request"`
			Response json.RawMessage `json:"response,omitempty"`
		}{"https://legacy.example/", map[string]any{"raw": request}, response})
		if err != nil {
			t.Fatal(err)
		}
		x := evidence.NewExchange("https://legacy.example:443", "https://legacy.example/", request, []byte("HTTP/1.1 200 OK\r\n\r\nold"), evidence.ProvenanceCaptured)
		rr, err := FromEvidenceExchange(x)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, rr); err != nil {
			t.Fatal(err)
		}
		if rr.HasResponse() || rr.Evidence() != nil {
			t.Fatal("decoding absent/null response retained an old response or receipt")
		}
	}
}

func TestHttpRequestResponseJSONRejectsInvalidEvidence(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: destination.example\r\n\r\n")
	x := evidence.NewExchange("https://destination.example:443", "https://destination.example/", request, []byte("HTTP/1.1 200 OK\r\n\r\n"), evidence.ProvenanceCaptured)
	mutations := []struct {
		name string
		fn   func(*evidence.Exchange)
	}{
		{"changed bytes", func(x *evidence.Exchange) { x.Response[0] = 'X' }},
		{"missing identity", func(x *evidence.Exchange) { x.ID = "" }},
		{"invalid state", func(x *evidence.Exchange) { x.ResponseState = "invalid"; x.ContentHash = x.Hash() }},
		{"missing with bytes", func(x *evidence.Exchange) { x.ResponseState = evidence.StateMissing; x.ContentHash = x.Hash() }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			invalid := x.Clone()
			mutation.fn(invalid)
			encoded, err := json.Marshal(map[string]any{"url": x.URL, "request": map[string]any{"raw": request}, "evidence": invalid})
			if err != nil {
				t.Fatal(err)
			}
			rr, err := FromEvidenceExchange(x)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, rr); err == nil {
				t.Fatal("invalid receipt accepted")
			}
			if !reflect.DeepEqual(rr.Evidence(), x) || !bytes.Equal(rr.Request().Raw(), request) {
				t.Fatal("invalid receipt partially replaced receiver")
			}
		})
	}
}
