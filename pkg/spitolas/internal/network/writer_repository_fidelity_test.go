package network

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestRepositoryWriterRetainsBrowserReceiptAndBinaryBodies(t *testing.T) {
	requestBody := []byte{0, 0xff, 0xfe, '\r', '\n', 0x80}
	responseBody := []byte{0xff, 0, 0x80, 0xfe, '\r', '\n'}
	decodedBody, err := decodeResponseBody(&proto.NetworkGetResponseBodyResult{
		Base64Encoded: true,
		Body:          base64.StdEncoding.EncodeToString(responseBody),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, missing := range []bool{false, true} {
		name := "binary response"
		if missing {
			name = "missing response"
		}
		t.Run(name, func(t *testing.T) {
			saver := &fakeRecordSaver{}
			w := NewRepositoryWriter(saver, "spidering", "project")
			t.Cleanup(func() { _ = w.Close() })
			entry := createTestEntry("https://example.com:8443/upload")
			entry.Request.Method = "POST"
			entry.Request.Body = bytes.Clone(requestBody)
			entry.Response.Headers = map[string]string{"Content-Type": "application/octet-stream"}
			entry.Response.Body = bytes.Clone(decodedBody)
			entry.BodySource = BodySourceCDP
			if missing {
				entry.Response = nil
			}
			if err := w.Write(entry); err != nil {
				t.Fatal(err)
			}
			// Conversion happens before admission; later changes to the browser
			// entry must not alter either the queued messages or their receipt.
			entry.Request.Body[0] = 'X'
			if entry.Response != nil {
				entry.Response.Body[0] = 'X'
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			saver.mu.Lock()
			records := append([]*httpmsg.HttpRequestResponse(nil), saver.records...)
			saver.mu.Unlock()
			if len(records) != 1 {
				t.Fatalf("saved %d records, want one", len(records))
			}
			rr := records[0]
			x := browserReceipt(t, rr)
			if !bytes.Equal(rr.Request().Body(), requestBody) || !bytes.HasSuffix(x.Request, requestBody) {
				t.Fatal("writer lost binary request bytes")
			}
			if !missing && (!bytes.Equal(rr.Response().Body(), responseBody) || !bytes.HasSuffix(x.Response, responseBody)) {
				t.Fatal("writer lost CDP-decoded binary response bytes")
			}
			encoded, err := json.Marshal(rr)
			if err != nil {
				t.Fatal(err)
			}
			var restored httpmsg.HttpRequestResponse
			if err := json.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			for _, retained := range []*httpmsg.HttpRequestResponse{rr.Clone(), &restored} {
				if !reflect.DeepEqual(browserReceipt(t, retained), x) {
					t.Fatal("retention changed receipt identity, binary bytes or fidelity states")
				}
			}
		})
	}
}
