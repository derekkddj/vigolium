package fsexport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// writeLinkedFiles writes the .req/.resp.headers/.resp.body trio ReadLinkedRecord
// reads back, mirroring what the traffic pass produced on disk.
func writeLinkedFiles(t *testing.T, root, relPath, req, head, body string) {
	t.Helper()
	dir := filepath.Join(root, filepath.Dir(relPath))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	base := filepath.Join(root, filepath.FromSlash(relPath))
	require.NoError(t, os.WriteFile(base+".req", []byte(req), 0o644))
	if head != "" {
		require.NoError(t, os.WriteFile(base+".resp.headers", []byte(head), 0o644))
	}
	if body != "" {
		require.NoError(t, os.WriteFile(base+".resp.body", []byte(body), 0o644))
	}
}

// TestReadLinkedRecord checks the @target strip, the response head/body load, and
// the inline body cap with its truncation flag.
func TestReadLinkedRecord(t *testing.T) {
	root := t.TempDir()
	bigBody := strings.Repeat("A", InlineBodyCap+512)
	writeLinkedFiles(t, root, "h.example/0001",
		"@target https://h.example\nGET /x HTTP/1.1\r\nHost: h.example\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
		bigBody)

	lr := ReadLinkedRecord(root, "h.example/0001", false)
	assert.Equal(t, "h.example/0001", lr.Path)
	assert.Equal(t, "GET /x HTTP/1.1\r\nHost: h.example\r\n\r\n", lr.Request, "@target marker must be stripped")
	assert.True(t, strings.HasPrefix(lr.ResponseHead, "HTTP/1.1 200 OK"))
	assert.Len(t, lr.ResponseBody, InlineBodyCap, "body must be capped to InlineBodyCap")
	assert.True(t, lr.BodyTruncated)

	// omitResponse loads only the request.
	lr2 := ReadLinkedRecord(root, "h.example/0001", true)
	assert.NotEmpty(t, lr2.Request)
	assert.Empty(t, lr2.ResponseHead)
	assert.Empty(t, lr2.ResponseBody)
}

// TestRenderFindingPrefersOwnEvidence verifies an active finding's own captured
// request/response win over the linked record for the inline section, while the
// linked record still drives the Traffic cross-links.
func TestRenderFindingPrefersOwnEvidence(t *testing.T) {
	f := &database.Finding{
		ModuleID:   "xss",
		ModuleName: "Reflected XSS",
		Severity:   "high",
		Confidence: "firm",
		Request:    "GET /q=PAYLOAD HTTP/1.1\r\nHost: t.example",
		Response:   "HTTP/1.1 200 OK\r\n\r\n<script>PAYLOAD</script>",
	}
	linked := []LinkedRecord{{
		Path:         "t.example/0007",
		Request:      "GET /stored HTTP/1.1\r\nHost: t.example",
		ResponseHead: "HTTP/1.1 200 OK\r\n\r\n",
		ResponseBody: "stored-body",
	}}
	md := string(RenderFindingMarkdown(f, linked, "out-traffic"))

	assert.Contains(t, md, "GET /q=PAYLOAD", "inline request must come from the finding's own evidence")
	assert.Contains(t, md, "<script>PAYLOAD</script>", "inline response must come from the finding's own evidence")
	assert.NotContains(t, md, "stored-body", "linked body must not duplicate or override the finding's own response")
	assert.NotContains(t, md, "GET /stored", "linked request must remain a link when own evidence is present")
	assert.Contains(t, md, "## Legacy inline request — role unknown (not proof)")
	assert.Contains(t, md, "## Legacy inline response — role unknown (not proof)")
	assert.NotContains(t, md, "### Linked request")
	assert.Contains(t, md, "../../out-traffic/t.example/0007.req", "Traffic links still point at the linked record")
}

// TestRenderFindingTruncationNote checks the capped-body note links out to the
// full .resp.body file.
func TestRenderFindingTruncationNote(t *testing.T) {
	f := &database.Finding{ModuleID: "idor", ModuleName: "IDOR", Severity: "info", Confidence: "tentative"}
	linked := []LinkedRecord{{
		Path:          "t.example/0020",
		Request:       "GET /19 HTTP/1.1\r\nHost: t.example",
		ResponseHead:  "HTTP/1.1 200 OK\r\n\r\n",
		ResponseBody:  "capped",
		BodyTruncated: true,
	}}
	md := string(RenderFindingMarkdown(f, linked, "out-traffic"))
	assert.Contains(t, md, "### Linked request — role unknown (not proof)")
	assert.NotContains(t, md, "\n## Request\n", "linked traffic must not fabricate a primary request")
	assert.Contains(t, md, "### Linked response — role unknown (not proof)")
	assert.NotContains(t, md, "\n## Response\n", "linked traffic must not fabricate a primary response")
	assert.Contains(t, md, "truncated to 32 KB")
	assert.Contains(t, md, "../../out-traffic/t.example/0020.resp.body")
}

func TestRenderFindingManifestAndPartialInlineNeverBorrowLinkedMessages(t *testing.T) {
	x := evidence.NewExchange("https://t.example:443", "https://t.example/proof", []byte("typed request"), []byte("typed response"), evidence.ProvenanceCaptured)
	linked := []LinkedRecord{{Path: "t.example/0001", Request: "LINKED-REQUEST-NOT-PROOF", ResponseHead: "HTTP/1.1 200 OK\r\n\r\n", ResponseBody: "LINKED-BODY-NOT-PROOF", BodyTruncated: true}}
	for name, f := range map[string]*database.Finding{
		"typed receipt":         {EvidenceStatus: "selected", Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "proof")}},
		"missing typed receipt": {EvidenceStatus: "missing", Evidence: []evidence.Entry{{ExchangeID: "missing", Role: evidence.RoleAttack, Primary: true}}},
		"request only inline":   {Request: "own request"},
		"response only inline":  {Response: "own response"},
	} {
		t.Run(name, func(t *testing.T) {
			md := string(RenderFindingMarkdown(f, linked, "out-traffic"))
			assert.Contains(t, md, "../../out-traffic/t.example/0001.req")
			assert.Contains(t, md, "../../out-traffic/t.example/0001.resp.body")
			assert.NotContains(t, md, "LINKED-REQUEST-NOT-PROOF")
			assert.NotContains(t, md, "LINKED-BODY-NOT-PROOF")
			assert.NotContains(t, md, "### Linked request")
			assert.NotContains(t, md, "### Linked response")
			assert.NotContains(t, md, "truncated to 32 KB", "no truncation claim when no linked preview is shown")
			if f.Request == "" {
				assert.NotContains(t, md, "## Legacy inline request")
			}
			if f.Response == "" {
				assert.NotContains(t, md, "## Legacy inline response")
			}
			if name == "missing typed receipt" {
				assert.Contains(t, md, "Selected bytes unavailable; no fallback substituted")
			}
			if name == "typed receipt" {
				assert.Contains(t, md, "role attack, primary true")
			}
		})
	}
}

func TestRenderFindingHTTPPreviewsFenceUntrustedMarkdown(t *testing.T) {
	request := "POST / HTTP/1.1\r\nHost: t.example\r\n\r\n```\n# request body, not a heading\n```"
	response := "HTTP/1.1 200 OK\r\n\r\n````\n# response body, not a heading\n````"
	for _, linkedOnly := range []bool{false, true} {
		f := &database.Finding{}
		var linked []LinkedRecord
		if linkedOnly {
			linked = []LinkedRecord{{Path: "t.example/0001", Request: request, ResponseBody: response}}
		} else {
			f.Request, f.Response = request, response
		}
		md := string(RenderFindingMarkdown(f, linked, "out-traffic"))
		assert.Contains(t, md, "\n````http\n"+request+"\n````\n", "request backticks must stay inside a longer fence")
		assert.Contains(t, md, "\n`````http\n"+response+"\n`````\n", "response backticks must stay inside a longer fence")
		assert.Contains(t, md, "role unknown (not proof)")
	}
}

// TestRenderFindingNoEvidence verifies a finding with neither own nor linked
// traffic renders without a Request/Response/Traffic section and doesn't panic.
func TestRenderFindingNoEvidence(t *testing.T) {
	f := &database.Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", Description: "desc"}
	md := string(RenderFindingMarkdown(f, nil, "out-traffic"))
	assert.Contains(t, md, "## Description")
	assert.NotContains(t, md, "## Legacy inline request")
	assert.NotContains(t, md, "## Legacy inline response")
	assert.NotContains(t, md, "### Linked request")
	assert.NotContains(t, md, "### Linked response")
	assert.NotContains(t, md, "## Traffic")
}
