package server

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRuntimeLogDirectPagesPreserveBytesBeyondTailAndInventoryLimits(t *testing.T) {
	h, repo, _ := newAgentTestHandlers(t)
	app := newAgentTestApp(h)
	dir := t.TempDir()
	// Sort before runtime.log so it falls outside the bounded inventory. The
	// web viewer must be able to address the known filename directly anyway.
	for i := 0; i < maxArtifactListEntries+1; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("earlier-%04d.txt", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := bytes.Repeat([]byte("synthetic argument ñ漢字 "), 10000)
	content := append([]byte("Tool call synthetic\nCommand (verbatim):\n"), command...)
	content = append(content, []byte("\nResult:\n")...)
	content = append(content, bytes.Repeat([]byte("synthetic multiline result\n"), 30000)...)
	content = append(content, []byte{0xff, 0, '\r', '\n'}...)
	content = append(content, []byte("LAST-BYTES-NOT-A-SUMMARY\n")...)
	if len(content) <= 512*1024 {
		t.Fatal("fixture must exceed the live tail limit")
	}
	if err := os.WriteFile(filepath.Join(dir, "runtime.log"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	run := seedAgentSession(t, repo, dir)
	base := "/api/agent/sessions/" + run + "/artifacts"
	resp, inventory, err := getRequest(app, base, nil)
	if err != nil || resp.StatusCode != http.StatusOK || bytes.Contains(inventory, []byte("runtime.log")) {
		t.Fatalf("fixture did not put runtime.log outside inventory: err=%v", err)
	}

	// Exact API intervals remain unmodified; the browser handles overlapping
	// UTF-8 text display separately. Raw bytes, even malformed UTF-8, survive.
	const pageBytes = 256 * 1024
	collected := make([]byte, 0, len(content))
	for offset := 0; offset < len(content); offset += pageBytes {
		path := base + "/runtime.log?max_bytes=" + strconv.Itoa(pageBytes) + "&offset=" + strconv.Itoa(offset)
		resp, body, err := getRequest(app, path, nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("runtime page failed: offset=%d err=%v", offset, err)
		}
		end := min(offset+pageBytes, len(content))
		if !bytes.Equal(body, content[offset:end]) || resp.Header.Get("X-Artifact-Offset") != strconv.Itoa(offset) || resp.Header.Get("X-Artifact-Total-Size") != strconv.Itoa(len(content)) || resp.Header.Get("X-Artifact-Returned-Bytes") != strconv.Itoa(end-offset) {
			t.Fatal("runtime page changed or summarized source bytes")
		}
		collected = append(collected, body...)
	}
	if !bytes.Equal(collected, content) {
		t.Fatal("runtime pagination dropped stored commands/results or binary bytes")
	}
	resp, body, err := getRequest(app, base+"/runtime.log?download=1&max_bytes=1", nil)
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(body, content) || resp.Header.Get("X-Artifact-Truncated") != "0" {
		t.Fatalf("runtime full download still bounded/summarized: err=%v", err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "runtime.log"))
	if err != nil || !bytes.Equal(stored, content) {
		t.Fatal("reading runtime.log mutated historical source bytes")
	}
}
