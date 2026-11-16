package database

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestOverwriteRecordResponseBody verifies raw transformations are rejected
// without changing bytes, response hashes, metadata or timestamps.
func TestOverwriteRecordResponseBody(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	// Seed a JS record with a minified response body.
	minBody := `var a=1;var b=2;function f(x){return x*a+b}console.log(f(3),f(4),f(5));var q="/api/users";fetch(q);`
	rr, err := httpmsg.ParseRawRequest("GET /static/app.js HTTP/1.1\r\nHost: t.example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	origResp := httpmsg.NewHttpResponse([]byte(
		"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Encoding: gzip\r\n\r\n" + minBody))
	rr = rr.WithResponse(origResp)
	uuid, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}

	before, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID(before): %v", err)
	}

	// Overwrite with a beautified, multi-line body (Content-Encoding dropped).
	beaut := "var a = 1;\nvar b = 2;\n\nfunction f(x) {\n  return x * a + b;\n}\n\nconsole.log(f(3), f(4), f(5));\nvar q = \"/api/users\";\nfetch(q);\n"
	newResp := origResp.WithRemovedHeader("Content-Encoding").WithBody([]byte(beaut))
	newRaw := newResp.Raw()

	// A derived representation must not change the wire capture, even when
	// the record is not yet referenced by a finding.
	if err := repo.OverwriteRecordResponseBody(ctx, uuid, newRaw); !errors.Is(err, ErrImmutableRecordExchange) {
		t.Fatalf("OverwriteRecordResponseBody should reject transformation: %v", err)
	}

	after, err := repo.GetRecordByUUID(ctx, uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID(after): %v", err)
	}

	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected analysis transformation changed stored HTTP data")
	}
	if err := repo.OverwriteRecordResponseBody(ctx, uuid, before.RawResponse); err != nil {
		t.Fatalf("identical overwrite should be a no-op: %v", err)
	}
}

func TestOverwriteRecordResponseBody_Errors(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	if err := repo.OverwriteRecordResponseBody(ctx, "", []byte("x")); err == nil {
		t.Error("expected error for empty uuid")
	}
	if err := repo.OverwriteRecordResponseBody(ctx, "does-not-exist", []byte("HTTP/1.1 200 OK\r\n\r\nx")); err == nil {
		t.Error("expected error for unknown uuid")
	}
}
