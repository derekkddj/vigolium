package database

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"path/filepath"
	"testing"
)

// TestOASTSessions_PrivateKeyRoundTripsExactly: interactsh exports a session's
// private key as raw PKCS#1 DER bytes in a Go string (SessionInfo.PrivateKey),
// and resumes by parsing that string back as DER, ignoring a parse failure.
// The stored key must therefore come back byte for byte; a key that does not
// leaves the resumed client with a nil key, and the first callback it decrypts
// panics the whole process.
func TestOASTSessions_PrivateKeyRoundTripsExactly(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)

	// The production opener: its dialect is the one that rewrites strings.
	db, _ := newSchemaDB(t, writableConfig(filepath.Join(t.TempDir(), "oast.sqlite")))
	repo := NewRepository(db)
	ctx := context.Background()
	if err := repo.SaveOASTSession(ctx, &OASTSession{
		ProjectUUID: DefaultProjectUUID, ScanUUID: "s1", ServerURL: "https://oast.example",
		CorrelationID: "corr-der", SecretKey: "SECRET", PrivateKey: string(der), PublicKey: "PUB",
	}); err != nil {
		t.Fatal(err)
	}
	open, err := repo.ListOpenOASTSessions(ctx, DefaultProjectUUID, "s1")
	if err != nil || len(open) != 1 {
		t.Fatalf("open = %+v, %v", open, err)
	}
	if got := []byte(open[0].PrivateKey); !bytes.Equal(got, der) {
		t.Fatalf("stored private key changed: %d bytes in, %d bytes out", len(der), len(got))
	}
	if _, err := x509.ParsePKCS1PrivateKey([]byte(open[0].PrivateKey)); err != nil {
		t.Fatalf("stored private key no longer parses: %v", err)
	}
}
