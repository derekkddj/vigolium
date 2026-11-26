package oast

import (
	"context"
	"strings"
	"testing"
	"time"

	interactshclient "github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/vigolium/vigolium/pkg/database"
)

// TestPollSessions_UnreadablePrivateKeyClosesWithoutResuming: interactsh
// ignores a private key it cannot parse and resumes with a nil key, so the
// first callback it decrypts panics the whole process (the server's periodic
// poller took production down this way). A kept session whose key does not
// parse is therefore closed, never resumed.
func TestPollSessions_UnreadablePrivateKeyClosesWithoutResuming(t *testing.T) {
	var resumed int
	orig := resumeClient
	resumeClient = func(*options.SessionInfo) (*interactshclient.Client, error) {
		resumed++
		return nil, context.Canceled
	}
	t.Cleanup(func() { resumeClient = orig })

	repo := newOASTTestRepo(t)
	ctx := context.Background()
	// The shape the old store produced: NULs stripped, invalid bytes as U+FFFD.
	if err := repo.SaveOASTSession(ctx, &database.OASTSession{
		ProjectUUID: database.DefaultProjectUUID, ScanUUID: "scan-1", ServerURL: "https://oast.example",
		CorrelationID: "corr-bad", SecretKey: "SECRET", PrivateKey: "0�\x04�\x02\x01\x02�", PublicKey: "PUB",
	}); err != nil {
		t.Fatal(err)
	}
	sessions, err := repo.ListOpenOASTSessions(ctx, database.DefaultProjectUUID, "scan-1")
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions = %+v, %v", sessions, err)
	}

	res := PollSessions(ctx, repo, sessions, PollOptions{Wait: 10 * time.Millisecond})
	if resumed != 0 {
		t.Fatalf("resumed %d session(s) with an unreadable private key", resumed)
	}
	if len(res) != 1 || !res[0].Closed || !strings.Contains(res[0].Error, "private key") {
		t.Fatalf("poll result = %+v, want the session closed with a private-key error", res)
	}
	if open, _ := repo.ListOpenOASTSessions(ctx, database.DefaultProjectUUID, ""); len(open) != 0 {
		t.Fatalf("open sessions = %d, want 0", len(open))
	}
}
