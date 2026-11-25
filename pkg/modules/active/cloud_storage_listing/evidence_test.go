package cloud_storage_listing

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestListingEvidenceRetainsFullRedirectedResponse(t *testing.T) {
	listing := `<ListBucketResult><Contents><Key>secret.txt</Key></Contents>` +
		strings.Repeat("<!-- listing context -->", 150) +
		`<Contents><Key>tail-evidence.txt</Key></Contents></ListBucketResult>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/original" {
			http.Redirect(w, r, "/final-listing", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("X-Listing-Receipt", "full-response")
		_, _ = fmt.Fprint(w, listing)
	}))
	defer srv.Close()
	probe := s3ListingProbes[0]
	probe.path = "/original"
	result, err := New().tryProbe(modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), probe)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.BaselineEvidence)
	require.Equal(t, "selected", result.EvidenceStatus)
	require.Contains(t, result.Request, "GET /final-listing HTTP/")
	require.NotContains(t, result.Request, "GET /original HTTP/")
	require.True(t, strings.HasPrefix(result.Response, "HTTP/"), "body projections are not full HTTP responses")
	require.Contains(t, result.Response, "Content-Type: application/xml")
	require.Contains(t, result.Response, "X-Listing-Receipt: full-response")
	require.Contains(t, result.Response, listing, "the old 2000-byte report projection must not replace the receipt")
	require.Len(t, result.Evidence, 1)
	primary := result.Evidence[0]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
	require.Equal(t, evidence.StateComplete, primary.Exchange.ResponseState)
	require.Equal(t, srv.URL+"/final-listing", primary.Exchange.URL)
	require.Equal(t, result.Request, string(primary.Exchange.Request))
	require.Equal(t, result.Response, string(primary.Exchange.Response))
	require.NoError(t, primary.Exchange.Validate())
}
