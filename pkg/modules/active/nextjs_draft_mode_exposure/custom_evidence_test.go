package nextjs_draft_mode_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestCustomEvidenceKeepsAllFourDraftVerificationReceipts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/api/draft" {
			http.SetCookie(w, &http.Cookie{Name: "__prerender_bypass", Value: "live-preview", Path: "/"})
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if c, err := r.Cookie("__prerender_bypass"); err == nil && c.Value == "live-preview" {
			_, _ = w.Write([]byte("<html>UNPUBLISHED DRAFT " + strings.Repeat("draft ", 40) + "</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>PUBLIC ARTICLE " + strings.Repeat("public ", 40) + "</html>"))
	}))
	defer srv.Close()
	rr := modtest.Response(modtest.Request(t, srv.URL+"/"), "text/html", nextDataBody)
	results, err := New().ScanPerHost(rr, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.EqualValues(t, 5, hits.Load())
	f := results[0]
	assert.Equal(t, output.RecordKindFinding, f.RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, f.EvidenceGrade)
	assert.Equal(t, ModuleSeverity, f.Info.Severity)
	assert.Equal(t, ModuleConfidence, f.Info.Confidence)
	require.Len(t, f.Evidence, 5)
	anonymousRaw, err := httpmsg.RemoveHeader(verificationRequestRaw(rr, "/"), "Cookie")
	require.NoError(t, err)
	draftRaw, err := httpmsg.SetCookie(anonymousRaw, "__prerender_bypass", "live-preview")
	require.NoError(t, err)
	ids := map[string]bool{}
	for i, entry := range f.Evidence {
		assert.Equal(t, i == 0, entry.Primary)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.RequestState)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
		assert.NoError(t, entry.Exchange.Validate())
		assert.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Receipt-Seq: %d", i+1))
		assert.False(t, ids[entry.ExchangeID])
		ids[entry.ExchangeID] = true
		if i == 1 || i == 2 {
			assert.Equal(t, evidence.RoleControl, entry.Role)
			assert.Equal(t, anonymousRaw, entry.Exchange.Request, "receipt matches the verbatim sender input")
			assert.NotContains(t, string(entry.Exchange.Request), "__prerender_bypass=live-preview")
		} else if i >= 3 {
			assert.Equal(t, evidence.RoleConfirmation, entry.Role)
			assert.Equal(t, draftRaw, entry.Exchange.Request, "receipt matches the verbatim sender input")
			assert.Contains(t, string(entry.Exchange.Request), "__prerender_bypass=live-preview")
		}
	}
	assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
	assert.Contains(t, f.Request, "GET /api/draft ")
	assert.Contains(t, f.Response, "307 Temporary Redirect")
	assert.Contains(t, f.Response, "X-Receipt-Seq: 1")
	assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
	assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
}

func TestCustomEvidenceKeepsDraftVerificationReceiptsOnRejectedSample(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		w.Header().Set("X-Receipt-Seq", fmt.Sprint(n))
		if n == 2 {
			w.WriteHeader(http.StatusForbidden)
		}
		_, _ = w.Write([]byte("verification response"))
	}))
	defer srv.Close()
	rr := modtest.Request(t, srv.URL+"/")
	proof := modkit.NewEvidenceCollector()
	confirmed, legacy := verifyDraftContent(rr, modtest.Requester(t), "__prerender_bypass", "live-preview", "/", proof)
	assert.False(t, confirmed)
	assert.Len(t, legacy, 4, "preserve the existing first-anonymous/first-draft projections")
	assert.EqualValues(t, 4, hits.Load())
	require.Len(t, proof.Evidence(), 4)
	for i, entry := range proof.Evidence() {
		assert.False(t, entry.Primary)
		assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
		assert.Equal(t, evidence.StateComplete, entry.Exchange.RequestState)
		assert.NoError(t, entry.Exchange.Validate())
		assert.Contains(t, string(entry.Exchange.Response), fmt.Sprintf("X-Receipt-Seq: %d", i+1))
		if i < 2 {
			assert.Equal(t, evidence.RoleControl, entry.Role)
		} else {
			assert.Equal(t, evidence.RoleConfirmation, entry.Role)
		}
	}
	assert.Contains(t, string(proof.Evidence()[1].Exchange.Response), "403 Forbidden")
}
