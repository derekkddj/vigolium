package xml_saml_security

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestSignatureBypassSelectsMutationAndActualControls(t *testing.T) {
	for _, suppliedBaseline := range []bool{false, true} {
		t.Run(fmt.Sprint(suppliedBaseline), func(t *testing.T) {
			const accepted = "Welcome, authenticated user dashboard"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Receipt", "saml")
				if strings.Contains(samlDecode(r.URL.Query().Get("SAMLResponse")), "vigolium-bogus") {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, "rejected assertion")
					return
				}
				_, _ = fmt.Fprint(w, accepted)
			}))
			defer srv.Close()
			value := base64.StdEncoding.EncodeToString([]byte(signedSAML))
			ctx := modtest.Request(t, srv.URL+"/acs?SAMLResponse="+url.QueryEscape(value))
			if suppliedBaseline {
				ctx = modtest.Response(ctx, "text/plain", accepted)
			}
			ip := modtest.InsertionPoint(t, ctx, "SAMLResponse")
			results, err := New().ScanPerInsertionPoint(ctx, ip, modtest.Requester(t), &modkit.ScanContext{})
			require.NoError(t, err)
			require.Len(t, results, 1)
			result := results[0]
			require.False(t, result.BaselineEvidence)
			require.Len(t, result.Evidence, 5)
			require.Equal(t, evidence.RoleAttack, result.Evidence[0].Role)
			require.Contains(t, result.Response, "X-Receipt: saml")
			require.NotEqual(t, string(ctx.Request().Raw()), result.Request)
			require.Equal(t, evidence.RoleBaseline, result.Evidence[1].Role)
			wantProvenance := evidence.ProvenanceCaptured
			if suppliedBaseline {
				wantProvenance = evidence.ProvenanceSupplied
			}
			require.Equal(t, wantProvenance, result.Evidence[1].Exchange.Provenance)
			for i, role := range []evidence.Role{evidence.RoleControl, evidence.RoleConfirmation, evidence.RoleControl} {
				entry := result.Evidence[i+2]
				require.False(t, entry.Primary)
				require.Equal(t, role, entry.Role)
				require.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
				require.NoError(t, entry.Exchange.Validate())
				require.NotEqual(t, result.Evidence[0].ExchangeID, entry.ExchangeID)
			}
		})
	}
}
