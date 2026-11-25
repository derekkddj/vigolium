package mass_assignment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestCustomEvidenceKeepsBenignReinjectionAndBothReadbacks(t *testing.T) {
	for _, rejectSecond := range []bool{false, true} {
		t.Run(fmt.Sprintf("reject-second=%t", rejectSecond), func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := hits.Add(1)
				w.Header().Set("X-Receipt-Seq", fmt.Sprint(n))
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					if rejectSecond && n == 6 {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"error":"readback denied"}`))
						return
					}
					_, _ = w.Write([]byte(`{"username":"bob","role":"admin"}`))
					return
				}
				in := decodeBody(r)
				delete(in, canaryKey)
				w.Header().Set("Location", "/record")
				_ = json.NewEncoder(w).Encode(in)
			}))
			defer srv.Close()
			rr := jsonPost(t, srv.URL+"/record", `{"username":"bob"}`, `{"username":"bob"}`)
			results, err := New().ScanPerRequest(rr, modtest.Requester(t), &modkit.ScanContext{})
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.EqualValues(t, 6, hits.Load())
			f := results[0]
			if rejectSecond {
				assert.Equal(t, output.RecordKindCandidate, f.RecordKind)
				assert.Equal(t, output.EvidenceGradeDifferential, f.EvidenceGrade)
			} else {
				assert.Equal(t, output.RecordKindFinding, f.RecordKind)
				assert.Equal(t, output.EvidenceGradeImpact, f.EvidenceGrade)
			}
			assert.Equal(t, ModuleSeverity, f.Info.Severity)
			assert.Equal(t, ModuleConfidence, f.Info.Confidence)
			require.Len(t, f.Evidence, 6)
			assert.True(t, f.Evidence[0].Primary)
			assert.Equal(t, evidence.RoleAttack, f.Evidence[0].Role)
			assert.Contains(t, f.Response, "X-Receipt-Seq: 3")
			assert.Equal(t, string(f.Evidence[0].Exchange.Request), f.Request)
			assert.Equal(t, string(f.Evidence[0].Exchange.Response), f.Response)
			seen := map[int]bool{}
			ids := map[string]bool{}
			for _, entry := range f.Evidence {
				assert.Equal(t, evidence.ProvenanceCaptured, entry.Exchange.Provenance)
				assert.Equal(t, evidence.StateComplete, entry.Exchange.ResponseState)
				assert.False(t, ids[entry.ExchangeID])
				ids[entry.ExchangeID] = true
				for n := 1; n <= 6; n++ {
					if !stringsContainsReceipt(entry.Exchange.Response, n) {
						continue
					}
					seen[n] = true
					if n == 1 || n == 2 {
						assert.Equal(t, evidence.RoleControl, entry.Role)
					} else if n >= 4 {
						assert.Equal(t, evidence.RoleConfirmation, entry.Role)
					}
					if n == 6 && rejectSecond {
						assert.Contains(t, string(entry.Exchange.Response), "403 Forbidden")
					}
				}
			}
			assert.Len(t, seen, 6)
		})
	}
}

func stringsContainsReceipt(response []byte, seq int) bool {
	return strings.Contains(string(response), fmt.Sprintf("X-Receipt-Seq: %d\r\n", seq))
}
