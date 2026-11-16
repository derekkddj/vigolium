package powerpages_dataverse_exposure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestPowerPagesSelectsUsedVerdictReceipt(t *testing.T) {
	for _, mode := range []string{"sample", "fallback", "column-restricted"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Operation", fmt.Sprint(calls.Add(1)))
				if mode == "column-restricted" {
					w.WriteHeader(403)
					_, _ = fmt.Fprint(w, `{"error":{"code":"90040101","message":"AttributePermissionIsMissing"}}`)
					return
				}
				if mode == "fallback" && r.URL.Query().Get("$top") == "20" {
					w.WriteHeader(404)
					return
				}
				_, _ = fmt.Fprint(w, `{"@odata.context":"test/$metadata#accounts","@odata.count":3,"value":[{"name":"own record"}]}`)
			}))
			defer srv.Close()
			r := New().probeAndConfirm(modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), seedTables[0], srv.URL, "test")
			require.NotNil(t, r)
			require.NotEmpty(t, r.Evidence)
			primary := r.Evidence[0]
			assert.True(t, primary.Primary)
			assert.Equal(t, evidence.RoleObservation, primary.Role)
			require.NotNil(t, primary.Exchange)
			assert.Equal(t, evidence.ProvenanceCaptured, primary.Exchange.Provenance)
			assert.Equal(t, string(primary.Exchange.Request), r.Request)
			assert.Equal(t, string(primary.Exchange.Response), r.Response)
			assert.False(t, r.BaselineEvidence)
			switch mode {
			case "sample":
				assert.Contains(t, r.Response, "X-Operation: 4")
				assert.Contains(t, r.Request, "$top=20")
				assert.Equal(t, int64(4), calls.Load())
			case "fallback":
				assert.Contains(t, r.Response, "X-Operation: 1")
				assert.NotContains(t, r.Request, "$top=20")
				assert.Equal(t, int64(4), calls.Load())
			case "column-restricted":
				assert.Contains(t, r.Response, "403")
				assert.Contains(t, r.Response, "90040101")
				assert.Equal(t, int64(1), calls.Load())
			}
			for _, entry := range r.Evidence[1:] {
				assert.NotEqual(t, primary.ExchangeID, entry.ExchangeID)
			}
		})
	}
}
