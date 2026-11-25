package magento_misconfig

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestMagentoNestedSiblingGuardAppendsAfterBuilderPrimary(t *testing.T) {
	var sends atomic.Int64
	p := probes[0]
	probePath := "/shop/setup/"
	body := "Magento Web Setup Wizard Component Manager"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Send", fmt.Sprint(sends.Add(1)))
		w.Header().Set("X-Actual-Path", r.URL.Path)
		if r.URL.Path == probePath {
			_, _ = fmt.Fprint(w, body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "actual missing sibling")
	}))
	defer srv.Close()

	result := New().probeFile(modtest.Request(t, srv.URL+"/seed"), modtest.Requester(t), p, probePath, nil)
	require.NotNil(t, result)
	require.Equal(t, int64(2), sends.Load(), "one candidate and the existing sibling guard only")
	require.Len(t, result.Evidence, 2)
	require.LessOrEqual(t, len(result.Evidence)-1, modkit.MaxEvidencePairs)
	require.Len(t, result.AdditionalEvidence, 1)
	require.Equal(t, "Magento Misconfiguration: "+p.name, result.Info.Name)
	require.Equal(t, p.sev, result.Info.Severity)
	require.Equal(t, p.conf, result.Info.Confidence)

	primary, control := result.Evidence[0], result.Evidence[1]
	require.True(t, primary.Primary)
	require.Equal(t, evidence.RoleObservation, primary.Role)
	require.NoError(t, primary.Exchange.Validate())
	require.Equal(t, string(primary.Exchange.Request), result.Request)
	require.Equal(t, string(primary.Exchange.Response), result.Response)
	require.Contains(t, result.Request, "GET "+probePath+" HTTP/")
	require.Contains(t, result.Response, "X-Send: 1")
	require.True(t, strings.HasSuffix(result.Response, body))
	require.False(t, control.Primary)
	require.Equal(t, evidence.RoleControl, control.Role)
	require.NotEqual(t, primary.ExchangeID, control.ExchangeID)
	require.NoError(t, control.Exchange.Validate())
	require.Contains(t, string(control.Exchange.Request), "GET /shop/")
	require.NotContains(t, string(control.Exchange.Request), "GET "+probePath+" HTTP/")
	require.Contains(t, string(control.Exchange.Response), "X-Send: 2")
	require.Contains(t, string(control.Exchange.Response), "X-Actual-Path: /shop/")
	require.True(t, strings.HasSuffix(string(control.Exchange.Response), "actual missing sibling"))
}
