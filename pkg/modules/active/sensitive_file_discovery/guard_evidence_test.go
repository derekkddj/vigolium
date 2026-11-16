package sensitive_file_discovery

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

func TestFileGuardsKeepReplayAndCachedDecoyWithoutReplacingPrimary(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Receipt", fmt.Sprint(hits.Add(1)))
		if r.URL.Path == "/config/one.txt" || r.URL.Path == "/config/two.txt" {
			_, _ = fmt.Fprint(w, "SECRET_KEY=actual-file-content")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "decoy not found")
	}))
	defer srv.Close()
	ctx, client, sc := modtest.Request(t, srv.URL+"/input"), modtest.Requester(t), &modkit.ScanContext{}
	m := New()
	var decoyID string
	for i, path := range []string{"/config/one.txt", "/config/two.txt"} {
		sf := sensitiveFile{path: path, name: "receipt", markers: []string{"SECRET_KEY"}}
		r := m.probeFile(ctx, client, sc, sf, path, nil)
		require.NotNil(t, r)
		require.Len(t, r.Evidence, 3)
		primary, replay, decoy := r.Evidence[0], r.Evidence[1], r.Evidence[2]
		require.True(t, primary.Primary)
		require.Equal(t, evidence.RoleObservation, primary.Role)
		require.Equal(t, string(primary.Exchange.Request), r.Request)
		require.Equal(t, string(primary.Exchange.Response), r.Response)
		require.Contains(t, r.Request, "GET "+path+" HTTP/1.1")
		require.Equal(t, evidence.RoleConfirmation, replay.Role)
		require.Contains(t, string(replay.Exchange.Request), "GET "+path+" HTTP/1.1")
		require.NotEqual(t, primary.ExchangeID, replay.ExchangeID)
		require.Equal(t, evidence.RoleControl, decoy.Role)
		require.Contains(t, string(decoy.Exchange.Response), "X-Receipt: 3")
		if i == 0 {
			decoyID = decoy.ExchangeID
			require.Equal(t, int32(3), hits.Load())
		} else {
			require.Equal(t, decoyID, decoy.ExchangeID, "cached decoy is the original execution, not a recapture")
			require.Equal(t, int32(5), hits.Load(), "cached decoy adds no send")
			require.Contains(t, r.Response, "X-Receipt: 4")
			require.Contains(t, string(replay.Exchange.Response), "X-Receipt: 5")
		}
	}
}
