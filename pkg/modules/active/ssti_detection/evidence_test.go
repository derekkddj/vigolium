package ssti_detection

import (
	"bytes"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
)

// #1530: an image baseline and PATH_FILENAME insertion must never be emitted as
// the attack's request paired with a normalized fingerprint/error response.
func TestSSTI1530ImagePathFilenameOwnedSelectedExchanges(t *testing.T) {
	image := []byte{'\x89', 'P', 'N', 'G', 0, 0xff, 'i', 'm', 'g'}
	var hits atomic.Int32
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hits.Add(1)
		if r.URL.Path == "/assets/photo.png" {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(image)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(classifyEvaluation(strings.TrimPrefix(r.URL.Path, "/assets/"))))
	}))
	defer srv.Close()
	client := modtest.Requester(t)
	client, err := client.WithAdditionalHeaders([]string{"Authorization: Bearer capture", "Cookie: test=actual"})
	require.NoError(t, err)
	rr := modtest.Request(t, srv.URL+"/assets/photo.png")
	chain, _, err := client.Execute(rr, http.Options{NoClustering: true})
	require.NoError(t, err)
	baseline := http.CaptureEvidence(chain)
	rr = rr.WithResponse(httpmsg.NewHttpResponse(bytes.Clone(chain.FullResponseBytes()))).WithEvidence(baseline)
	chain.Close()
	ip := modtest.InsertionPointByType(t, rr, httpmsg.INS_URL_PATH_FILENAME)
	m := New()
	sc, guard := &modkit.ScanContext{}, modkit.NewEvidenceCollector()
	beforeGuard := hits.Load()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, rr, client, guard))
	require.Equal(t, int32(modkit.EndpointStabilitySamples), hits.Load()-beforeGuard)
	guardIDs := map[string]bool{}
	for _, entry := range guard.Evidence() {
		guardIDs[entry.ExchangeID] = true
	}
	results, err := m.ScanPerInsertionPoint(rr, ip, client, sc)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	r := results[0]
	require.Equal(t, "selected", r.EvidenceStatus)
	require.NotEmpty(t, r.Payload)
	require.NotEqual(t, string(baseline.Request), r.Request)
	roles := map[evidence.Role]int{}
	primaries, stabilityControls := 0, 0
	for _, entry := range r.Evidence {
		roles[entry.Role]++
		x := entry.Exchange
		require.NotNil(t, x)
		require.NoError(t, x.Validate())
		require.Contains(t, string(x.Request), "Authorization: Bearer capture")
		require.Contains(t, string(x.Request), "Cookie: test=actual")
		u, err := url.Parse(x.URL)
		require.NoError(t, err)
		request := httpmsg.NewHttpRequest(x.Request)
		require.Equal(t, u.RequestURI(), request.Path())
		if guardIDs[entry.ExchangeID] {
			stabilityControls++
			require.False(t, entry.Primary)
			require.Equal(t, evidence.RoleControl, entry.Role)
			require.True(t, bytes.HasSuffix(x.Response, image), "cached stability control keeps its own binary response")
		} else if entry.Role == evidence.RoleBaseline {
			require.True(t, bytes.HasSuffix(x.Response, image), "binary baseline must survive filtering/close")
		} else {
			require.Contains(t, string(x.Response), classifyEvaluation(strings.TrimPrefix(u.Path, "/assets/")))
		}
		if entry.Primary {
			primaries++
			require.Equal(t, evidence.RoleAttack, entry.Role)
			require.Equal(t, string(x.Request), r.Request)
			require.Equal(t, string(x.Response), r.Response)
			require.Contains(t, u.Path, r.Payload)
		}
	}
	require.Equal(t, 1, primaries)
	require.Positive(t, roles[evidence.RoleAttack])
	require.Equal(t, roles[evidence.RoleAttack], roles[evidence.RoleControl]-stabilityControls)
	require.Positive(t, roles[evidence.RoleConfirmation])
	require.Equal(t, 1, roles[evidence.RoleBaseline])
	require.GreaterOrEqual(t, stabilityControls, 4)
	require.LessOrEqual(t, len(r.Evidence), modkit.MaxEvidencePairs+1)
	beforeCachedGuard := hits.Load()
	cached := modkit.NewEvidenceCollector()
	require.False(t, modkit.EndpointVolatileWithEvidence(sc, rr, client, cached))
	require.Equal(t, beforeCachedGuard, hits.Load(), "no proof-only requests on cached guard selection")
	for _, entry := range cached.Evidence() {
		require.True(t, guardIDs[entry.ExchangeID], "cache keeps original receipt identities")
	}
}

func TestSSTISelectionDoesNotSubstituteSoftBaselineForControl(t *testing.T) {
	p := &diffscan.Probe{Name: "pair"}
	makeSnap := func(path string) *diffscan.ResponseSnapshot {
		return &diffscan.ResponseSnapshot{Exchange: evidence.NewExchange("http://test", "http://test/"+path, []byte("GET /"+path+" HTTP/1.1\r\nHost: test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n"+path), evidence.ProvenanceCaptured)}
	}
	attack := &diffscan.Attack{Probe: p, FirstSnapshot: makeSnap("break"), LastSnapshot: makeSnap("break-confirm")}
	control := &diffscan.Attack{Probe: p, FirstSnapshot: makeSnap("escape"), LastSnapshot: makeSnap("escape-confirm")}
	base := &diffscan.Attack{FirstSnapshot: makeSnap("baseline")}
	entries := selectAttackEvidence([]*diffscan.Attack{attack, control}, base)
	require.Len(t, entries, 5)
	require.Equal(t, evidence.RoleControl, entries[2].Role)
	require.Contains(t, string(entries[2].Exchange.Request), "/escape ")
	require.False(t, entries[4].Primary)
	require.Equal(t, evidence.RoleBaseline, entries[4].Role)
}
