package source

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	deparosstorage "github.com/vigolium/vigolium/pkg/deparos/storage"
)

// fakeJSProvider is a RecordSaver (via captureSaver) that also implements
// spideredJSProvider, handing back a fixed set of stored JavaScript records.
type fakeJSProvider struct {
	captureSaver
	records  []jsRow
	gotHost  string
	gotLimit int
}

type jsRow struct {
	url, contentType string
	body             []byte
}

func (f *fakeJSProvider) WalkJavaScriptRecords(_ context.Context, _, hostname string, limit int, fn func(string, string, []byte) error) error {
	f.gotHost = hostname
	f.gotLimit = limit
	for _, r := range f.records {
		if err := fn(r.url, r.contentType, r.body); err != nil {
			return err
		}
	}
	return nil
}

// TestSeedSpideredJS proves the browser→JSTangle bridge actually populates the
// ephemeral discovery sitemap from stored JS before the engine starts: records
// with absolute URLs are stored (and walkable with their JS body), a relative
// URL is skipped, and the provider is queried scoped to the target host.
func TestSeedSpideredJS(t *testing.T) {
	provider := &fakeJSProvider{records: []jsRow{
		{url: "https://app.example.com/assets/app.js", contentType: "application/javascript", body: []byte("fetch('/api/users')")},
		{url: "https://app.example.com/static/vendor.js", contentType: "text/javascript", body: []byte("axios.get('/api/orders')")},
		{url: "/relative/without/origin.js", contentType: "application/javascript", body: []byte("nope")}, // skipped: no scheme/host
	}}
	d := newTestDiscoverySource(provider)

	storageCfg := deparosstorage.DefaultConfig()
	storageCfg.SaveResponseBody = true // discovery enables this; required to persist JS bodies
	siteMap, err := deparosstorage.NewSiteMap(storageCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = siteMap.Close() }()

	d.seedSpideredJS(context.Background(), siteMap, "https://app.example.com/dashboard")

	assert.Equal(t, "app.example.com", provider.gotHost, "provider must be queried scoped to the target host")
	assert.Equal(t, maxSeededSpideredJS, provider.gotLimit, "seed must pass the bounded limit")

	// Only the two absolute-URL JS records are stored (the relative row is
	// skipped), each walkable with its decoded JS body intact for JSTangle.
	var jsBodies []string
	err = siteMap.WalkFiles(func(n *deparosstorage.DiscoveredNode) error {
		if r := n.Response(); r != nil && len(r.Body) > 0 {
			jsBodies = append(jsBodies, string(r.Body))
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Len(t, jsBodies, 2, "two absolute-URL JS files must be seeded, the relative one skipped")
	assert.Contains(t, jsBodies, "fetch('/api/users')")
	assert.Contains(t, jsBodies, "axios.get('/api/orders')")
}

// TestSeedSpideredJS_NoProviderNoOp verifies a repository that only satisfies
// RecordSaver (no WalkJavaScriptRecords) is a graceful no-op.
func TestSeedSpideredJS_NoProviderNoOp(t *testing.T) {
	d := newTestDiscoverySource(newCaptureSaver())
	storageCfg := deparosstorage.DefaultConfig()
	storageCfg.SaveResponseBody = true // discovery enables this; required to persist JS bodies
	siteMap, err := deparosstorage.NewSiteMap(storageCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = siteMap.Close() }()

	// Must not panic and must store nothing.
	d.seedSpideredJS(context.Background(), siteMap, "https://app.example.com/")

	count := 0
	_ = siteMap.WalkFiles(func(*deparosstorage.DiscoveredNode) error { count++; return nil })
	assert.Zero(t, count, "no provider → nothing seeded")
}

// The URL/MIME/decoded-body bridge is extraction-only: it has no raw request,
// actual status, capture state or execution identity. Its placeholder GET/200
// nodes used to flow through readDiscoveredNode into rebuilt HTTP scan inputs.
func TestSeedSpideredJSNotReimportedAsHTTPProof(t *testing.T) {
	for _, stream := range []bool{true, false} {
		name := "end-of-target"
		if stream {
			name = "streaming"
		}
		t.Run(name, func(t *testing.T) {
			provider := &fakeJSProvider{
				captureSaver: *newCaptureSaver(),
				records: []jsRow{{
					url: "https://app.example.com/seed.js", contentType: "application/javascript",
					body: []byte("fetch('/api/seeded-route')"),
				}},
			}
			d := newTestDiscoverySource(provider)
			d.cfg.FuzzAtEnd = !stream
			storageCfg := deparosstorage.DefaultConfig()
			storageCfg.SaveResponseBody = true
			siteMap, err := deparosstorage.NewSiteMap(storageCfg)
			require.NoError(t, err)
			defer func() { _ = siteMap.Close() }()

			ctx, target := context.Background(), "https://app.example.com/"
			d.seedSpideredJS(ctx, siteMap, target)
			// Same pre-engine boundary as discoverTarget: route extraction still
			// walks these nodes, but only later nodes reach the HTTP collector.
			seededThrough := siteMap.LatestNodeID()
			require.Positive(t, seededThrough)
			collector := newTargetCollector(d, target, siteMap)
			collector.cursor.Store(seededThrough)
			require.NoError(t, collector.flush(ctx))
			require.Empty(t, provider.bySource)
			require.Empty(t, d.items, "seeded bodies must not become baseline scan inputs")
			require.Zero(t, collector.stats.TotalDiscovered)

			var extractionBodies []string
			require.NoError(t, siteMap.WalkFiles(func(node *deparosstorage.DiscoveredNode) error {
				extractionBodies = append(extractionBodies, string(node.Response().Body))
				return nil
			}))
			require.Contains(t, extractionBodies, "fetch('/api/seeded-route')")

			// A real crawl result arriving after the boundary still survives both
			// the in-crawl flush and final drain, exactly once.
			fetchedURL, err := url.Parse("https://app.example.com/fetched.js")
			require.NoError(t, err)
			fetched := deparosstorage.NewResult(fetchedURL)
			fetched.Request.Method = "GET"
			fetched.Response.StatusCode = 200
			fetched.Response.MIMEType = "application/javascript"
			fetched.Response.Body = []byte("fetch('/api/fetched-route')")
			fetched.Metadata.FoundBy = "spider"
			require.NoError(t, siteMap.Store(fetched))
			require.NoError(t, collector.flush(ctx))
			require.NoError(t, collector.finish(ctx, noEngineFacts{}, false))
			require.Equal(t, 1, provider.bySource[crawlRecordSource])
			require.Len(t, d.items, 1)
			item := <-d.items
			require.Equal(t, fetchedURL.String(), item.Request.Target())
			require.NotContains(t, collector.acc.uuidByURL, provider.records[0].url, "seed URL must not acquire an invented HTTP record")
		})
	}
}
