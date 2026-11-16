package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
)

func destinationExchange(t *testing.T) *httpmsg.HttpRequestResponse {
	t.Helper()
	service, err := httpmsg.NewService("127.0.0.1", 8443, "https")
	require.NoError(t, err)
	// Neither absolute-form authority nor Host is the actual destination. The
	// intentionally mismatched Content-Length must survive every read path.
	raw := []byte("POST http://named.invalid:8080/path?q=1 HTTP/1.1\r\nHost: host.invalid\r\nContent-Length: 1\r\nX-Exact: yes\r\n\r\nmore than one byte")
	return httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(service, raw),
		httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\ncomplete response")))
}

func TestDirectConverterDestinationIsServiceNotAbsoluteAuthority(t *testing.T) {
	rr := destinationExchange(t)
	var identity, complete HTTPRecord
	require.NoError(t, identity.PrepareIdentity(rr))
	require.NoError(t, complete.FromHttpRequestResponse(rr))
	for _, record := range []*HTTPRecord{&identity, &complete} {
		require.Equal(t, "https", record.Scheme)
		require.Equal(t, "127.0.0.1", record.Hostname)
		require.Equal(t, 8443, record.Port)
		require.Equal(t, "http://named.invalid:8080/path?q=1", record.URL)
	}
	require.Equal(t, rr.Request().Raw(), complete.RawRequest)
	require.Equal(t, rr.Response().Raw(), complete.RawResponse)
}

func TestDBSourcesPreserveDestinationAndAuthoritativeBytes(t *testing.T) {
	for _, mode := range []string{"cursor", "risk", "uuid_list", "writer"} {
		t.Run(mode, func(t *testing.T) {
			db := newTestDB(t)
			repo := NewRepository(db)
			ctx := context.Background()
			rr := destinationExchange(t)
			var id string
			var err error
			if mode == "writer" {
				writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
				defer writer.Close()
				id, err = writer.Write(ctx, rr, RecordSourceIngestCLI, DefaultProjectUUID)
			} else {
				id, err = repo.SaveRecord(ctx, rr, RecordSourceIngestCLI, DefaultProjectUUID)
			}
			require.NoError(t, err)
			var item *work.WorkItem
			switch mode {
			case "cursor":
				source := NewOneShotDBInputSource(db, repo, createTestScan(t, repo))
				defer source.Close()
				item, err = source.Next(ctx)
			case "risk":
				source := NewRiskPrioritizedDBInputSource(db, repo, createTestScan(t, repo))
				defer source.Close()
				item, err = source.Next(ctx)
			default:
				source := NewUUIDListDBInputSource(repo, []string{id})
				defer source.Close()
				item, err = source.Next(ctx)
			}
			require.NoError(t, err)
			require.Equal(t, id, item.RecordUUID)
			got := item.Request
			require.Equal(t, rr.Request().Raw(), got.Request().Raw())
			require.Equal(t, rr.Response().Raw(), got.Response().Raw())
			require.Equal(t, "https", got.Service().Protocol())
			require.Equal(t, "127.0.0.1", got.Service().Host())
			require.Equal(t, 8443, got.Service().Port())
			item.Complete()
		})
	}
}
