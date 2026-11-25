package database

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestFindingRecordIdentityIncludesResponseAndAbsence(t *testing.T) {
	for _, batched := range []bool{false, true} {
		t.Run(map[bool]string{false: "repository", true: "writer_cache"}[batched], func(t *testing.T) {
			db := newTestDB(t)
			repo := NewRepository(db)
			ctx := context.Background()
			var writer *RecordWriter
			if batched {
				writer = NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
				defer writer.Close()
			}
			save := func(rr *httpmsg.HttpRequestResponse) string {
				var id string
				var err error
				if batched {
					id, err = writer.Write(ctx, rr, RecordKindFinding, "")
				} else {
					id, err = repo.SaveRecord(ctx, rr, RecordKindFinding, "")
				}
				require.NoError(t, err)
				return id
			}
			req := makeTestGet(t, "/identity", "")
			a := req.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nfirst")))
			b := req.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 403 Forbidden\r\n\r\nsecond")))
			idA, idB, idMissing := save(a), save(b), save(req)
			require.NotEqual(t, idA, idB)
			require.NotEqual(t, idA, idMissing)
			require.NotEqual(t, idB, idMissing)
			require.Equal(t, idA, save(a))
			require.Equal(t, idB, save(b))
			require.Equal(t, 3, countRecords(t, db))
		})
	}
}

func TestLinkedSnapshotResponseIsVersionedNotRewritten(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	first, second := snapshotPair(t, 200, "first"), snapshotPair(t, 403, "changed")
	id, _, err := repo.UpsertSnapshotRecord(ctx, first, "burp-sitemap", "")
	require.NoError(t, err)
	// A legacy finding has unknown roles, but its context is still historical.
	ev := &output.ResultEvent{ModuleID: "legacy", URL: first.Target(), OriginRecordUUID: id}
	require.NoError(t, repo.SaveFinding(ctx, ev, []string{id}, "scan", ""))
	newID, outcome, err := repo.UpsertSnapshotRecord(ctx, second, "burp-sitemap", "")
	require.NoError(t, err)
	require.NotEqual(t, id, newID)
	require.Equal(t, "inserted", outcome)
	old, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, string(first.Response().Raw()), string(old.RawResponse))
	repeated, outcome, err := repo.UpsertSnapshotRecord(ctx, second, "burp-sitemap", "")
	require.NoError(t, err)
	require.Equal(t, newID, repeated)
	require.Equal(t, "unchanged", outcome)
}

// Crawl and ingestion exchanges can become finding context after they are
// stored. Header-only differences therefore need the same identity guarantees
// as records explicitly labelled finding/candidate/observation.
func TestEveryRecordSourcePreservesChangedExchange(t *testing.T) {
	for _, mode := range []string{"repository", "writer_cache", "snapshot"} {
		for _, source := range []string{"scanner", "ingest-cli", "burp-sitemap", RecordKindFinding, RecordKindCandidate, RecordKindObservation} {
			t.Run(mode+"/"+source, func(t *testing.T) {
				db := newTestDB(t)
				repo := NewRepository(db)
				ctx := context.Background()
				writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
				defer writer.Close()
				trySave := func(rr *httpmsg.HttpRequestResponse) (string, error) {
					switch mode {
					case "repository":
						return repo.SaveRecord(ctx, rr, source, "")
					case "writer_cache":
						return writer.Write(ctx, rr, source, "")
					default:
						id, _, err := repo.UpsertSnapshotRecord(ctx, rr, source, "")
						return id, err
					}
				}
				save := func(rr *httpmsg.HttpRequestResponse) string {
					id, err := trySave(rr)
					require.NoError(t, err)
					return id
				}
				responseA := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=A\r\n\r\nbody"))
				responseB := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=B\r\n\r\nbody"))
				a := makeTestGet(t, "/header-identity", "Cookie: session=A\r\nAuthorization: Bearer A").WithResponse(responseA)
				cookieB := makeTestGet(t, "/header-identity", "Cookie: session=B\r\nAuthorization: Bearer A")
				authB := makeTestGet(t, "/header-identity", "Cookie: session=A\r\nAuthorization: Bearer B")
				variants := []*httpmsg.HttpRequestResponse{
					a, cookieB.WithResponse(responseA), cookieB.WithResponse(responseB),
					authB.WithResponse(responseA), authB.WithResponse(responseB),
					a.WithResponse(responseB), a.WithResponse(nil),
				}
				// A present-but-empty object cannot survive supplied reload as
				// present. Reject it, rather than storing a false response identity.
				emptyID, err := trySave(a.WithResponse(httpmsg.NewHttpResponse(nil)))
				require.ErrorContains(t, err, "empty response object")
				require.Empty(t, emptyID)
				require.Zero(t, countRecords(t, db))
				ids := make(map[string]bool)
				for _, rr := range variants {
					id := save(rr)
					require.False(t, ids[id], "changed exchange reused %s", id)
					ids[id] = true
					record, err := repo.GetRecordByUUID(ctx, id)
					require.NoError(t, err)
					require.Equal(t, rr.Request().Raw(), record.RawRequest)
					require.Equal(t, rr.HasResponse(), record.HasResponse)
					if rr.HasResponse() {
						require.Equal(t, string(rr.Response().Raw()), string(record.RawResponse))
					}
					require.Equal(t, id, save(rr), "exact exchange must reuse UUID")
				}
				require.Len(t, ids, len(variants))
				require.Equal(t, len(variants), countRecords(t, db))
			})
		}
	}
}

func TestRecordIdentityPreservesDestinationService(t *testing.T) {
	for _, mode := range []string{"repository", "writer_cache", "snapshot"} {
		t.Run(mode, func(t *testing.T) {
			db := newTestDB(t)
			repo := NewRepository(db)
			ctx := context.Background()
			writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
			defer writer.Close()
			// Absolute-form target and Host name a virtual host, not the actual
			// destination. Service identity must not be recovered from that URL.
			raw := []byte("GET https://virtual.example/service HTTP/1.1\r\nHost: virtual.example\r\n\r\n")
			services := []*httpmsg.Service{
				httpmsg.NewServiceSecure("dest.example", 443, true),
				httpmsg.NewServiceSecure("other.example", 443, true),
				httpmsg.NewServiceSecure("dest.example", 8443, true),
				httpmsg.NewServiceSecure("dest.example", 443, false),
			}
			ids := make(map[string]bool)
			for _, service := range services {
				rr := httpmsg.NewHttpRequestResponse(httpmsg.NewHttpRequestWithService(service, raw),
					httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nsame")))
				save := func() string {
					var id string
					var err error
					switch mode {
					case "repository":
						id, err = repo.SaveRecord(ctx, rr, "ingest", "")
					case "writer_cache":
						id, err = writer.Write(ctx, rr, "scanner", "")
					case "snapshot":
						id, _, err = repo.UpsertSnapshotRecord(ctx, rr, "burp-sitemap", "")
					}
					require.NoError(t, err)
					return id
				}
				id := save()
				require.False(t, ids[id], "changed destination reused UUID")
				ids[id] = true
				record, err := repo.GetRecordByUUID(ctx, id)
				require.NoError(t, err)
				require.Equal(t, service.Host(), record.Hostname)
				require.Equal(t, service.Protocol(), record.Scheme)
				require.Equal(t, service.Port(), record.Port)
				require.Equal(t, raw, record.RawRequest)
				require.Equal(t, id, save())
			}
		})
	}
}

func TestWriterSnapshotWriterKeepsCachedExchangeExact(t *testing.T) {
	for _, header := range []string{"Cookie", "Authorization"} {
		for _, sameResponse := range []bool{false, true} {
			t.Run(header+map[bool]string{false: "/different_response", true: "/same_response"}[sameResponse], func(t *testing.T) {
				db := newTestDB(t)
				repo := NewRepository(db)
				ctx := context.Background()
				writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
				defer writer.Close()
				a := makeTestGet(t, "/cached", header+": A").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nA")))
				b := makeTestGet(t, "/cached", header+": B").WithResponse(a.Response())
				if !sameResponse {
					b = b.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 403 Forbidden\r\n\r\nB")))
				}
				idA, err := writer.Write(ctx, a, "scanner", "")
				require.NoError(t, err)
				before, err := repo.GetRecordByUUID(ctx, idA)
				require.NoError(t, err)
				idB, outcome, err := repo.UpsertSnapshotRecord(ctx, b, "burp-sitemap", "")
				require.NoError(t, err)
				require.Equal(t, "inserted", outcome)
				require.NotEqual(t, idA, idB)
				again, err := writer.Write(ctx, a, "scanner", "")
				require.NoError(t, err)
				require.Equal(t, idA, again)
				after, err := repo.GetRecordByUUID(ctx, again)
				require.NoError(t, err)
				require.Equal(t, before, after, "cache must still identify all original data")
				repeated, outcome, err := repo.UpsertSnapshotRecord(ctx, b, "ingest-other-source", "")
				require.NoError(t, err)
				require.Equal(t, idB, repeated, "source must not change exchange identity")
				require.Equal(t, "unchanged", outcome)
			})
		}
	}
}

func TestSnapshotVersionsBeforePendingFindingReferencesCommit(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, b := snapshotPair(t, 200, "first"), snapshotPair(t, 403, "later")
	idA, _, err := repo.UpsertSnapshotRecord(ctx, a, "burp-sitemap", "")
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	writer := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize: 1,
		saveBatch: func(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
			close(entered)
			<-release
			return repo.SaveFindingsBatchResults(ctx, writes)
		},
	})
	defer writer.Close()
	defer unblock()
	require.NoError(t, writer.Save(ctx, &output.ResultEvent{
		ModuleID: "pending", URL: a.Target(), OriginRecordUUID: idA,
	}, []string{idA}, "scan", ""))
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	n, err := db.NewSelect().Table("finding_records").Where("record_uuid = ?", idA).Count(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "finding reference must still be pending")
	idB, outcome, err := repo.UpsertSnapshotRecord(ctx, b, "burp-sitemap", "")
	require.NoError(t, err)
	require.NotEqual(t, idA, idB)
	require.Equal(t, "inserted", outcome)
	unblock()
	require.True(t, writer.Shutdown().Clean())
	n, err = db.NewSelect().Table("finding_records").Where("record_uuid = ?", idA).Count(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	old, err := repo.GetRecordByUUID(ctx, idA)
	require.NoError(t, err)
	require.Equal(t, a.Request().Raw(), old.RawRequest)
	require.Equal(t, a.Response().Raw(), old.RawResponse)
}

func TestSnapshotDuringPendingRecordWritePreservesBothExchanges(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	writer := NewRecordWriter(repo, RecordWriterConfig{
		Shards: 1,
		insertBatch: func(ctx context.Context, records []*HTTPRecord) error {
			close(entered)
			<-release
			_, err := repo.SaveRecordsBatch(ctx, records)
			return err
		},
	})
	defer writer.Close()
	defer unblock()
	a := makeTestGet(t, "/pending-record", "Cookie: A").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nA")))
	b := makeTestGet(t, "/pending-record", "Cookie: B").WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 403 Forbidden\r\n\r\nB")))
	pending := writer.admit(ctx, a, "scanner", "", RecordLineage{})
	require.False(t, pending.resolved)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	idB, outcome, err := repo.UpsertSnapshotRecord(ctx, b, "burp-sitemap", "")
	require.NoError(t, err)
	require.Equal(t, "inserted", outcome)
	unblock()
	idA, err := writer.await(ctx, pending)
	require.NoError(t, err)
	require.NotEqual(t, idA, idB)
	again, err := writer.Write(ctx, a, "scanner", "")
	require.NoError(t, err)
	require.Equal(t, idA, again)
	record, err := repo.GetRecordByUUID(ctx, idA)
	require.NoError(t, err)
	require.Equal(t, a.Request().Raw(), record.RawRequest)
	require.Equal(t, a.Response().Raw(), record.RawResponse)
}

func TestExactLookupSkipsStaleCandidateWithoutRewritingOldData(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()
	a := snapshotPair(t, 200, "original")
	stale, exact := toRecord(t, a, "legacy-import"), toRecord(t, a, "scanner")
	stale.UUID, exact.UUID = "a-stale", "b-exact"
	stale.RawResponse = []byte("HTTP/1.1 200 OK\r\n\r\nlegacy altered bytes")
	_, err := repo.SaveRecordsBatch(ctx, []*HTTPRecord{stale, exact})
	require.NoError(t, err)
	id, err := repo.findDuplicateRecord(ctx, toRecord(t, a, RecordKindFinding))
	require.NoError(t, err)
	require.Equal(t, exact.UUID, id, "must try a valid candidate after rejecting stale raw")
	old, err := repo.GetRecordByUUID(ctx, stale.UUID)
	require.NoError(t, err)
	require.Equal(t, stale.RawResponse, old.RawResponse, "legacy data must not be repaired or destroyed")
	require.Equal(t, stale.ResponseHash, old.ResponseHash)
}

func TestWriterRejectsStaleCachedOrCandidateRawIdentity(t *testing.T) {
	for _, corruption := range []string{"stale_hash", "changed_hash", "compacted", "deleted"} {
		t.Run(corruption, func(t *testing.T) {
			db := newTestDB(t)
			repo := NewRepository(db)
			ctx := context.Background()
			writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
			defer writer.Close()
			a := snapshotPair(t, 200, "original")
			id, err := writer.Write(ctx, a, RecordKindFinding, "")
			require.NoError(t, err)
			changed := []byte("HTTP/1.1 200 OK\r\n\r\nlegacy mutation")
			switch corruption {
			case "stale_hash":
				_, err = db.ExecContext(ctx, "UPDATE http_records SET raw_response = ? WHERE uuid = ?", changed, id)
			case "changed_hash":
				_, err = db.ExecContext(ctx, "UPDATE http_records SET raw_response = ?, response_hash = ? WHERE uuid = ?", changed, rawRecordHash(changed), id)
			case "compacted":
				_, err = db.ExecContext(ctx, "UPDATE http_records SET body_compaction = ? WHERE uuid = ?", `{"version":1}`, id)
			case "deleted":
				_, err = db.ExecContext(ctx, "DELETE FROM http_records WHERE uuid = ?", id)
			}
			require.NoError(t, err)
			// Both paths must verify the row, not trust cache residency or a
			// candidate's retained hashes from older transformations/compaction.
			lookup, err := repo.findDuplicateRecord(ctx, toRecord(t, a, "scanner"))
			require.NoError(t, err)
			require.Empty(t, lookup)
			newID, err := writer.Write(ctx, a, RecordKindFinding, "")
			require.NoError(t, err)
			require.NotEqual(t, id, newID)
			record, err := repo.GetRecordByUUID(ctx, newID)
			require.NoError(t, err)
			require.Equal(t, a.Request().Raw(), record.RawRequest)
			require.Equal(t, a.Response().Raw(), record.RawResponse)
			require.True(t, recordExchangeBytesValid(record))
		})
	}
}
