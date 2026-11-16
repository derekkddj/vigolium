package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

type riskMemoryFixture struct {
	id       string
	request  []byte
	response []byte
	at       time.Time
	score    int
}

func (f riskMemoryFixture) size() int64 {
	return int64(len(f.request) + len(f.response))
}

// Binary bodies contain NUL, invalid UTF-8 and multibyte UTF-8. Framing is valid,
// and assertions use the exact stored exchange bytes, never Content-Length.
func insertRiskMemoryFixture(t *testing.T, repo *Repository, path string, requestBody, responseBody, score, ordinal int) riskMemoryFixture {
	t.Helper()
	binaryBody := func(n int) []byte {
		body := make([]byte, n)
		pattern := []byte{0, 0xff, 0xc3, 0xa9}
		for i := range body {
			body[i] = pattern[i%len(pattern)]
		}
		return body
	}
	method := "GET"
	if requestBody > 0 {
		method = "POST"
	}
	request := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: memory.test\r\nContent-Length: %d\r\n\r\n", method, path, requestBody))
	request = append(request, binaryBody(requestBody)...)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", responseBody))
	response = append(response, binaryBody(responseBody)...)
	rr, err := httpmsg.ParseRawRequestWithURL(string(request), "http://memory.test"+path)
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse(response))
	id, err := repo.SaveRecord(context.Background(), rr, "test", DefaultProjectUUID)
	require.NoError(t, err)
	at := time.Unix(1700000000+int64(ordinal), 0).UTC()
	_, err = repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).
		Set("created_at = ?", at).Set("risk_score = ?", score).
		Set("request_content_length = 0").Set("response_content_length = 1").
		Where("uuid = ?", id).Exec(context.Background())
	require.NoError(t, err)
	stored, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	require.Equal(t, request, stored.RawRequest)
	require.Equal(t, response, stored.RawResponse)
	return riskMemoryFixture{id: id, request: request, response: response, at: at, score: score}
}

type riskMemoryQueryHook struct {
	before func(context.Context, *bun.QueryEvent) context.Context
	after  func(context.Context, *bun.QueryEvent)
}

func (h riskMemoryQueryHook) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if h.before != nil {
		return h.before(ctx, e)
	}
	return ctx
}

func (h riskMemoryQueryHook) AfterQuery(ctx context.Context, e *bun.QueryEvent) {
	if h.after != nil {
		h.after(ctx, e)
	}
}

func isRiskMemoryBodyQuery(e *bun.QueryEvent) bool {
	return strings.Contains(e.Query, "END AS raw_response")
}

func riskMemoryQueryIDs(query string, fixtures []riskMemoryFixture) []string {
	var ids []string
	for _, f := range fixtures {
		if strings.Contains(query, "'"+f.id+"'") {
			ids = append(ids, f.id)
		}
	}
	return ids
}

func requireRiskMemoryCursorUnchanged(t *testing.T, repo *Repository, scanID string) {
	t.Helper()
	scan, err := repo.GetScanByUUID(context.Background(), scanID)
	require.NoError(t, err)
	require.True(t, scan.CursorAt.IsZero(), "a partial round must not checkpoint past unfinished coverage")
	require.Empty(t, scan.CursorUUID)
	require.Zero(t, scan.ProcessedCount)
}

func requireRiskMemoryFatal(t *testing.T, err error) *RiskRecordMemoryLimitError {
	t.Helper()
	var limitErr *RiskRecordMemoryLimitError
	require.ErrorAs(t, err, &limitErr)
	var fatal interface{ FatalSourceError() bool }
	require.True(t, errors.As(err, &fatal))
	require.True(t, fatal.FatalSourceError(), "the feed must fail/partially drain, not retry a deterministic oversize boundary")
	require.True(t, limitErr.FatalSourceError())
	return limitErr
}

func TestRiskMemoryLimitsAlwaysFinite(t *testing.T) {
	for _, values := range [][2]int64{{0, 0}, {-1, -1}, {1 << 62, 1 << 62}} {
		s := (&RiskPrioritizedDBInputSource{}).WithMemoryLimits(values[0], values[1])
		page, record := s.memoryLimits()
		require.Equal(t, int64(16<<20), page)
		require.Equal(t, int64(64<<20), record)
	}
	s := (&RiskPrioritizedDBInputSource{}).WithMemoryLimits(333, 777)
	page, record := s.memoryLimits()
	require.Equal(t, int64(333), page)
	require.Equal(t, int64(777), record)
	page, record = (&RiskPrioritizedDBInputSource{}).memoryLimits()
	require.Equal(t, int64(16<<20), page)
	require.Equal(t, int64(64<<20), record)
}

func TestRiskMemoryMixedSizesByteBoundedPriorityNoHoles(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	var fixtures []riskMemoryFixture
	for i := 0; i < riskPrefetchBatchSize+7; i++ {
		fixtures = append(fixtures, insertRiskMemoryFixture(t, repo, fmt.Sprintf("/entry/%d", i),
			(i%3)*80, (i%5)*120, (i*7)%11, i/2)) // includes timestamp/score ties
	}
	sort.Slice(fixtures, func(i, j int) bool {
		a, b := fixtures[i], fixtures[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		return a.id < b.id
	})
	var bodyQueries []string
	repo.DB().AddQueryHook(riskMemoryQueryHook{before: func(ctx context.Context, e *bun.QueryEvent) context.Context {
		if isRiskMemoryBodyQuery(e) {
			bodyQueries = append(bodyQueries, e.Query)
		}
		return ctx
	}})
	const budget int64 = 1100
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithMemoryLimits(budget, 4096)
	require.Zero(t, source.Count())
	var got []string
	for {
		item, err := source.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		got = append(got, item.RecordUUID)
		source.mu.Lock()
		for _, record := range source.buffer[:source.bufHead] {
			require.Nil(t, record, "consumed raw records must be released immediately")
		}
		source.mu.Unlock()
		item.Complete()
	}
	want := make([]string, 0, len(fixtures))
	byID := make(map[string]riskMemoryFixture, len(fixtures))
	for _, f := range fixtures {
		want = append(want, f.id)
		byID[f.id] = f
	}
	require.Equal(t, want, got, "byte cuts must preserve the complete risk/time/UUID ordering")
	require.Greater(t, len(bodyQueries), 2, "this tiny budget must split count-sized pages before hydration")
	var hydratedIDs []string
	for _, query := range bodyQueries {
		ids := riskMemoryQueryIDs(query, fixtures)
		var total int64
		for _, id := range ids {
			total += byID[id].size()
		}
		require.LessOrEqual(t, total, budget, "the SQL hydration UUID set, not just the surviving buffer, must be byte bounded")
		hydratedIDs = append(hydratedIDs, ids...)
	}
	require.Equal(t, want, hydratedIDs)
	require.Equal(t, int64(len(fixtures)), source.Count())
	scan, err := repo.GetScanByUUID(ctx, scanID)
	require.NoError(t, err)
	require.Equal(t, int64(len(fixtures)), scan.ProcessedCount)
	remaining, err := repo.CountRecordsAfterCursor(ctx, DefaultProjectUUID, scan.CursorAt, scan.CursorUUID, HostTarget{Hostname: "memory.test"})
	require.NoError(t, err)
	require.Zero(t, remaining)
}

func TestRiskMemoryLargerThanPageOwnsPageAloneAtRecordLimit(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	large := insertRiskMemoryFixture(t, repo, "/large", 600, 600, 10, 0)
	small := insertRiskMemoryFixture(t, repo, "/small", 0, 0, 0, 1)
	var pages [][]string
	fixtures := []riskMemoryFixture{large, small}
	repo.DB().AddQueryHook(riskMemoryQueryHook{before: func(ctx context.Context, e *bun.QueryEvent) context.Context {
		if isRiskMemoryBodyQuery(e) {
			pages = append(pages, riskMemoryQueryIDs(e.Query, fixtures))
		}
		return ctx
	}})
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithMemoryLimits(256, large.size())
	first, err := source.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, large.id, first.RecordUUID)
	require.Len(t, source.buffer, 1)
	require.Nil(t, source.buffer[0])
	first.Complete()
	second, err := source.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, small.id, second.RecordUUID)
	second.Complete()
	_, err = source.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, [][]string{{large.id}, {small.id}}, pages)
}

func TestRiskMemoryOversizedFatalBeforeHydrationAndNoCursorOrACK(t *testing.T) {
	for _, earlierSmall := range []bool{false, true} {
		t.Run(fmt.Sprintf("earlier-small-%t", earlierSmall), func(t *testing.T) {
			repo := NewRepository(newTestDB(t))
			ctx := context.Background()
			scanID := createTestScan(t, repo)
			var small riskMemoryFixture
			if earlierSmall {
				small = insertRiskMemoryFixture(t, repo, "/search?q=small", 0, 8, 20, 0)
			}
			big := insertRiskMemoryFixture(t, repo, "/search?q=big", 0, 2048, 10, 1)
			var bodies, descriptors atomic.Int32
			repo.DB().AddQueryHook(riskMemoryQueryHook{before: func(ctx context.Context, e *bun.QueryEvent) context.Context {
				if isRiskMemoryBodyQuery(e) {
					bodies.Add(1)
				}
				if strings.Contains(e.Query, "END AS parameters") {
					descriptors.Add(1)
				}
				return ctx
			}})
			source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).
				WithMemoryLimits(512, 1024).WithParamShapeCoalescing(1)
			if earlierSmall {
				item, err := source.Next(ctx)
				require.NoError(t, err)
				require.Equal(t, small.id, item.RecordUUID)
				item.Complete()
			}
			keyBefore, totalBefore := source.keyID, source.total
			bodyBefore, descriptorBefore := bodies.Load(), descriptors.Load()
			for i := 0; i < 2; i++ {
				item, err := source.Next(ctx)
				require.Nil(t, item)
				limitErr := requireRiskMemoryFatal(t, err)
				require.Equal(t, big.id, limitErr.RecordUUID)
				require.Equal(t, big.size(), limitErr.StoredBytes)
				require.Equal(t, int64(1024), limitErr.LimitBytes)
				require.Equal(t, keyBefore, source.keyID)
				require.Equal(t, totalBefore, source.total)
				require.Equal(t, bodyBefore, bodies.Load(), "oversized body must never be fetched")
				require.Equal(t, descriptorBefore, descriptors.Load(), "oversized rows must not even hydrate coalescing parameter values")
				require.Zero(t, source.CoalescedDropped(), "an oversized row cannot silently consume a drop/sample slot")
				require.Zero(t, source.skipped)
				require.Equal(t, totalBefore, source.acked)
				require.False(t, source.streamsExhausted)
				require.NoError(t, source.FlushCursor(ctx))
				requireRiskMemoryCursorUnchanged(t, repo, scanID)
			}
			require.Len(t, source.coalescer.seenByShape, totalBefore)
		})
	}
}

func TestRiskMemoryExplicitExclusionsPrecedeByteAdmissionAndCoalescing(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	excluded := insertRiskMemoryFixture(t, repo, "/admit?q=old", 0, 2048, 100, 0)
	observed := insertRiskMemoryFixture(t, repo, "/admit?q=observed", 0, 8, 10, 1)
	tail := insertRiskMemoryFixture(t, repo, "/admit?q=tail", 0, 8, 0, 2)
	var hydrated []string
	fixtures := []riskMemoryFixture{excluded, observed, tail}
	repo.DB().AddQueryHook(riskMemoryQueryHook{before: func(ctx context.Context, e *bun.QueryEvent) context.Context {
		if isRiskMemoryBodyQuery(e) {
			hydrated = append(hydrated, riskMemoryQueryIDs(e.Query, fixtures)...)
		}
		return ctx
	}})
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).
		WithMemoryLimits(256, 1024).WithParamShapeCoalescing(1).WithExcludedRecordUUIDs([]string{excluded.id})
	item, err := source.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, observed.id, item.RecordUUID)
	item.Complete()
	_, err = source.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, []string{observed.id}, hydrated)
	require.Equal(t, 1, source.ExcludedRecords())
	require.Equal(t, 1, source.CoalescedDropped())
	require.NoError(t, source.Close())
	require.Equal(t, 1, source.ExcludedRecords())
	require.Equal(t, 1, source.CoalescedDropped())
	scan, err := repo.GetScanByUUID(ctx, scanID)
	require.NoError(t, err)
	require.Equal(t, int64(1), scan.ProcessedCount)
	require.Equal(t, tail.id, scan.CursorUUID)
}

func TestRiskMemoryOversizedDescriptorsOnlyLoadLengths(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	f := insertRiskMemoryFixture(t, repo, "/query?q=one", 0, 8, 1, 0)
	params, err := json.Marshal([]EmbeddedParam{{Name: "payload", Type: "json", Value: strings.Repeat("x", 4096)}})
	require.NoError(t, err)
	_, err = repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("parameters = ?", string(params)).Where("uuid = ?", f.id).Exec(ctx)
	require.NoError(t, err)
	var queries []string
	repo.DB().AddQueryHook(riskMemoryQueryHook{before: func(ctx context.Context, e *bun.QueryEvent) context.Context {
		queries = append(queries, e.Query)
		return ctx
	}})
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithMemoryLimits(256, 1024).WithParamShapeCoalescing(1)
	_, err = source.Next(ctx)
	limitErr := requireRiskMemoryFatal(t, err)
	require.Equal(t, f.id, limitErr.RecordUUID)
	require.Contains(t, limitErr.Kind, "descriptors")
	for _, query := range queries {
		require.NotContains(t, query, "END AS parameters")
		require.NotContains(t, query, "END AS raw_response")
	}
	require.Empty(t, source.coalescer.seenByShape)
	require.False(t, source.started)
	requireRiskMemoryCursorUnchanged(t, repo, scanID)
}

func TestRiskMemoryPreflightLengthsCoalesceNULLAndUseBlobBytes(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	binary := insertRiskMemoryFixture(t, repo, "/binary", 17, 29, 2, 0)
	// Same (risk, surface) bucket: a page lists one bucket at a time.
	empty := insertRiskMemoryFixture(t, repo, "/null", 0, 0, 2, 1)
	_, err := repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("raw_request = NULL").Set("raw_response = NULL").Where("uuid = ?", empty.id).Exec(ctx)
	require.NoError(t, err)
	_, err = repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("surface_score = 0").Where("1 = 1").Exec(ctx)
	require.NoError(t, err)
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithParamShapeCoalescing(1)
	source.mu.Lock()
	err = source.captureBoundLocked(ctx)
	if err != nil {
		source.mu.Unlock()
		t.Fatal(err)
	}
	rows, err := source.nextPageRowsLocked(ctx)
	source.mu.Unlock()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, binary.size(), rows[0].StoredBytes)
	require.Zero(t, rows[1].StoredBytes)
	for _, row := range rows {
		require.Nil(t, row.Parameters)
		require.Empty(t, row.URL)
	}
}

func TestRiskMemoryRefillClearsConsumedAndHiddenTailReferences(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	var fixtures []riskMemoryFixture
	for i := 0; i < 4; i++ {
		// One (risk, surface) bucket, in created_at order: the byte budget, not
		// a bucket boundary, is what cuts the first page.
		fixtures = append(fixtures, insertRiskMemoryFixture(t, repo, fmt.Sprintf("/tail/%d", i), 0, 8, 4, i))
	}
	_, err := repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("surface_score = 0").Where("1 = 1").Exec(ctx)
	require.NoError(t, err)
	budget := fixtures[0].size() + fixtures[1].size() + fixtures[2].size()
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithMemoryLimits(budget, 4096)
	for i := 0; i < 3; i++ {
		item, err := source.Next(ctx)
		require.NoError(t, err)
		require.Equal(t, fixtures[i].id, item.RecordUUID)
		require.Nil(t, source.buffer[i])
		item.Complete()
	}
	require.Len(t, source.buffer, 3)
	backing := source.buffer[:cap(source.buffer)]
	// Isolate the full-capacity cleanup from consumed-entry cleanup: seed stale
	// references both in the previous length and in a hidden shorter-page tail.
	backing[0] = &HTTPRecord{RawResponse: bytes.Repeat([]byte{0xff}, 1024)}
	backing[len(backing)-1] = &HTTPRecord{RawResponse: bytes.Repeat([]byte{0xff}, 1024)}
	last, err := source.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, fixtures[3].id, last.RecordUUID)
	require.Len(t, source.buffer, 1)
	require.Equal(t, cap(backing), cap(source.buffer))
	for _, record := range backing {
		require.Nil(t, record, "a shorter refill must not retain an old raw row anywhere in the backing array")
	}
	last.Complete()
	_, err = source.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
}

func TestRiskMemoryCloseReleasesPageAndKeepsCountersAndLateACK(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		t.Run(fmt.Sprintf("exhausted-%t", exhausted), func(t *testing.T) {
			repo := NewRepository(newTestDB(t))
			ctx := context.Background()
			scanID := createTestScan(t, repo)
			for i := 0; i < 3; i++ {
				// One (risk, surface) bucket: the page holds all three rows.
				insertRiskMemoryFixture(t, repo, fmt.Sprintf("/close?q=%d", i), 0, 24, 3, i)
			}
			_, err := repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("surface_score = 0").Where("1 = 1").Exec(ctx)
			require.NoError(t, err)
			capSamples := 2
			if exhausted {
				capSamples = 1
			}
			source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithParamShapeCoalescing(capSamples)
			item, err := source.Next(ctx)
			require.NoError(t, err)
			if exhausted {
				_, err = source.Next(ctx)
				require.ErrorIs(t, err, io.EOF)
			}
			backing := source.buffer[:cap(source.buffer)]
			dropped, total := source.CoalescedDropped(), source.total
			require.NotEmpty(t, source.coalescer.seenByShape)
			require.NoError(t, source.Close())
			require.Nil(t, source.buffer)
			require.Zero(t, source.bufHead)
			require.Nil(t, source.coalescer.seenByShape)
			for _, record := range backing {
				require.Nil(t, record)
			}
			require.Equal(t, dropped, source.CoalescedDropped())
			require.Equal(t, total, source.total)
			require.Equal(t, int64(3), source.Count())
			item.Complete()
			item.Complete() // callback remains exactly once after Close
			require.Equal(t, 1, source.acked)
			require.Equal(t, dropped, source.CoalescedDropped())
			require.NoError(t, source.FlushCursor(ctx))
			if exhausted {
				scan, err := repo.GetScanByUUID(ctx, scanID)
				require.NoError(t, err)
				require.Equal(t, int64(1), scan.ProcessedCount)
				require.True(t, source.committed)
			} else {
				require.Equal(t, 1, source.Unresolved())
				requireRiskMemoryCursorUnchanged(t, repo, scanID)
			}
			_, err = source.Next(ctx)
			require.ErrorIs(t, err, io.EOF)
			require.NoError(t, source.Close())
		})
	}
}

func TestRiskMemoryCloseFencesConcurrentSuccessfulFill(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	scanID := createTestScan(t, repo)
	for i := 0; i < 3; i++ {
		insertRiskMemoryFixture(t, repo, fmt.Sprintf("/fill?q=%d", i), 0, 32, 3-i, i)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	repo.DB().AddQueryHook(riskMemoryQueryHook{after: func(ctx context.Context, e *bun.QueryEvent) {
		if isRiskMemoryBodyQuery(e) {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}})
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithParamShapeCoalescing(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nextDone := make(chan error, 1)
	go func() {
		item, err := source.Next(ctx)
		if item != nil {
			nextDone <- fmt.Errorf("unserved page installed after Close: %s", item.RecordUUID)
			return
		}
		nextDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("body fetch never reached the deterministic fill fence")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- source.Close() }()
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("Close blocked behind a fetch holding the source lock")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-nextDone:
		require.ErrorIs(t, err, io.EOF)
	case <-ctx.Done():
		t.Fatal("Next did not release its lock/return after the fenced fill")
	}
	require.Nil(t, source.buffer)
	require.False(t, source.started)
	require.Empty(t, source.keyID)
	require.Zero(t, source.total)
	require.Zero(t, source.acked)
	require.Zero(t, source.skipped)
	require.Zero(t, source.CoalescedDropped(), "the unserved coalescer plan must not commit")
	require.Nil(t, source.coalescer.seenByShape)
	require.False(t, source.streamsExhausted)
	require.NoError(t, source.FlushCursor(context.Background()))
	requireRiskMemoryCursorUnchanged(t, repo, scanID)
}

func TestRiskMemoryBoundedRetryDiscardsCoalescerPlanUntilFetchSucceeds(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	var fixtures []riskMemoryFixture
	for i := 0; i < 4; i++ {
		// One (risk, surface) bucket: the page lists all four rows.
		fixtures = append(fixtures, insertRiskMemoryFixture(t, repo, fmt.Sprintf("/retry?q=%d", i), 0, 24, 4, i))
	}
	if _, uerr := repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("surface_score = 0").Where("1 = 1").Exec(ctx); uerr != nil {
		t.Fatal(uerr)
	}
	// Derive the injected budget from actual SQL descriptor/raw byte lengths,
	// including whatever parameter metadata this repository version writes.
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithParamShapeCoalescing(2)
	source.mu.Lock()
	err := source.captureBoundLocked(ctx)
	if err != nil {
		source.mu.Unlock()
		t.Fatal(err)
	}
	source.loaded = true
	metadata, err := source.nextPageRowsLocked(ctx)
	source.mu.Unlock()
	require.NoError(t, err)
	require.Len(t, metadata, len(fixtures))
	budget := metadata[0].StoredBytes + metadata[0].DescriptorBytes + metadata[1].StoredBytes + metadata[1].DescriptorBytes
	source.WithMemoryLimits(budget, 4096)
	var calls atomic.Int32
	var bodyQueries []string
	repo.DB().AddQueryHook(riskMemoryQueryHook{before: func(ctx context.Context, e *bun.QueryEvent) context.Context {
		if isRiskMemoryBodyQuery(e) {
			bodyQueries = append(bodyQueries, e.Query)
			if calls.Add(1) <= cursorFlushAttempts {
				// Only the SQL attempt's context fails; the live feed context lets
				// RetryBusy exhaust its finite retry policy deterministically.
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				return cancelled
			}
		}
		return ctx
	}})
	// Budget only two admitted rows, so the subsequent all-dropped prefix also
	// exercises coalescer accounting across a byte cut, not just a count cut.
	item, err := source.Next(ctx)
	require.Nil(t, item)
	require.Error(t, err)
	require.Equal(t, int32(cursorFlushAttempts), calls.Load())
	require.False(t, source.started)
	require.Zero(t, source.total)
	require.Zero(t, source.skipped)
	require.Zero(t, source.CoalescedDropped())
	require.Empty(t, source.coalescer.seenByShape)
	requireRiskMemoryCursorUnchanged(t, repo, scanID)
	var got []string
	for {
		item, err := source.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		got = append(got, item.RecordUUID)
		item.Complete()
	}
	require.Equal(t, []string{fixtures[0].id, fixtures[1].id}, got)
	require.Equal(t, int32(cursorFlushAttempts+1), calls.Load())
	for _, query := range bodyQueries {
		require.Equal(t, got, riskMemoryQueryIDs(query, fixtures), "failed retries must choose the exact same bounded survivors")
	}
	require.Equal(t, 2, source.CoalescedDropped(), "whole coalesced pages still contribute their drop count")
	scan, err := repo.GetScanByUUID(ctx, scanID)
	require.NoError(t, err)
	require.Equal(t, int64(2), scan.ProcessedCount)
	require.Equal(t, fixtures[len(fixtures)-1].id, scan.CursorUUID)
}

func TestRiskMemoryBodyCoalescingPreservesDescriptorsAcrossByteCuts(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	var ids []string
	response := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"), []byte{0, 0xff, 0xc3, 0xa9}...)
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"id":"%d"}`, i)
		raw := fmt.Sprintf("POST /json HTTP/1.1\r\nHost: memory.test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		rr, err := httpmsg.ParseRawRequestWithURL(raw, "http://memory.test/json")
		require.NoError(t, err)
		id, err := repo.SaveRecord(ctx, rr.WithResponse(httpmsg.NewHttpResponse(response)), "test", DefaultProjectUUID)
		require.NoError(t, err)
		ids = append(ids, id)
		_, err = repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).
			Set("created_at = ?", time.Unix(1700000000+int64(i), 0).UTC()).Set("risk_score = ?", 3-i).
			Where("uuid = ?", id).Exec(ctx)
		require.NoError(t, err)
		stored, err := repo.GetRecordByUUID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, []byte(raw), stored.RawRequest)
		require.Equal(t, response, stored.RawResponse)
		hasJSON := false
		for _, param := range stored.Parameters {
			if param.Type == "json" {
				hasJSON = true
			}
		}
		require.True(t, hasJSON, "test fixture must contain observed JSON parameters")
	}
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithMemoryLimits(128, 4096).WithParamShapeCoalescing(1)
	item, err := source.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, ids[0], item.RecordUUID)
	item.Complete()
	_, err = source.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 2, source.CoalescedDropped(), "POST descriptors must survive the separate bounded metadata hydration")
	scan, err := repo.GetScanByUUID(ctx, scanID)
	require.NoError(t, err)
	require.Equal(t, int64(1), scan.ProcessedCount)
	require.Equal(t, ids[2], scan.CursorUUID)
}

func TestRiskMemorySQLGuardRejectsGrowthWithoutHydratingTheGrownBody(t *testing.T) {
	repo := NewRepository(newTestDB(t))
	ctx := context.Background()
	scanID := createTestScan(t, repo)
	f := insertRiskMemoryFixture(t, repo, "/grow", 0, 8, 1, 0)
	source := NewRiskPrioritizedDBInputSource(repo.DB(), repo, scanID).WithMemoryLimits(512, 1024)
	source.mu.Lock()
	err := source.captureBoundLocked(ctx)
	if err != nil {
		source.mu.Unlock()
		t.Fatal(err)
	}
	source.loaded = true
	rows, err := source.nextPageRowsLocked(ctx)
	source.mu.Unlock()
	require.NoError(t, err)
	grown := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n"), bytes.Repeat([]byte{0xff}, 2048)...)
	_, err = repo.DB().NewUpdate().Model((*HTTPRecord)(nil)).Set("raw_response = ?", grown).Where("uuid = ?", f.id).Exec(ctx)
	require.NoError(t, err)
	var hydrationSQL string
	repo.DB().AddQueryHook(riskMemoryQueryHook{after: func(_ context.Context, e *bun.QueryEvent) {
		if isRiskMemoryBodyQuery(e) {
			hydrationSQL = e.Query
		}
	}})
	records, err := source.fetchBoundedPageRecords(ctx, rows)
	require.Nil(t, records)
	limitErr := requireRiskMemoryFatal(t, fmt.Errorf("page: %w", err))
	require.Equal(t, f.id, limitErr.RecordUUID)
	require.Equal(t, f.size(), limitErr.LimitBytes)
	require.Contains(t, limitErr.Kind, "grew")
	require.NotEmpty(t, hydrationSQL)
	// Independently inspect the very same SQL projection: the grown raw bytes
	// must be NULL at the database boundary, not fetched then rejected in Go.
	rawRows, err := repo.DB().QueryContext(ctx, hydrationSQL)
	require.NoError(t, err)
	defer rawRows.Close()
	columns, err := rawRows.Columns()
	require.NoError(t, err)
	require.True(t, rawRows.Next())
	values := make([]any, len(columns))
	for i := range values {
		values[i] = new(any)
	}
	require.NoError(t, rawRows.Scan(values...))
	for i, column := range columns {
		if column == "raw_request" || column == "raw_response" {
			require.Nil(t, *values[i].(*any), "guarded raw column must not hydrate the grown row")
		}
	}
	require.NoError(t, rawRows.Close())
	require.False(t, source.started)
	require.Zero(t, source.total)
	requireRiskMemoryCursorUnchanged(t, repo, scanID)
}
