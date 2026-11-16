package core

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestFindingAdmissionPersistenceDirectFailureIsReported(t *testing.T) {
	e, db := newRepoExecutor(t)
	var emitted int
	onEvent := func(*output.ResultEvent) { emitted++ }
	e.cfg.OnResult = onEvent
	e.cfg.OnCandidate = onEvent
	e.cfg.OnObservation = onEvent
	require.NoError(t, db.Close())

	result := e.emitResult(context.Background(), &output.ResultEvent{
		ModuleID: "direct-persistence", URL: "https://example.test/direct",
	}, nil, nil)
	require.NotNil(t, result.event, "persistence failure must not suppress live output")
	assert.Equal(t, 1, emitted)
	rep := e.Report()
	assert.Equal(t, int64(1), rep.FindingStoreFailed)
	assert.False(t, rep.Clean(), "a direct finding save failure cannot remain warning-only")
	assert.Zero(t, e.StoreFailed(), "finding saves must not inflate primary-input record failures")
}

func TestFindingAdmissionPersistenceWriterRejectionIsNotDirectFailure(t *testing.T) {
	e, _ := newRepoExecutor(t)
	w := database.NewFindingWriter(e.repo, database.FindingWriterConfig{MaxPendingBytes: 1})
	t.Cleanup(w.Close)
	e.findingWriter = w

	result := e.emitResult(context.Background(), &output.ResultEvent{
		ModuleID: "writer-admission", URL: "https://example.test/rejected",
	}, nil, nil)
	require.NotNil(t, result.event, "live output remains available for a rejected finding")
	assert.Zero(t, e.Report().FindingStoreFailed, "writer owns rejected and failed attempts")
	o := w.Shutdown()
	assert.Equal(t, int64(1), o.Rejected)
	assert.Zero(t, o.Accepted)
	assert.Zero(t, o.Failed)
	assert.False(t, o.Clean())
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
}

func TestFindingAdmissionPersistenceAsyncFailureIsNotDirectFailure(t *testing.T) {
	e, db := newRepoExecutor(t)
	w := database.NewFindingWriter(e.repo, database.FindingWriterConfig{
		BatchSize: 1, FlushInterval: time.Hour,
	})
	t.Cleanup(w.Close)
	e.findingWriter = w
	require.NoError(t, db.Close())

	e.emitResult(context.Background(), &output.ResultEvent{
		ModuleID: "writer-async", URL: "https://example.test/async",
	}, nil, nil)
	o := w.Shutdown()
	assert.Equal(t, int64(1), o.Accepted)
	assert.Equal(t, int64(1), o.Failed)
	assert.Zero(t, o.Rejected)
	assert.Zero(t, o.Committed)
	assert.Zero(t, o.Unknown)
	assert.Zero(t, e.Report().FindingStoreFailed, "async loss is counted only at writer shutdown")
}

func TestFindingAdmissionPersistenceDirectCounterIsConcurrent(t *testing.T) {
	e, db := newRepoExecutor(t)
	require.NoError(t, db.Close())
	const workers = 8
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.emitResult(context.Background(), &output.ResultEvent{
				ModuleID: "direct-concurrent", URL: "https://example.test/concurrent",
			}, nil, nil)
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(workers), e.Report().FindingStoreFailed,
		"count persistence attempts, including failed dedup/occurrence merges")
}

func TestFindingAdmissionPersistenceReportIsPerExecute(t *testing.T) {
	e := NewExecutor(ExecutorConfig{
		Workers: 1, DisableFeedback: true, SkipBaseline: true,
	}, &terminalTestSource{err: io.EOF}, nil, nil)
	e.findingStoreFailed.Add(2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := e.Execute(ctx)
	require.NoError(t, err)
	assert.Zero(t, e.Report().FindingStoreFailed, "prior attempts are outside this run")
	e.findingStoreFailed.Add(1)
	assert.Equal(t, int64(1), e.Report().FindingStoreFailed)
	assert.False(t, e.Report().Clean())
	_, err = e.Execute(ctx)
	require.NoError(t, err)
	assert.Zero(t, e.Report().FindingStoreFailed, "reused executors reset the report baseline")
	assert.True(t, e.Report().Clean())
}
