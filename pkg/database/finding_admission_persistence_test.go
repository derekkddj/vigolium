package database

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestFindingAdmissionPersistenceRejectedIsNotAccepted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget int64
		cancel bool
		event  *output.ResultEvent
	}{
		{name: "oversize", budget: 1, event: &output.ResultEvent{ModuleID: "oversize"}},
		{name: "cancelled", cancel: true, event: &output.ResultEvent{ModuleID: "cancelled"}},
		{name: "invalid event"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := NewFindingWriter(nil, FindingWriterConfig{MaxPendingBytes: tc.budget})
			t.Cleanup(w.Close)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}

			require.Error(t, w.Save(ctx, tc.event, nil, "scan", "project"))
			o := w.Shutdown()
			assert.Equal(t, int64(1), o.Rejected)
			assert.Zero(t, o.Accepted, "a refused finding was never accepted")
			assert.Zero(t, o.Committed)
			assert.Zero(t, o.Failed, "Failed is reserved for accepted writes")
			assert.Zero(t, o.Unknown)
			assert.False(t, o.Clean(), "rejection must not become warning-only persistence loss")
			assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
			assert.Equal(t, o, w.Shutdown(), "rejections are part of the once-only outcome")
			assert.Equal(t, o.Rejected, w.Metrics().AdmissionFailed)
		})
	}
}

func TestFindingAdmissionPersistenceMergeAndJSON(t *testing.T) {
	o := PersistenceOutcome{Writer: PersistenceWriterFindings, Rejected: 2}
	o.Merge(PersistenceOutcome{Writer: PersistenceWriterFindings, Accepted: 3, Committed: 2, Failed: 1})
	o.Merge(PersistenceOutcome{Writer: PersistenceWriterRecords, Accepted: 4, Committed: 3, Unknown: 1})

	assert.Equal(t, PersistenceWriterMixed, o.Writer)
	assert.Equal(t, int64(2), o.Rejected)
	assert.Equal(t, int64(7), o.Accepted)
	assert.Equal(t, int64(5), o.Committed)
	assert.Equal(t, int64(1), o.Failed)
	assert.Equal(t, int64(1), o.Unknown)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
	assert.False(t, o.Clean())

	raw, err := json.Marshal(o)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"rejected":2`)
	var decoded PersistenceOutcome
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, o, decoded)

	raw, err = json.Marshal(PersistenceOutcome{Writer: PersistenceWriterFindings, Accepted: 1, Committed: 1})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"rejected"`, "clean existing JSON stays unchanged")
}

func TestFindingAdmissionPersistenceMixedFailuresCountedOnce(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	w := NewFindingWriter(nil, FindingWriterConfig{
		BufferSize:    1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		FlushTimeout:  2 * time.Second,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			results := make([]FindingSaveResult, len(writes))
			switch writes[0].Event.ModuleID {
			case "async-failure":
				close(entered)
				<-release
				results[0].Err = errors.New("async failure")
			case "inline-failure":
				results[0].Err = errors.New("inline failure")
			}
			return results
		},
	})
	t.Cleanup(func() {
		unblock()
		w.Close()
	})
	ctx := context.Background()
	save := func(id string) error {
		return w.Save(ctx, &output.ResultEvent{ModuleID: id}, nil, "scan", "project")
	}
	require.NoError(t, save("async-failure"))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("async save did not enter the barrier")
	}
	require.NoError(t, save("queued-success")) // occupies the one remaining queue slot
	require.Error(t, save("inline-failure"))
	require.NoError(t, save("inline-success"))
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, w.Save(cancelled, &output.ResultEvent{ModuleID: "rejected"}, nil, "scan", "project"))
	unblock()

	o := w.Shutdown()
	assert.Equal(t, int64(4), o.Accepted)
	assert.Equal(t, int64(2), o.Committed, "one queued and one completed inline save")
	assert.Equal(t, int64(2), o.Failed, "one inline and one async failure, not Save errors plus failures")
	assert.Equal(t, int64(1), o.Rejected)
	assert.Zero(t, o.Unknown)
	assert.False(t, o.TimedOut)
	assert.False(t, o.Clean())
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
	m := w.Metrics()
	assert.Equal(t, int64(1), m.Errors)
	assert.Equal(t, int64(2), m.Inline)
	assert.Equal(t, int64(1), m.InlineFailed)
	assert.Equal(t, int64(1), m.AdmissionFailed)
	assert.Equal(t, o, w.Shutdown())
}

func TestFindingAdmissionPersistencePendingInlineIsNotCommitted(t *testing.T) {
	asyncEntered, inlineEntered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	w := NewFindingWriter(nil, FindingWriterConfig{
		BufferSize:    1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		FlushTimeout:  50 * time.Millisecond,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			switch writes[0].Event.ModuleID {
			case "async":
				close(asyncEntered)
			case "inline":
				close(inlineEntered)
			}
			<-release // deliberately ignores the persistence deadline
			return make([]FindingSaveResult, len(writes))
		},
	})
	t.Cleanup(func() {
		unblock()
		w.Close()
		require.True(t, waitBounded(&w.wg, 2*time.Second), "released flush must exit")
	})
	ctx := context.Background()
	require.NoError(t, w.Save(ctx, &output.ResultEvent{ModuleID: "async"}, nil, "scan", "project"))
	select {
	case <-asyncEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("async save did not enter the barrier")
	}
	require.NoError(t, w.Save(ctx, &output.ResultEvent{ModuleID: "queued"}, nil, "scan", "project"))
	inlineDone := make(chan error, 1)
	go func() {
		inlineDone <- w.Save(ctx, &output.ResultEvent{ModuleID: "inline"}, nil, "scan", "project")
	}()
	select {
	case <-inlineEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("inline save did not enter the barrier")
	}

	o := w.Shutdown()
	assert.True(t, o.TimedOut)
	assert.Equal(t, int64(3), o.Accepted)
	assert.Zero(t, o.Committed, "an unfinished inline attempt is not committed")
	assert.Zero(t, o.Failed)
	assert.Zero(t, o.Rejected)
	assert.Equal(t, int64(3), o.Unknown)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
	assert.False(t, o.Clean())
	unblock()
	select {
	case err := <-inlineDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("released inline save did not exit")
	}
	assert.Equal(t, o, w.Shutdown(), "late commits cannot rewrite the frozen shutdown report")
}
