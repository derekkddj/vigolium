package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Block delivery to the second caller, not the database. Receiving a terminal
// result must imply that the batch's terminal persistence counts are visible,
// even while another caller or best-effort adoption has not completed.
func TestRecordWriterTerminalMetricsPublishedBeforeResults(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "committed"
		if failed {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			repo := NewRepository(newTestDB(t))
			cfg := RecordWriterConfig{Shards: 1, DedupCacheSize: -1}
			if failed {
				cfg.insertBatch = func(context.Context, []*HTTPRecord) error { return errors.New("intentional insert failure") }
			}
			writer := NewRecordWriter(repo, cfg)
			defer writer.Close()
			first, last := make(chan WriteResult, 1), make(chan WriteResult)
			batch := make([]writeRequest, 0, 2)
			for i, result := range []chan WriteResult{first, last} {
				record := toRecord(t, makeTestRequest(i), "publication")
				batch = append(batch, writeRequest{record: record, result: result, dedupKey: recordDedupKey(record)})
			}
			done := make(chan struct{})
			go func() { writer.flush(context.Background(), batch); close(done) }()
			defer func() {
				select {
				case <-last:
				case <-time.After(5 * time.Second):
					t.Error("flush did not deliver its final result")
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("flush did not finish")
				}
			}()
			select {
			case result := <-first:
				if failed {
					require.Error(t, result.Err)
				} else {
					require.NoError(t, result.Err)
					require.NotEmpty(t, result.UUID)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("flush did not deliver its first result")
			}
			metrics := writer.Metrics()
			if failed {
				require.Equal(t, int64(2), metrics.FlushFailed)
				require.Zero(t, metrics.Flushed)
			} else {
				require.Equal(t, int64(2), metrics.Flushed)
				require.Zero(t, metrics.FlushFailed)
			}
		})
	}
}
