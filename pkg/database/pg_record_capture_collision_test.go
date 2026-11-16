package database

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// Exercise PostgreSQL's actual transactional importer as well as SQLite: a
// skipped same-ID candidate must never emit bytes not committed by the database.
func TestPg_RecordCaptureFidelityCollisionRollback(t *testing.T) {
	for _, change := range []string{"bytes", "project", "legacy"} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", change, reverse), func(t *testing.T) {
				db := openPGTestDB(t)
				repo, ctx := NewRepository(db), context.Background()
				var first HTTPRecord
				require.NoError(t, first.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)))
				first.ProjectUUID = DefaultProjectUUID
				second := first
				switch change {
				case "bytes":
					second.RawResponse = append(bytes.Clone(second.RawResponse), 1)
				case "project":
					second.ProjectUUID = "other-project"
				case "legacy":
					second.CaptureRequestState, second.CaptureResponseState = "", ""
				}
				a, b := &first, &second
				if reverse {
					a, b = b, a
				}
				callbacks := 0
				repo.OnRecordSaved = func(*HTTPRecord) { callbacks++ }
				ids, err := repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{a, b})
				require.ErrorIs(t, err, ErrImmutableRecordExchange)
				require.Empty(t, ids)
				require.Zero(t, callbacks)
				count, err := db.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
				require.NoError(t, err)
				require.Zero(t, count)
				ids, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{a})
				require.NoError(t, err)
				require.Equal(t, []string{a.UUID}, ids)
				before, err := repo.GetRecordByUUID(ctx, a.UUID)
				require.NoError(t, err)
				ids, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{b})
				require.ErrorIs(t, err, ErrImmutableRecordExchange)
				require.Empty(t, ids)
				require.Equal(t, 1, callbacks)
				after, err := repo.GetRecordByUUID(ctx, a.UUID)
				require.NoError(t, err)
				require.Equal(t, before, after)
			})
		}
	}
}

func TestPg_RecordCaptureFidelityRejectsEmptyResponsePresence(t *testing.T) {
	repo, ctx := NewRepository(openPGTestDB(t)), context.Background()
	for _, state := range []evidence.State{evidence.StateMissing, evidence.StateUnknown, evidence.StateTruncated} {
		t.Run(string(state), func(t *testing.T) {
			var record HTTPRecord
			require.NoError(t, record.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)))
			record.ProjectUUID = DefaultProjectUUID
			record.RawResponse = nil
			record.CaptureResponseState = state
			_, err := repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&record})
			require.Error(t, err, "present-empty metadata is rejected, not silently reloaded as absent")
			record.HasResponse = false
			record.ResponseHash = ""
			ids, err := repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&record})
			require.NoError(t, err)
			require.Equal(t, []string{record.UUID}, ids)
			stored, err := repo.GetRecordByUUID(ctx, record.UUID)
			require.NoError(t, err)
			reloaded, err := RecordToHttpRequestResponse(stored)
			require.NoError(t, err)
			require.False(t, reloaded.HasResponse())
			require.Equal(t, state, reloaded.Evidence().ResponseState)
		})
	}
}
