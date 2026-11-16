package database

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestMergeSQLiteRawRecordCaptureFidelity(t *testing.T) {
	src, path := newFileDB(t, "fidelity-source.sqlite")
	source, ctx := NewRepository(src), context.Background()
	var ids []string
	var originals []*HTTPRecord
	for _, pair := range [][2]evidence.State{
		{evidence.StateUnknown, evidence.StateTruncated},
		{evidence.StateTruncated, evidence.StateUnknown},
		{evidence.StateUnknown, evidence.StateUnknown},
		{evidence.StateTruncated, evidence.StateTruncated},
	} {
		rr := fidelityExchange(t, evidence.ProvenanceCaptured, pair[0], pair[1])
		id, err := source.SaveRecord(ctx, rr, "baseline", "")
		require.NoError(t, err)
		record, err := source.GetRecordByUUID(ctx, id)
		require.NoError(t, err)
		ids = append(ids, id)
		originals = append(originals, record)
	}
	legacyID, err := source.SaveRecord(ctx, destinationExchange(t), RecordKindObservation, "")
	require.NoError(t, err)
	legacy, err := source.GetRecordByUUID(ctx, legacyID)
	require.NoError(t, err)
	dest := newTestDB(t)
	stats, err := MergeSQLiteFile(ctx, dest, path)
	require.NoError(t, err)
	require.Equal(t, len(ids)+1, stats.RecordsMerged)
	repo := NewRepository(dest)
	for i, id := range ids {
		record, err := repo.GetRecordByUUID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, originals[i], record, "column-discovered copies dropped fidelity or changed raw snapshots")
		rr := fidelityExchange(t, evidence.ProvenanceCaptured, record.CaptureRequestState, record.CaptureResponseState)
		assertRecordFidelity(t, record, rr)
	}
	gotLegacy, err := repo.GetRecordByUUID(ctx, legacyID)
	require.NoError(t, err)
	require.Equal(t, legacy, gotLegacy)
	rr, err := RecordToHttpRequestResponse(gotLegacy)
	require.NoError(t, err)
	require.Nil(t, rr.Evidence())
	stats, err = MergeSQLiteFile(ctx, dest, path)
	require.NoError(t, err)
	require.Zero(t, stats.RecordsMerged)
	// Even valid changed metadata must not be silently skipped by UUID dedup.
	mustExec(t, src, "UPDATE http_records SET capture_request_state = 'complete' WHERE uuid = ?", ids[0])
	_, err = MergeSQLiteFile(ctx, dest, path)
	require.ErrorIs(t, err, ErrImmutableRecordExchange)
	mustExec(t, src, "UPDATE http_records SET capture_request_state = ? WHERE uuid = ?", originals[0].CaptureRequestState, ids[0])
	// Invalid known source metadata must fail even when UUIDs already exist.
	mustExec(t, src, "UPDATE http_records SET capture_response_state = 'invalid' WHERE uuid = ?", ids[0])
	_, err = MergeSQLiteFile(ctx, dest, path)
	require.Error(t, err)
	_, err = MergeSQLiteFile(ctx, newTestDB(t), path)
	require.Error(t, err, "invalid new source rows must also fail canonical state validation")
	unchanged, err := repo.GetRecordByUUID(ctx, ids[0])
	require.NoError(t, err)
	require.Equal(t, originals[0], unchanged)
}

func TestMergeSQLiteRawRecordCaptureFidelityCollisionIdentity(t *testing.T) {
	changes := []struct {
		name   string
		change func(*HTTPRecord)
	}{
		{"request bytes", func(r *HTTPRecord) { r.RawRequest = append(bytes.Clone(r.RawRequest), 1) }},
		{"response bytes", func(r *HTTPRecord) { r.RawResponse = append(bytes.Clone(r.RawResponse), 1) }},
		{"service", func(r *HTTPRecord) { r.Hostname = "other.invalid"; r.Port++ }},
		{"response presence", func(r *HTTPRecord) { r.HasResponse = false; r.RawResponse = nil }},
		{"project", func(r *HTTPRecord) { r.ProjectUUID = "other-project" }},
		{"source time", func(r *HTTPRecord) { r.SentAt = r.SentAt.Add(time.Microsecond) }},
		{"compaction", func(r *HTTPRecord) {
			r.BodyCompaction = &BodyCompaction{Response: &CompactedBody{OriginalLength: 100, KeptLength: 0}}
		}},
		{"legacy versus known", func(r *HTTPRecord) { r.CaptureRequestState, r.CaptureResponseState = "", "" }},
	}
	for _, change := range changes {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", change.name, reverse), func(t *testing.T) {
				src, path := newFileDB(t, "fidelity-collision.sqlite")
				dest := newTestDB(t)
				source, target, ctx := NewRepository(src), NewRepository(dest), context.Background()
				var first HTTPRecord
				require.NoError(t, first.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)))
				first.ProjectUUID = DefaultProjectUUID
				second := first
				change.change(&second)
				a, b := &first, &second
				if reverse {
					a, b = b, a
				}
				_, err := source.SaveRecordsBatch(ctx, []*HTTPRecord{a})
				require.NoError(t, err)
				_, err = target.SaveRecordsBatch(ctx, []*HTTPRecord{b})
				require.NoError(t, err)
				before, err := target.GetRecordByUUID(ctx, first.UUID)
				require.NoError(t, err)
				_, err = MergeSQLiteFile(ctx, dest, path)
				require.ErrorIs(t, err, ErrImmutableRecordExchange, "equal states cannot hide different immutable snapshots")
				after, err := target.GetRecordByUUID(ctx, first.UUID)
				require.NoError(t, err)
				require.Equal(t, before, after)
			})
		}
	}
}

func TestMergeSQLiteLegacyCaptureCollisionRequiresOwnership(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%t", reverse), func(t *testing.T) {
			src, path := newFileDB(t, "legacy-collision.sqlite")
			dest, ctx := newTestDB(t), context.Background()
			source, target := NewRepository(src), NewRepository(dest)
			var first HTTPRecord
			require.NoError(t, first.FromHttpRequestResponse(destinationExchange(t)))
			first.ProjectUUID = DefaultProjectUUID
			second := first
			second.RawResponse = []byte("different historical bytes")
			a, b := &first, &second
			if reverse {
				a, b = b, a
			}
			_, err := source.SaveRecordsBatch(ctx, []*HTTPRecord{a})
			require.NoError(t, err)
			_, err = target.SaveRecordsBatch(ctx, []*HTTPRecord{b})
			require.NoError(t, err)
			before, err := target.GetRecordByUUID(ctx, first.UUID)
			require.NoError(t, err)
			stats, err := MergeSQLiteFile(ctx, dest, path)
			require.NoError(t, err)
			require.Zero(t, stats.RecordsMerged, "same-project metadata-free imports retain historical skip")
			mustExec(t, src, "UPDATE http_records SET project_uuid = 'other-project' WHERE uuid = ?", first.UUID)
			_, err = MergeSQLiteFile(ctx, dest, path)
			require.ErrorIs(t, err, ErrImmutableRecordExchange)
			after, err := target.GetRecordByUUID(ctx, first.UUID)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestMergeSQLiteCaptureEmptyResponsePresenceFailsClosed(t *testing.T) {
	for _, state := range []evidence.State{evidence.StateMissing, evidence.StateTruncated, evidence.StateUnknown} {
		t.Run(string(state), func(t *testing.T) {
			src, path := newFileDB(t, "empty-presence.sqlite")
			source, ctx := NewRepository(src), context.Background()
			var record HTTPRecord
			require.NoError(t, record.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateUnknown)))
			record.RawResponse, record.HasResponse, record.CaptureResponseState = nil, false, state
			_, err := source.SaveRecordsBatch(ctx, []*HTTPRecord{&record})
			require.NoError(t, err)
			mustExec(t, src, "UPDATE http_records SET has_response = true WHERE uuid = ?", record.UUID)
			dest := newTestDB(t)
			_, err = MergeSQLiteFile(ctx, dest, path)
			require.Error(t, err, "known source rows cannot promise a present empty response")
			count, err := dest.NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
			require.NoError(t, err)
			require.Zero(t, count)
		})
	}
}
