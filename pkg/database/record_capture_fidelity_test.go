package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func fidelityExchange(t *testing.T, provenance evidence.Provenance, request, response evidence.State) *httpmsg.HttpRequestResponse {
	t.Helper()
	base := destinationExchange(t)
	x := evidence.NewExchange("https://127.0.0.1:8443", base.Target(),
		append(base.Request().Raw(), 0, 255), append(base.Response().Raw(), 0, 255), provenance)
	x.RequestState, x.ResponseState = request, response
	// PostgreSQL raw-record timestamps have microsecond precision. Test exact
	// storage/reload time at that boundary, not a restored captured identity.
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 123456000, time.UTC)
	x.ContentHash = x.Hash()
	rr, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	return rr
}

func assertRecordFidelity(t *testing.T, record *HTTPRecord, original *httpmsg.HttpRequestResponse) {
	t.Helper()
	source := original.Evidence()
	require.Equal(t, source.RequestState, record.CaptureRequestState)
	require.Equal(t, source.ResponseState, record.CaptureResponseState)
	require.Equal(t, source.Request, record.RawRequest)
	require.Equal(t, source.Response, record.RawResponse)
	require.True(t, source.CapturedAt.Equal(record.SentAt))
	rr, err := RecordToHttpRequestResponse(record)
	require.NoError(t, err)
	x := rr.Evidence() // equivalent to the executor's supplied-input receipt path
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, source.RequestState, x.RequestState)
	require.Equal(t, source.ResponseState, x.ResponseState)
	require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
	require.NotEqual(t, source.ID, x.ID)
	require.NotEqual(t, record.UUID, x.ID)
	require.Equal(t, "https://127.0.0.1:8443", x.Service)
	require.Equal(t, source.Request, x.Request)
	require.Equal(t, source.Response, x.Response)
	require.Equal(t, source.Request, rr.Request().Raw())
	require.Equal(t, source.Response, rr.Response().Raw())
	require.True(t, record.SentAt.Equal(x.CapturedAt))
	clone := rr.Clone()
	require.Equal(t, x, clone.Evidence(), "ordinary request/response copies retain supplied fidelity")
	again, err := RecordToHttpRequestResponse(record)
	require.NoError(t, err)
	require.NotEqual(t, x.ID, again.Evidence().ID, "each reload is an independent supplied view")
}

func testRecordCaptureFidelityWrites(t *testing.T, db *DB) {
	repo, ctx := NewRepository(db), context.Background()
	writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1, BatchSize: 8, DedupCacheSize: 32})
	defer writer.Close()
	states := [][2]evidence.State{
		{evidence.StateUnknown, evidence.StateTruncated},
		{evidence.StateTruncated, evidence.StateUnknown},
		{evidence.StateUnknown, evidence.StateUnknown},
		{evidence.StateTruncated, evidence.StateTruncated},
	}
	for _, provenance := range []evidence.Provenance{evidence.ProvenanceCaptured, evidence.ProvenanceSupplied, evidence.ProvenanceCached} {
		for _, pair := range states {
			t.Run(string(provenance)+"/"+string(pair[0])+"/"+string(pair[1]), func(t *testing.T) {
				rr := fidelityExchange(t, provenance, pair[0], pair[1])
				var notified []*HTTPRecord
				repo.OnRecordSaved = func(record *HTTPRecord) { notified = append(notified, record) }
				defer func() { repo.OnRecordSaved = nil }()
				id, err := repo.SaveRecord(ctx, rr, RecordSourceIngestCLI, "")
				require.NoError(t, err)
				got, err := repo.GetRecordByUUID(ctx, id)
				require.NoError(t, err)
				assertRecordFidelity(t, got, rr)
				// A repeated supplied/cached view with the same known states can
				// reuse exact bytes, but never overwrite historical time/metadata.
				writerProject := "writer-" + string(provenance) + "-" + string(pair[0]) + "-" + string(pair[1])
				writerID, err := writer.Write(ctx, rr, RecordSourceIngestCLI, writerProject)
				require.NoError(t, err)
				writerRecord, err := repo.GetRecordByUUID(ctx, writerID)
				require.NoError(t, err)
				assertRecordFidelity(t, writerRecord, rr)
				repeat, err := writer.Write(ctx, rr, RecordSourceIngestCLI, writerProject) // cache path
				require.NoError(t, err)
				require.Equal(t, writerID, repeat)
				repeat, err = repo.SaveRecord(ctx, rr, RecordSourceIngestCLI, writerProject) // SQL path
				require.NoError(t, err)
				require.Equal(t, writerID, repeat)
				after, err := repo.GetRecordByUUID(ctx, id)
				require.NoError(t, err)
				require.Equal(t, got, after)
				projection, err := repo.GetScanRecordsByUUIDs(ctx, []string{id})
				require.NoError(t, err)
				require.Len(t, projection, 1)
				assertRecordFidelity(t, projection[0], rr)

				// High-level batch writes, model copies and callback/export JSON
				// retain both fields without deriving an execution identity.
				ids, err := repo.SaveRecordBatch(ctx, []*httpmsg.HttpRequestResponse{rr.Clone()}, RecordSourceIngestCLI, "")
				require.NoError(t, err)
				require.Len(t, ids, 1)
				record, err := repo.GetRecordByUUID(ctx, ids[0])
				require.NoError(t, err)
				assertRecordFidelity(t, record, rr)
				snapshotID, outcome, err := repo.UpsertSnapshotRecord(ctx, rr, RecordSourceIngestCLI, writerProject+"-snapshot")
				require.NoError(t, err)
				require.Equal(t, "inserted", outcome)
				snapshotRecord, err := repo.GetRecordByUUID(ctx, snapshotID)
				require.NoError(t, err)
				assertRecordFidelity(t, snapshotRecord, rr)
				require.NotEmpty(t, notified)
				for _, eventRecord := range notified {
					assertRecordFidelity(t, eventRecord, rr)
					encoded, err := json.Marshal(eventRecord)
					require.NoError(t, err)
					var copied HTTPRecord
					require.NoError(t, json.Unmarshal(encoded, &copied))
					assertRecordFidelity(t, &copied, rr)
				}
			})
		}
	}
}

func TestRecordCaptureFidelityWrites(t *testing.T) {
	testRecordCaptureFidelityWrites(t, newTestDB(t))
}

func testRecordCaptureFidelityDedup(t *testing.T, db *DB) {
	repo, ctx := NewRepository(db), context.Background()
	writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1, BatchSize: 1, DedupCacheSize: 32})
	defer writer.Close()
	ids := make(map[string]bool)
	for _, pair := range [][2]evidence.State{
		{evidence.StateUnknown, evidence.StateComplete},
		{evidence.StateTruncated, evidence.StateComplete},
		{evidence.StateComplete, evidence.StateUnknown},
		{evidence.StateComplete, evidence.StateTruncated},
		{evidence.StateComplete, evidence.StateComplete},
	} {
		rr := fidelityExchange(t, evidence.ProvenanceCaptured, pair[0], pair[1])
		id, err := writer.Write(ctx, rr, "deparos", "")
		require.NoError(t, err)
		require.False(t, ids[id], "same bytes with different fidelity merged")
		ids[id] = true
		// SQL lookup and cache lookup must agree on the state-sensitive key.
		repeat, err := repo.SaveRecord(ctx, rr, "deparos", "")
		require.NoError(t, err)
		require.Equal(t, id, repeat)
		repeat, err = writer.Write(ctx, rr, "deparos", "")
		require.NoError(t, err)
		require.Equal(t, id, repeat)
	}
	legacy := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateComplete, evidence.StateComplete).WithEvidence(nil)
	id, err := writer.Write(ctx, legacy, "deparos", "")
	require.NoError(t, err)
	require.False(t, ids[id], "legacy unknown merged with known complete")
	repeat, err := repo.SaveRecord(ctx, legacy, "deparos", "")
	require.NoError(t, err)
	require.Equal(t, id, repeat, "legacy exact comparisons keep their old behavior")
	cleanups := []func(context.Context, string) (RecordCleanupResult, error){
		func(ctx context.Context, project string) (RecordCleanupResult, error) {
			return repo.DeduplicateDeparosByNormHash(ctx, project)
		},
	}
	// The existing soft-prefix cleanup uses SQLite INSTR; this correction does
	// not expand that separate API's PostgreSQL support.
	if db.Driver() == driverSQLite {
		cleanups = append(cleanups, repo.DeduplicateSoftDeparosRecords)
	}
	for _, cleanup := range cleanups {
		result, err := cleanup(ctx, "")
		require.NoError(t, err)
		require.Zero(t, result.Deleted, "cleanup folded distinct known states")
	}
	deleted, err := repo.DeduplicateDeparosRecords(ctx, "")
	require.NoError(t, err)
	require.Zero(t, deleted)
	result, err := repo.ApplyDeparosStatusPolicy(ctx, "", DeparosStatusPolicy{KeepOnePerHost: []int{200}})
	require.NoError(t, err)
	require.Zero(t, result.Deleted)
}

func TestRecordCaptureFidelityDedup(t *testing.T) {
	testRecordCaptureFidelityDedup(t, newTestDB(t))
}

func TestRecordCaptureFidelityInvalidAndNormalized(t *testing.T) {
	testRecordCaptureFidelityInvalidAndNormalized(t, newTestDB(t))
}

func testRecordCaptureFidelityInvalidAndNormalized(t *testing.T, db *DB) {
	repo, ctx := NewRepository(db), context.Background()
	writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1})
	defer writer.Close()
	base := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateTruncated, evidence.StateUnknown)
	x := base.Evidence()
	x.RequestState = "invalid"
	x.ContentHash = x.Hash()
	bad := base.WithEvidence(x)
	_, err := repo.SaveRecord(ctx, bad, "probe", "")
	require.Error(t, err)
	_, err = writer.Write(ctx, bad, "probe", "")
	require.Error(t, err)
	ids, err := repo.SaveRecordBatch(ctx, []*httpmsg.HttpRequestResponse{bad}, "probe", "")
	require.NoError(t, err)
	require.Equal(t, []string{""}, ids, "invalid receipt must not be stored by batch conversion")

	var record HTTPRecord
	require.NoError(t, record.FromHttpRequestResponse(base))
	record.CaptureResponseState = "invalid"
	_, err = repo.SaveRecordsBatch(ctx, []*HTTPRecord{&record})
	require.Error(t, err)
	_, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&record})
	require.Error(t, err)
	rr, err := RecordToHttpRequestResponse(&record)
	require.Error(t, err)
	require.Nil(t, rr)
	// Even an existing UUID cannot hide invalid import fidelity.
	_, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&record})
	require.Error(t, err)
	storedID, err := repo.SaveRecord(ctx, base, "probe", "")
	require.NoError(t, err)
	mustExec(t, repo.DB(), "UPDATE http_records SET capture_request_state = 'invalid' WHERE uuid = ?", storedID)
	poisoned, err := repo.GetRecordByUUID(ctx, storedID)
	require.NoError(t, err)
	rr, err = RecordToHttpRequestResponse(poisoned)
	require.Error(t, err)
	require.Nil(t, rr, "malformed stored metadata must not fall back to legacy/supplied complete")

	complete := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateComplete, evidence.StateComplete)
	normalized := complete.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\n\r\nnormalized"))).WithEvidence(complete.Evidence())
	require.NoError(t, record.FromHttpRequestResponse(normalized))
	require.Equal(t, evidence.StateComplete, record.CaptureRequestState)
	require.Equal(t, evidence.StateUnknown, record.CaptureResponseState, "different live bytes cannot inherit complete")
	restored, err := RecordToHttpRequestResponse(&record)
	require.NoError(t, err)
	require.Equal(t, evidence.StateUnknown, restored.Evidence().ResponseState)
	require.Equal(t, normalized.Response().Raw(), restored.Evidence().Response)
}

func TestRecordCaptureFidelityExplicitBodyCompaction(t *testing.T) {
	db, _ := newFileDB(t, "capture-compaction.sqlite")
	repo, ctx := NewRepository(db), context.Background()
	original := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateComplete, evidence.StateComplete)
	id, err := repo.SaveRecord(ctx, original, "baseline", "")
	require.NoError(t, err)
	before, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, evidence.StateComplete, before.CaptureResponseState)
	require.NotEmpty(t, httpmsg.NewHttpResponse(before.RawResponse).Body())
	legacyID, err := repo.SaveRecord(ctx, original.WithEvidence(nil), RecordKindObservation, "legacy")
	require.NoError(t, err)
	_, err = db.CompactBodies(ctx, CompactOptions{BodyOver: 8, KeepHead: 0})
	require.NoError(t, err)
	compacted, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, compacted.BodyCompaction)
	require.NotNil(t, compacted.BodyCompaction.Request)
	require.NotNil(t, compacted.BodyCompaction.Response)
	require.Less(t, compacted.BodyCompaction.Request.KeptLength, compacted.BodyCompaction.Request.OriginalLength)
	require.Less(t, compacted.BodyCompaction.Response.KeptLength, compacted.BodyCompaction.Response.OriginalLength)
	require.Equal(t, evidence.StateComplete, compacted.CaptureRequestState)
	require.Equal(t, evidence.StateComplete, compacted.CaptureResponseState)
	require.True(t, before.SentAt.Equal(compacted.SentAt))
	require.NotEqual(t, before.RawRequest, compacted.RawRequest)
	require.NotEqual(t, before.RawResponse, compacted.RawResponse)
	projection, err := repo.GetScanRecordsByUUIDs(ctx, []string{id})
	require.NoError(t, err)
	require.Len(t, projection, 1)
	require.Empty(t, httpmsg.NewHttpResponse(compacted.RawResponse).Body(), "KeepHead=0 retains headers, not body bytes")
	responses, err := repo.GetRecordsWithResponseBody(ctx, DefaultProjectUUID, "", 10)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	require.Equal(t, compacted.BodyCompaction, responses[0].BodyCompaction)
	require.Equal(t, evidence.StateComplete, responses[0].CaptureResponseState)
	candidates, err := repo.GetReSpiderCandidates(ctx, DefaultProjectUUID, "", 10)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, compacted.BodyCompaction, candidates[0].BodyCompaction)
	require.Equal(t, evidence.StateComplete, candidates[0].CaptureResponseState)
	// Lightweight consumers load only response-side bytes. Combine those exact
	// projected fields with the request for conversion, never infer completeness
	// from headers or a retained immutable complete state after body loss.
	responseView, candidateView := *compacted, *compacted
	responseView.RawResponse = responses[0].RawResponse
	responseView.CaptureResponseState = responses[0].CaptureResponseState
	responseView.BodyCompaction = responses[0].BodyCompaction
	candidateView.RawResponse = candidates[0].RawResponse
	candidateView.CaptureResponseState = candidates[0].CaptureResponseState
	candidateView.BodyCompaction = candidates[0].BodyCompaction
	for _, record := range []*HTTPRecord{compacted, projection[0], &responseView, &candidateView} {
		requestState, responseState, err := record.EffectiveCaptureStates()
		require.NoError(t, err)
		rr, err := RecordToHttpRequestResponse(record)
		require.NoError(t, err)
		x := rr.Evidence()
		require.Equal(t, requestState, x.RequestState, "effective state lookup and supplied reload share one authority")
		require.Equal(t, responseState, x.ResponseState)
		require.Equal(t, evidence.StateTruncated, x.RequestState)
		require.Equal(t, evidence.StateTruncated, x.ResponseState)
		require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
		require.Equal(t, compacted.RawRequest, x.Request)
		require.Equal(t, compacted.RawResponse, x.Response)
		require.Equal(t, compacted.RawRequest, rr.Request().Raw())
		require.Equal(t, compacted.RawResponse, rr.Response().Raw())
	}
	legacy, err := repo.GetRecordByUUID(ctx, legacyID)
	require.NoError(t, err)
	rr, err := RecordToHttpRequestResponse(legacy)
	require.NoError(t, err)
	require.Nil(t, rr.Evidence(), "legacy compaction does not create a new receipt")
	// A marker alone is not loss: only its explicit kept/original contract
	// controls degradation, independently per side, never Content-Length.
	unchanged := *before
	unchanged.BodyCompaction = &BodyCompaction{Request: &CompactedBody{OriginalLength: 2, KeptLength: 2}}
	rr, err = RecordToHttpRequestResponse(&unchanged)
	require.NoError(t, err)
	require.Equal(t, evidence.StateComplete, rr.Evidence().RequestState)
	require.Equal(t, evidence.StateComplete, rr.Evidence().ResponseState)
	unchanged.BodyCompaction.Request.KeptLength = 1
	rr, err = RecordToHttpRequestResponse(&unchanged)
	require.NoError(t, err)
	require.Equal(t, evidence.StateTruncated, rr.Evidence().RequestState)
	require.Equal(t, evidence.StateComplete, rr.Evidence().ResponseState)
}

func TestRecordCaptureFidelityLightweightProjections(t *testing.T) {
	repo, ctx := NewRepository(newTestDB(t)), context.Background()
	rr := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)
	id, err := repo.SaveRecord(ctx, rr, "baseline", "")
	require.NoError(t, err)
	responses, err := repo.GetRecordsWithResponseBody(ctx, DefaultProjectUUID, "", 10)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	require.Equal(t, id, responses[0].UUID)
	require.Equal(t, evidence.StateUnknown, responses[0].CaptureRequestState)
	require.Equal(t, evidence.StateTruncated, responses[0].CaptureResponseState)
	require.Equal(t, rr.Response().Raw(), responses[0].RawResponse)
	candidates, err := repo.GetReSpiderCandidates(ctx, DefaultProjectUUID, "", 10)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, id, candidates[0].UUID)
	require.Equal(t, evidence.StateUnknown, candidates[0].CaptureRequestState)
	require.Equal(t, evidence.StateTruncated, candidates[0].CaptureResponseState)
	require.Equal(t, rr.Response().Raw(), candidates[0].RawResponse)
}

func TestGenericRecordCaptureFidelityCannotBeUpgraded(t *testing.T) {
	db := newTestDB(t)
	repo, ctx := NewRepository(db), context.Background()
	rr := fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)
	id, err := repo.SaveRecord(ctx, rr, "baseline", "")
	require.NoError(t, err)
	before, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	for _, column := range recordCaptureStateColumns {
		require.False(t, isGenericRecordMetadataColumn(column))
		err := UpdateGenericRecord(ctx, db, "http_records", id, map[string]interface{}{column: "complete", "risk_score": 99})
		require.ErrorIs(t, err, ErrImmutableRecordExchange)
	}
	after, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after)
	assertRecordFidelity(t, after, rr)
}

func TestRecordCaptureFidelityLegacyAndMissing(t *testing.T) {
	repo, ctx := NewRepository(newTestDB(t)), context.Background()
	for _, source := range []string{RecordKindObservation, "baseline", "probe"} {
		id, err := repo.SaveRecord(ctx, destinationExchange(t), source, "legacy-"+source)
		require.NoError(t, err)
		record, err := repo.GetRecordByUUID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, source, record.Source, "fidelity handling must not reclassify an observation or baseline")
		require.Empty(t, record.CaptureRequestState)
		require.Empty(t, record.CaptureResponseState)
		rr, err := RecordToHttpRequestResponse(record)
		require.NoError(t, err)
		require.Nil(t, rr.Evidence(), "legacy rows acquire neither fidelity nor proof roles")
	}
	// Known empty request metadata must not fabricate a GET from the row URL.
	record := &HTTPRecord{Scheme: "https", Hostname: "127.0.0.1", Port: 8443,
		URL: "https://attribution.invalid/seed", SentAt: time.Now().UTC(),
		CaptureRequestState: evidence.StateMissing, CaptureResponseState: evidence.StateUnknown}
	rr, err := RecordToHttpRequestResponse(record)
	require.NoError(t, err)
	require.Empty(t, rr.Request().Raw())
	require.Equal(t, evidence.StateMissing, rr.Evidence().RequestState)
	record.CaptureRequestState = evidence.StateComplete
	_, err = RecordToHttpRequestResponse(record)
	require.Error(t, err, "known complete without bytes must fail closed")
	record.RawRequest = []byte("GET / HTTP/1.1\r\nHost: virtual.invalid\r\n\r\n")
	record.CaptureRequestState = ""
	rr, err = RecordToHttpRequestResponse(record)
	require.NoError(t, err)
	require.Equal(t, evidence.StateUnknown, rr.Evidence().RequestState, "absent half of known fidelity cannot be completed")
	record.CaptureRequestState = evidence.StateMissing
	_, err = RecordToHttpRequestResponse(record)
	require.Error(t, err, "known missing with bytes must fail closed")
	record.CaptureRequestState = evidence.StateComplete
	record.BodyCompaction = &BodyCompaction{Request: &CompactedBody{OriginalLength: 100, KeptLength: 0}}
	rr, err = RecordToHttpRequestResponse(record)
	require.NoError(t, err)
	require.Equal(t, evidence.StateTruncated, rr.Evidence().RequestState)
	require.Equal(t, evidence.StateComplete, record.CaptureRequestState, "reload does not overwrite immutable stored metadata")
}

func TestRecordCaptureFidelityUUIDCollisionIdentity(t *testing.T) {
	changes := []struct {
		name   string
		change func(*HTTPRecord)
	}{
		{"request bytes", func(r *HTTPRecord) { r.RawRequest = append(bytes.Clone(r.RawRequest), 1) }},
		{"response bytes", func(r *HTTPRecord) { r.RawResponse = append(bytes.Clone(r.RawResponse), 1) }},
		{"scheme", func(r *HTTPRecord) { r.Scheme = "http" }},
		{"hostname", func(r *HTTPRecord) { r.Hostname = "other.invalid" }},
		{"port", func(r *HTTPRecord) { r.Port++ }},
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
			for _, inBatch := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reverse=%t/in-batch=%t", change.name, reverse, inBatch), func(t *testing.T) {
					repo, ctx := NewRepository(newTestDB(t)), context.Background()
					var first HTTPRecord
					require.NoError(t, first.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)))
					first.ProjectUUID = DefaultProjectUUID
					second := first
					change.change(&second)
					require.NoError(t, first.ValidateCaptureStates())
					require.NoError(t, second.ValidateCaptureStates())
					a, b := &first, &second
					if reverse {
						a, b = b, a
					}
					var before *HTTPRecord
					if !inBatch {
						_, err := repo.SaveRecordsBatch(ctx, []*HTTPRecord{a})
						require.NoError(t, err)
						before, err = repo.GetRecordByUUID(ctx, first.UUID)
						require.NoError(t, err)
					}
					var events []*HTTPRecord
					repo.OnRecordSaved = func(r *HTTPRecord) { events = append(events, r) }
					batch := []*HTTPRecord{b}
					if inBatch {
						batch = []*HTTPRecord{a, b}
					}
					ids, err := repo.SaveRecordsBatchSkipExisting(ctx, batch)
					require.ErrorIs(t, err, ErrImmutableRecordExchange)
					require.Empty(t, ids)
					require.Empty(t, events, "the first SQL row and last callback candidate must never disagree")
					if inBatch {
						count, err := repo.DB().NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
						require.NoError(t, err)
						require.Zero(t, count, "conflicting duplicates roll back the first insert too")
					} else {
						got, err := repo.GetRecordByUUID(ctx, first.UUID)
						require.NoError(t, err)
						require.Equal(t, before, got)
					}
				})
			}
		}
	}
}

func TestRecordCaptureFidelitySameBatchExactCallbackReadback(t *testing.T) {
	repo, ctx := NewRepository(newTestDB(t)), context.Background()
	var first HTTPRecord
	require.NoError(t, first.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateUnknown, evidence.StateTruncated)))
	first.ProjectUUID = DefaultProjectUUID
	second := first
	// Enrichment is not receipt identity and cannot replace exact raw bytes.
	second.RequestHash, second.ResponseHash = "untrusted-import-hash", "untrusted-import-hash"
	second.Method, second.Path = "guessed-method", "guessed-path"
	var events []*HTTPRecord
	repo.OnRecordSaved = func(r *HTTPRecord) { events = append(events, r) }
	ids, err := repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&first, &second})
	require.NoError(t, err)
	require.Equal(t, []string{first.UUID}, ids)
	require.Len(t, events, 1)
	got, err := repo.GetRecordByUUID(ctx, first.UUID)
	require.NoError(t, err)
	require.Equal(t, first.RequestHash, got.RequestHash, "SQL keeps the first row, not the last candidate")
	require.True(t, recordCaptureIdentityEqual(got, events[0]), "callback and readback identify the exact same known snapshot")
	ids, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&second})
	require.NoError(t, err)
	require.Empty(t, ids)
	require.Len(t, events, 1)
}

func TestRecordCaptureFidelityLegacyUUIDSkipStillRequiresOwnership(t *testing.T) {
	repo, ctx := NewRepository(newTestDB(t)), context.Background()
	var original HTTPRecord
	require.NoError(t, original.FromHttpRequestResponse(destinationExchange(t)))
	original.ProjectUUID = DefaultProjectUUID
	_, err := repo.SaveRecordsBatch(ctx, []*HTTPRecord{&original})
	require.NoError(t, err)
	before, err := repo.GetRecordByUUID(ctx, original.UUID)
	require.NoError(t, err)
	conflict := *before
	conflict.RawResponse = []byte("historical import skipped despite different bytes")
	ids, err := repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&conflict})
	require.NoError(t, err)
	require.Empty(t, ids)
	conflict.ProjectUUID = "other-project"
	_, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&conflict})
	require.ErrorIs(t, err, ErrImmutableRecordExchange)
	got, err := repo.GetRecordByUUID(ctx, original.UUID)
	require.NoError(t, err)
	require.Equal(t, before, got)
	for _, reverse := range []bool{false, true} {
		repo := NewRepository(newTestDB(t))
		a, b := before, &conflict
		if reverse {
			a, b = b, a
		}
		_, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{a, b})
		require.ErrorIs(t, err, ErrImmutableRecordExchange)
		count, err := repo.DB().NewSelect().Model((*HTTPRecord)(nil)).Count(ctx)
		require.NoError(t, err)
		require.Zero(t, count)
	}
}

func TestRecordCaptureFidelityEmptyResponsePresence(t *testing.T) {
	repo, ctx := NewRepository(newTestDB(t)), context.Background()
	writer := NewRecordWriter(repo, RecordWriterConfig{Shards: 1, BatchSize: 1, DedupCacheSize: 8})
	defer writer.Close()
	for _, state := range []evidence.State{evidence.StateMissing, evidence.StateTruncated, evidence.StateUnknown} {
		t.Run(string(state), func(t *testing.T) {
			base := destinationExchange(t)
			x := evidence.NewExchange("https://127.0.0.1:8443", base.Target(), base.Request().Raw(), nil, evidence.ProvenanceCaptured)
			x.ResponseState = state
			x.ContentHash = x.Hash()
			rr, err := httpmsg.FromEvidenceExchange(x)
			require.NoError(t, err)
			require.False(t, rr.HasResponse())
			var record HTTPRecord
			require.NoError(t, record.FromHttpRequestResponse(rr))
			require.False(t, record.HasResponse)
			require.Empty(t, record.ResponseHash)
			for _, save := range []func() (string, error){
				func() (string, error) { return repo.SaveRecord(ctx, rr, "baseline", string(state)) },
				func() (string, error) { return writer.Write(ctx, rr, "baseline", "writer-"+string(state)) },
			} {
				id, err := save()
				require.NoError(t, err)
				stored, err := repo.GetRecordByUUID(ctx, id)
				require.NoError(t, err)
				require.False(t, stored.HasResponse)
				reloaded, err := RecordToHttpRequestResponse(stored)
				require.NoError(t, err)
				require.False(t, reloaded.HasResponse())
				require.Equal(t, state, reloaded.Evidence().ResponseState)
				require.Equal(t, x.Request, reloaded.Request().Raw())
				require.Empty(t, reloaded.Evidence().Response)
			}
			// Import metadata must not promise presence that supplied reload loses.
			record.HasResponse = true
			require.Error(t, record.ValidateCaptureStates())
			_, err = RecordToHttpRequestResponse(&record)
			require.Error(t, err)
			_, err = repo.SaveRecordsBatch(ctx, []*HTTPRecord{&record})
			require.Error(t, err)
			_, err = repo.SaveRecordsBatchSkipExisting(ctx, []*HTTPRecord{&record})
			require.Error(t, err)
			// Reject producers BEFORE the writer can construct presence or an
			// empty-byte hash, including its repeat/cache admission path.
			emptyObject := rr.WithResponse(httpmsg.NewHttpResponse(nil)).WithEvidence(x)
			require.True(t, emptyObject.HasResponse())
			require.Error(t, record.FromHttpRequestResponse(emptyObject))
			_, err = repo.SaveRecord(ctx, emptyObject, "baseline", string(state))
			require.Error(t, err)
			_, err = writer.Write(ctx, emptyObject, "baseline", "writer-"+string(state))
			require.Error(t, err)
		})
	}
}

func TestRecordEffectiveCaptureStatesMatchesSuppliedReload(t *testing.T) {
	var original HTTPRecord
	require.NoError(t, original.FromHttpRequestResponse(fidelityExchange(t, evidence.ProvenanceCaptured, evidence.StateComplete, evidence.StateComplete)))
	for _, marker := range []*BodyCompaction{
		nil,
		{Request: &CompactedBody{OriginalLength: 2, KeptLength: 2}},
		{Request: &CompactedBody{OriginalLength: 2, KeptLength: 0}},
		{Response: &CompactedBody{OriginalLength: 2, KeptLength: 0}},
		{Request: &CompactedBody{OriginalLength: 2, KeptLength: 0}, Response: &CompactedBody{OriginalLength: 2, KeptLength: 0}},
	} {
		record := original
		record.BodyCompaction = marker
		request, response, err := record.EffectiveCaptureStates()
		require.NoError(t, err)
		rr, err := RecordToHttpRequestResponse(&record)
		require.NoError(t, err)
		require.Equal(t, request, rr.Evidence().RequestState)
		require.Equal(t, response, rr.Evidence().ResponseState)
		require.Equal(t, evidence.StateComplete, record.CaptureRequestState)
		require.Equal(t, evidence.StateComplete, record.CaptureResponseState)
		require.Equal(t, original.RawRequest, record.RawRequest)
		require.Equal(t, original.RawResponse, record.RawResponse)
	}
	legacy := original
	legacy.CaptureRequestState, legacy.CaptureResponseState = "", ""
	legacy.BodyCompaction = &BodyCompaction{Response: &CompactedBody{OriginalLength: 2, KeptLength: 0}}
	request, response, err := legacy.EffectiveCaptureStates()
	require.NoError(t, err)
	require.Equal(t, evidence.StateUnknown, request)
	require.Equal(t, evidence.StateUnknown, response)
	original.CaptureResponseState = "invalid"
	_, _, err = original.EffectiveCaptureStates()
	require.Error(t, err)
}
