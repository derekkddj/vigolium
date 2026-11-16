package dbimport

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func importFidelityRecord(t *testing.T, repo *database.Repository, request, response evidence.State) (*database.HTTPRecord, *evidence.Exchange) {
	t.Helper()
	x := evidence.NewExchange("https://127.0.0.1:8443", "https://attribution.invalid/assertion",
		[]byte("POST http://absolute.invalid/probe HTTP/1.1\r\nHost: virtual.invalid\r\nContent-Length: 999\r\n\r\n\x00\xffshort"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n\x00\xffprefix"), evidence.ProvenanceCaptured)
	x.RequestState, x.ResponseState = request, response
	// Bun stores raw-record timestamps at microsecond precision, including
	// SQLite. Exercise exact source time at the supported storage boundary.
	x.CapturedAt = time.Date(2026, 11, 3, 1, 2, 3, 123456000, time.UTC)
	x.ContentHash = x.Hash()
	rr, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	id, err := repo.SaveRecord(context.Background(), rr, "baseline", "")
	require.NoError(t, err)
	record, err := repo.GetRecordByUUID(context.Background(), id)
	require.NoError(t, err)
	return record, x
}

func assertImportedFidelityRecord(t *testing.T, expected, actual *database.HTTPRecord) {
	t.Helper()
	require.Equal(t, expected.RawRequest, actual.RawRequest)
	require.Equal(t, expected.RawResponse, actual.RawResponse)
	require.Equal(t, expected.CaptureRequestState, actual.CaptureRequestState)
	require.Equal(t, expected.CaptureResponseState, actual.CaptureResponseState)
	require.Equal(t, expected.HasResponse, actual.HasResponse)
	require.Equal(t, expected.ProjectUUID, actual.ProjectUUID)
	require.Equal(t, expected.Source, actual.Source)
	require.True(t, expected.SentAt.Equal(actual.SentAt), "immutable source capture time changed")
	require.True(t, expected.ReceivedAt.Equal(actual.ReceivedAt))
	require.True(t, expected.CreatedAt.Equal(actual.CreatedAt))
	// JSONL round trips can turn SQLite's UTC default timestamp into an
	// anonymous zero-offset location. Compare instants, not time.Location's
	// private representation; every other model field must still match exactly.
	want, got := *expected, *actual
	want.SentAt, got.SentAt = want.SentAt.UTC(), got.SentAt.UTC()
	want.ReceivedAt, got.ReceivedAt = want.ReceivedAt.UTC(), got.ReceivedAt.UTC()
	want.CreatedAt, got.CreatedAt = want.CreatedAt.UTC(), got.CreatedAt.UTC()
	require.Equal(t, want, got)
}

func TestImportJSONLRawRecordCaptureFidelity(t *testing.T) {
	for _, pair := range [][2]evidence.State{
		{evidence.StateUnknown, evidence.StateTruncated},
		{evidence.StateTruncated, evidence.StateUnknown},
		{evidence.StateTruncated, evidence.StateTruncated},
		{evidence.StateUnknown, evidence.StateUnknown},
	} {
		t.Run(string(pair[0])+"/"+string(pair[1]), func(t *testing.T) {
			original, capture := importFidelityRecord(t, newTestRepo(t), pair[0], pair[1])
			line := jsonlEnvelope(t, "http_record", original)
			require.Contains(t, line, `"capture_request_state"`)
			require.Contains(t, line, `"capture_response_state"`)
			repo, ctx := newTestRepo(t), context.Background()
			var notified *database.HTTPRecord
			repo.OnRecordSaved = func(record *database.HTTPRecord) { notified = record }
			result, err := ImportJSONL(ctx, repo, strings.NewReader(line), "", Options{})
			require.NoError(t, err)
			require.Equal(t, 1, result.RecordsImported)
			require.NotNil(t, notified)
			got, err := repo.GetRecordByUUID(ctx, original.UUID)
			require.NoError(t, err)
			assertImportedFidelityRecord(t, original, got)
			assertImportedFidelityRecord(t, got, notified)
			require.Equal(t, "baseline", got.Source)
			require.Equal(t, pair[0], notified.CaptureRequestState)
			require.Equal(t, pair[1], notified.CaptureResponseState)
			rr, err := database.RecordToHttpRequestResponse(got)
			require.NoError(t, err)
			x := rr.Evidence()
			require.NotNil(t, x)
			require.NoError(t, x.Validate())
			require.Equal(t, pair[0], x.RequestState)
			require.Equal(t, pair[1], x.ResponseState)
			require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
			require.NotEqual(t, capture.ID, x.ID)
			require.NotEqual(t, got.UUID, x.ID)
			require.Equal(t, capture.Service, x.Service)
			require.Equal(t, capture.Request, x.Request)
			require.Equal(t, capture.Response, x.Response)
			require.True(t, capture.CapturedAt.Equal(x.CapturedAt))
			// An overlapping import keeps historical metadata and emits no event.
			notified = nil
			result, err = ImportJSONL(ctx, repo, strings.NewReader(line), "", Options{})
			require.NoError(t, err)
			require.Zero(t, result.RecordsImported)
			require.Equal(t, 1, result.RecordsSkippedDuplicate)
			require.Nil(t, notified)
			got, err = repo.GetRecordByUUID(ctx, original.UUID)
			require.NoError(t, err)
			assertImportedFidelityRecord(t, original, got)
			conflict := *original
			conflict.CaptureRequestState = evidence.StateComplete
			_, err = ImportJSONL(ctx, repo, strings.NewReader(jsonlEnvelope(t, "http_record", &conflict)), "", Options{})
			require.ErrorIs(t, err, database.ErrImmutableRecordExchange, "valid but different fidelity cannot be silently skipped on UUID conflict")
			got, err = repo.GetRecordByUUID(ctx, original.UUID)
			require.NoError(t, err)
			assertImportedFidelityRecord(t, original, got)
		})
	}
}

func TestImportJSONLRawRecordCaptureFidelityInvalidFailsClosed(t *testing.T) {
	for _, change := range []func(*database.HTTPRecord){
		func(r *database.HTTPRecord) { r.CaptureRequestState = "invalid" },
		func(r *database.HTTPRecord) { r.CaptureResponseState = "invalid" },
		func(r *database.HTTPRecord) { r.CaptureRequestState = evidence.StateComplete; r.RawRequest = nil },
		func(r *database.HTTPRecord) { r.CaptureResponseState = evidence.StateMissing },
		func(r *database.HTTPRecord) { r.HasResponse = false },
		func(r *database.HTTPRecord) { r.RawResponse = nil; r.CaptureResponseState = evidence.StateMissing },
		func(r *database.HTTPRecord) { r.RawResponse = nil; r.CaptureResponseState = evidence.StateTruncated },
		func(r *database.HTTPRecord) { r.RawResponse = nil; r.CaptureResponseState = evidence.StateUnknown },
	} {
		source, _ := importFidelityRecord(t, newTestRepo(t), evidence.StateUnknown, evidence.StateTruncated)
		original := *source
		change(source)
		line := jsonlEnvelope(t, "http_record", source)
		repo, ctx := newTestRepo(t), context.Background()
		_, err := ImportJSONL(ctx, repo, strings.NewReader(line), "", Options{})
		require.Error(t, err)
		count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
		require.NoError(t, err)
		require.Zero(t, count)
		// DO NOTHING on UUID conflict must not hide invalid fidelity either.
		_, err = repo.SaveRecordsBatch(ctx, []*database.HTTPRecord{&original})
		require.NoError(t, err)
		_, err = ImportJSONL(ctx, repo, strings.NewReader(line), "", Options{})
		require.Error(t, err)
		got, err := repo.GetRecordByUUID(ctx, original.UUID)
		require.NoError(t, err)
		assertImportedFidelityRecord(t, &original, got)
	}
}

func TestImportJSONLLegacyRawRecordDoesNotInferCapture(t *testing.T) {
	record, _ := importFidelityRecord(t, newTestRepo(t), evidence.StateUnknown, evidence.StateTruncated)
	record.CaptureRequestState, record.CaptureResponseState = "", ""
	record.Source = database.RecordKindObservation
	line := jsonlEnvelope(t, "http_record", record)
	require.NotContains(t, line, `"capture_request_state"`)
	require.NotContains(t, line, `"capture_response_state"`)
	repo, ctx := newTestRepo(t), context.Background()
	result, err := ImportJSONL(ctx, repo, strings.NewReader(line), "", Options{})
	require.NoError(t, err)
	require.Equal(t, 1, result.RecordsImported)
	got, err := repo.GetRecordByUUID(ctx, record.UUID)
	require.NoError(t, err)
	assertImportedFidelityRecord(t, record, got)
	require.Equal(t, database.RecordKindObservation, got.Source)
	rr, err := database.RecordToHttpRequestResponse(got)
	require.NoError(t, err)
	require.Nil(t, rr.Evidence(), "legacy raw JSON cannot infer a wire capture or proof role")
}

func TestImportJSONLRawRecordCaptureFidelityCollisionIdentity(t *testing.T) {
	changes := []struct {
		name   string
		change func(*database.HTTPRecord)
	}{
		{"request bytes", func(r *database.HTTPRecord) { r.RawRequest = append(bytes.Clone(r.RawRequest), 1) }},
		{"response bytes", func(r *database.HTTPRecord) { r.RawResponse = append(bytes.Clone(r.RawResponse), 1) }},
		{"service", func(r *database.HTTPRecord) { r.Hostname = "other.invalid"; r.Port++ }},
		{"response presence", func(r *database.HTTPRecord) { r.HasResponse = false; r.RawResponse = nil }},
		{"project", func(r *database.HTTPRecord) { r.ProjectUUID = "other-project" }},
		{"source time", func(r *database.HTTPRecord) { r.SentAt = r.SentAt.Add(time.Microsecond) }},
		{"legacy versus known", func(r *database.HTTPRecord) { r.CaptureRequestState, r.CaptureResponseState = "", "" }},
	}
	for _, change := range changes {
		for _, reverse := range []bool{false, true} {
			for _, inBatch := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/reverse=%t/in-batch=%t", change.name, reverse, inBatch), func(t *testing.T) {
					first, _ := importFidelityRecord(t, newTestRepo(t), evidence.StateUnknown, evidence.StateTruncated)
					second := *first
					change.change(&second)
					a, b := first, &second
					if reverse {
						a, b = b, a
					}
					repo, ctx := newTestRepo(t), context.Background()
					opts := Options{PreserveProjectUUID: true}
					var before *database.HTTPRecord
					if !inBatch {
						_, err := ImportJSONL(ctx, repo, strings.NewReader(jsonlEnvelope(t, "http_record", a)), "", opts)
						require.NoError(t, err)
						before, err = repo.GetRecordByUUID(ctx, first.UUID)
						require.NoError(t, err)
					}
					var events []*database.HTTPRecord
					repo.OnRecordSaved = func(r *database.HTTPRecord) { events = append(events, r) }
					input := jsonlEnvelope(t, "http_record", b)
					if inBatch {
						input = jsonlEnvelope(t, "http_record", a) + "\n" + input
					}
					_, err := ImportJSONL(ctx, repo, strings.NewReader(input), "", opts)
					require.ErrorIs(t, err, database.ErrImmutableRecordExchange)
					require.Empty(t, events, "never emit the last in-batch candidate for the first SQL row")
					if inBatch {
						count, err := repo.DB().NewSelect().Model((*database.HTTPRecord)(nil)).Count(ctx)
						require.NoError(t, err)
						require.Zero(t, count)
					} else {
						got, err := repo.GetRecordByUUID(ctx, first.UUID)
						require.NoError(t, err)
						assertImportedFidelityRecord(t, before, got)
					}
				})
			}
		}
	}
}

func TestImportJSONLRawRecordCaptureFidelityEmptyAbsentResponse(t *testing.T) {
	for _, state := range []evidence.State{evidence.StateMissing, evidence.StateTruncated, evidence.StateUnknown} {
		t.Run(string(state), func(t *testing.T) {
			record, _ := importFidelityRecord(t, newTestRepo(t), evidence.StateUnknown, evidence.StateUnknown)
			record.RawResponse, record.HasResponse, record.ResponseHash = nil, false, ""
			record.CaptureResponseState = state
			repo, ctx := newTestRepo(t), context.Background()
			result, err := ImportJSONL(ctx, repo, strings.NewReader(jsonlEnvelope(t, "http_record", record)), "", Options{})
			require.NoError(t, err)
			require.Equal(t, 1, result.RecordsImported)
			got, err := repo.GetRecordByUUID(ctx, record.UUID)
			require.NoError(t, err)
			assertImportedFidelityRecord(t, record, got)
			rr, err := database.RecordToHttpRequestResponse(got)
			require.NoError(t, err)
			require.False(t, rr.HasResponse())
			require.Empty(t, rr.Evidence().Response)
			require.Equal(t, state, rr.Evidence().ResponseState)
			require.Equal(t, record.RawRequest, rr.Request().Raw())
		})
	}
}

func TestImportJSONLKnownCaptureDoesNotInventWireBytesOrHashes(t *testing.T) {
	record, _ := importFidelityRecord(t, newTestRepo(t), evidence.StateUnknown, evidence.StateUnknown)
	record.RawRequest, record.CaptureRequestState = nil, evidence.StateMissing
	record.RequestHash, record.ResponseHash = "untrusted-request-hash", "untrusted-response-hash"
	record.Method, record.Path = "GET", "/guessed-from-url"
	repo, ctx := newTestRepo(t), context.Background()
	_, err := ImportJSONL(ctx, repo, strings.NewReader(jsonlEnvelope(t, "http_record", record)), "", Options{})
	require.NoError(t, err)
	got, err := repo.GetRecordByUUID(ctx, record.UUID)
	require.NoError(t, err)
	assertImportedFidelityRecord(t, record, got)
	rr, err := database.RecordToHttpRequestResponse(got)
	require.NoError(t, err)
	require.Empty(t, rr.Request().Raw(), "guessed method/path/URL are not captured request bytes")
	require.Equal(t, evidence.StateMissing, rr.Evidence().RequestState)
	require.Equal(t, record.RawResponse, rr.Response().Raw())
	require.Equal(t, "untrusted-request-hash", got.RequestHash, "raw imports neither infer nor repair hashes")
	require.NotEqual(t, record.UUID, rr.Evidence().ID)
}
