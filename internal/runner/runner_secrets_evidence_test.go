package runner

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/passive/secret_detect"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/secretscan"
	"github.com/vigolium/vigolium/pkg/types"
)

const runnerSecretValue = "aB3xZ9qL7mV4vR2n"

func runnerSecretRecord() *database.HTTPRecord {
	body := []byte(`const apiToken = "` + runnerSecretValue + `";`)
	return &database.HTTPRecord{
		UUID: "secret-record", ProjectUUID: database.DefaultProjectUUID,
		Scheme: "https", Hostname: "127.0.0.1", Port: 8443,
		URL: "https://finding.example/app.js", Method: "POST", Path: "/app.js",
		HasResponse: true, ResponseContentType: "application/javascript",
		// The destination differs from Host/URL; declared lengths intentionally
		// disagree with the raw binary bytes. Neither may be repaired for proof.
		RawRequest:  append([]byte("POST /app.js HTTP/1.1\r\nHost: vhost.example\r\nContent-Length: 1\r\n\r\n"), 0, 255, 'x'),
		RawResponse: append(append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 1\r\n\r\n"), body...), 0, 255),
		SentAt:      time.Date(2026, 11, 3, 1, 2, 3, 0, time.UTC),
	}
}

func runnerSecretMatch(body []byte) secretscan.Match {
	start := bytes.Index(body, []byte(runnerSecretValue))
	return secretscan.Match{
		RuleID: "runner.test.secret", RuleName: "Runner Test Secret",
		Source: "kingfisher", Confidence: "high", Secret: runnerSecretValue,
		Start: start, End: start + len(runnerSecretValue),
	}
}

func assertRunnerSecretReceipt(t *testing.T, record *database.HTTPRecord, x *evidence.Exchange, request, response evidence.State) {
	t.Helper()
	require.NotNil(t, x)
	require.NoError(t, x.Validate())
	require.Equal(t, evidence.ProvenanceSupplied, x.Provenance)
	require.NotEqual(t, record.UUID, x.ID, "a raw-record UUID is not a captured execution identity")
	require.Equal(t, "https://127.0.0.1:8443", x.Service)
	require.Equal(t, record.URL, x.URL)
	require.Equal(t, record.RawRequest, x.Request)
	require.Equal(t, record.RawResponse, x.Response)
	require.Equal(t, request, x.RequestState)
	require.Equal(t, response, x.ResponseState)
	require.True(t, record.SentAt.Equal(x.CapturedAt))
}

func assertRunnerSecretNoProof(t *testing.T, event *output.ResultEvent) {
	t.Helper()
	require.False(t, evidence.HasSelectedEvidence(event.Evidence), "legacy text/context links cannot select HTTP proof")
	for _, entry := range event.Evidence {
		if entry.Exchange != nil {
			require.Equal(t, evidence.ProvenanceLegacy, entry.Exchange.Provenance)
		}
	}
}

func TestSecretScanRecordEvidenceContextPreservesKnownFidelity(t *testing.T) {
	for _, tc := range []struct {
		name              string
		request, response evidence.State
		wantRequest       evidence.State
		wantResponse      evidence.State
	}{
		{"binary-complete", evidence.StateComplete, evidence.StateComplete, evidence.StateComplete, evidence.StateComplete},
		{"truncated", evidence.StateUnknown, evidence.StateTruncated, evidence.StateUnknown, evidence.StateTruncated},
		{"unknown", evidence.StateUnknown, evidence.StateUnknown, evidence.StateUnknown, evidence.StateUnknown},
		{"missing-request", evidence.StateMissing, evidence.StateComplete, evidence.StateMissing, evidence.StateComplete},
		{"missing-response", evidence.StateComplete, evidence.StateMissing, evidence.StateComplete, evidence.StateMissing},
		{"absent-request-state", "", evidence.StateTruncated, evidence.StateUnknown, evidence.StateTruncated},
		{"absent-response-state", evidence.StateTruncated, "", evidence.StateTruncated, evidence.StateUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := runnerSecretRecord()
			record.CaptureRequestState, record.CaptureResponseState = tc.request, tc.response
			if tc.request == evidence.StateMissing {
				record.RawRequest = nil
			}
			if tc.response == evidence.StateMissing {
				record.RawResponse, record.HasResponse = nil, false
			}
			ev, err := secretScanRecordEvidenceContext(record, httpmsg.NewHttpResponse(record.RawResponse))
			require.NoError(t, err)
			assertRunnerSecretReceipt(t, record, ev.Exchange, tc.wantRequest, tc.wantResponse)
			require.Equal(t, tc.request, record.CaptureRequestState, "do not mutate persisted metadata")
			require.Equal(t, tc.response, record.CaptureResponseState)
			again, err := secretScanRecordEvidenceContext(record, httpmsg.NewHttpResponse(record.RawResponse))
			require.NoError(t, err)
			require.NotEqual(t, ev.Exchange.ID, again.Exchange.ID, "each read is a fresh supplied view")
			if len(ev.Body) == 0 {
				return // an absent response has no secret to grade
			}
			event, ok := secret_detect.GradeMatch(runnerSecretMatch(ev.Body), ev)
			require.True(t, ok)
			require.Len(t, event.Evidence, 1)
			require.True(t, event.Evidence[0].Primary)
			require.Equal(t, evidence.RoleObservation, event.Evidence[0].Role)
			require.Equal(t, ev.Exchange, event.Evidence[0].Exchange)
			assertRunnerSecretReceipt(t, record, event.Evidence[0].Exchange, tc.wantRequest, tc.wantResponse)
		})
	}
}

func TestSecretScanRecordEvidenceContextKeepsDecodedBodyIndependent(t *testing.T) {
	record := runnerSecretRecord()
	decoded := []byte(`const apiToken = "` + runnerSecretValue + `";`)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := writer.Write(decoded)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	record.RawResponse = append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: application/javascript\r\n\r\n"), compressed.Bytes()...)
	record.CaptureRequestState, record.CaptureResponseState = evidence.StateUnknown, evidence.StateTruncated
	// Analysis may supply a decoded response view. The detector offsets refer to
	// that body, while the selected receipt must retain the compressed bytes.
	analysis := httpmsg.NewHttpResponse(append([]byte("HTTP/1.1 200 OK\r\n\r\n"), decoded...))
	ev, err := secretScanRecordEvidenceContext(record, analysis)
	require.NoError(t, err)
	require.Equal(t, decoded, ev.Body)
	event, ok := secret_detect.GradeMatch(runnerSecretMatch(ev.Body), ev)
	require.True(t, ok)
	require.Len(t, event.Evidence, 1)
	assertRunnerSecretReceipt(t, record, event.Evidence[0].Exchange, evidence.StateUnknown, evidence.StateTruncated)
	require.Equal(t, record.RawResponse, []byte(event.Response), "display projections must not replace canonical bytes")
}

func TestSecretScanRecordEvidenceContextLegacyAndInvalidMetadata(t *testing.T) {
	record := runnerSecretRecord()
	ev, err := secretScanRecordEvidenceContext(record, record.ParsedResponse())
	require.NoError(t, err)
	require.Nil(t, ev.Exchange, "nonempty raw bytes cannot invent capture metadata")
	event, ok := secret_detect.GradeMatch(runnerSecretMatch(ev.Body), ev)
	require.True(t, ok)
	assertRunnerSecretNoProof(t, event)
	record.CaptureResponseState = evidence.StateMissing // invalid: response bytes exist
	_, err = secretScanRecordEvidenceContext(record, record.ParsedResponse())
	require.Error(t, err, "invalid known metadata must not fall back to legacy proof")
}

func TestSecretScanBatchHydratesKnownReceiptsOnly(t *testing.T) {
	for _, tc := range []struct {
		name              string
		request, response evidence.State
	}{
		{"truncated", evidence.StateUnknown, evidence.StateTruncated},
		{"unknown", evidence.StateUnknown, evidence.StateUnknown},
		{"missing-request", evidence.StateMissing, evidence.StateComplete},
		{"legacy", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, ctx := newBannerRepo(t), context.Background()
			record := runnerSecretRecord()
			record.CaptureRequestState, record.CaptureResponseState = tc.request, tc.response
			if tc.request == evidence.StateMissing {
				record.RawRequest = nil
			}
			_, err := repo.DB().NewInsert().Model(record).Exec(ctx)
			require.NoError(t, err)
			r := &Runner{repository: repo, options: types.DefaultOptions()}
			r.options.ProjectUUID = record.ProjectUUID
			var events []*output.ResultEvent
			err = r.runSecretScanBatch(ctx, &phaseInfra{}, func(event *output.ResultEvent) { events = append(events, event) }, nil)
			require.NoError(t, err)
			require.NotEmpty(t, events, "fixture must reach the native detector")
			for _, event := range events {
				require.Contains(t, strings.Join(event.ExtractedResults, " "), runnerSecretValue)
				if tc.request == "" && tc.response == "" {
					assertRunnerSecretNoProof(t, event)
					continue
				}
				require.Len(t, event.Evidence, 1)
				assertRunnerSecretReceipt(t, record, event.Evidence[0].Exchange, tc.request, tc.response)
			}
		})
	}
}

func TestSecretScanBatchCompactedCompleteReceiptIsTruncated(t *testing.T) {
	repo, ctx := newBannerRepo(t), context.Background()
	record := runnerSecretRecord()
	record.CaptureRequestState, record.CaptureResponseState = evidence.StateComplete, evidence.StateComplete
	record.RawResponse = append(record.RawResponse, bytes.Repeat([]byte(" /* padding */ "), 64)...)
	record.ResponseContentLength = int64(len(record.ParsedResponse().Body()))
	original := bytes.Clone(record.RawResponse)
	_, err := repo.DB().NewInsert().Model(record).Exec(ctx)
	require.NoError(t, err)
	compacted, err := repo.DB().CompactBodies(ctx, database.CompactOptions{
		ProjectUUID: record.ProjectUUID, BodyOver: 128, KeepHead: 64,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, compacted.ResponseBodiesCompacted)
	record, err = repo.GetRecordByUUID(ctx, record.UUID)
	require.NoError(t, err)
	require.NotEqual(t, original, record.RawResponse, "exercise actual stored-body compaction")
	require.NotNil(t, record.BodyCompaction)
	require.NotNil(t, record.BodyCompaction.Response)
	require.Less(t, record.BodyCompaction.Response.KeptLength, record.BodyCompaction.Response.OriginalLength)
	require.Equal(t, evidence.StateComplete, record.CaptureResponseState, "historical metadata remains immutable")
	projection, err := repo.GetRecordsWithResponseBody(ctx, record.ProjectUUID, "", 10)
	require.NoError(t, err)
	require.Len(t, projection, 1)
	require.Equal(t, record.BodyCompaction, projection[0].BodyCompaction, "the batch projection must retain explicit byte loss")

	r := &Runner{repository: repo, options: types.DefaultOptions()}
	r.options.ProjectUUID = record.ProjectUUID
	var events []*output.ResultEvent
	err = r.runSecretScanBatch(ctx, &phaseInfra{}, func(event *output.ResultEvent) { events = append(events, event) }, nil)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	for _, event := range events {
		require.Len(t, event.Evidence, 1)
		assertRunnerSecretReceipt(t, record, event.Evidence[0].Exchange, evidence.StateComplete, evidence.StateTruncated)
	}
}

func TestSecretRecoveredSourceRecordLinkDoesNotPromoteHTTPProof(t *testing.T) {
	repo, ctx := newBannerRepo(t), context.Background()
	record := runnerSecretRecord()
	record.CaptureRequestState, record.CaptureResponseState = evidence.StateComplete, evidence.StateComplete
	_, err := repo.DB().NewInsert().Model(record).Exec(ctx)
	require.NoError(t, err)
	r := &Runner{repository: repo, options: types.DefaultOptions()}
	r.options.ProjectUUID = record.ProjectUUID
	body := []byte(`const apiToken = "` + runnerSecretValue + `"; // recovered original`)
	ev := secret_detect.EvidenceContext{Body: body, Host: record.Hostname, URL: record.URL}
	var emitted *output.ResultEvent
	n := r.emitSecretFindings(ctx, &phaseInfra{}, []secretscan.Match{runnerSecretMatch(body)}, ev, make(map[string]struct{}),
		func(event *output.ResultEvent) { emitted = event }, secretEmitOptions{
			RecordUUIDs: []string{record.UUID}, ModuleShort: "Recovered source", ExtraTags: []string{"recovered-source"},
		})
	require.Equal(t, 1, n)
	require.NotNil(t, emitted)
	assertRunnerSecretNoProof(t, emitted)
	require.Empty(t, emitted.Request, "the generated bundle's request is not the recovered artifact's request")
	require.Contains(t, emitted.Response, string(body))
}
