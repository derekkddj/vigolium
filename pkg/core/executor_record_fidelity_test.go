package core

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestRecordLinkCacheDoesNotEraseKnownCaptureFidelity(t *testing.T) {
	x := evidence.NewExchange("http://proof.test:8080", "http://proof.test/probe",
		[]byte("GET /probe HTTP/1.1\r\nHost: proof.test\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nanswer"), evidence.ProvenanceCaptured)
	complete, err := httpmsg.FromEvidenceExchange(x)
	require.NoError(t, err)
	var record database.HTTPRecord
	require.NoError(t, record.FromHttpRequestResponse(complete))
	record.ProjectUUID = database.DefaultProjectUUID
	e := &Executor{}
	require.True(t, e.recordMatchesInput(&record, complete))
	partial := x.Clone()
	partial.ResponseState = evidence.StateTruncated
	partial.ContentHash = partial.Hash()
	truncated, err := httpmsg.FromEvidenceExchange(partial)
	require.NoError(t, err)
	require.False(t, e.recordMatchesInput(&record, truncated), "same bytes do not identify the same known fidelity")
	record.CaptureResponseState = evidence.StateTruncated
	require.True(t, e.recordMatchesInput(&record, truncated))
	require.False(t, e.recordMatchesInput(&record, complete))
	result := &output.ResultEvent{Request: string(x.Request), Response: string(x.Response), Evidence: []evidence.Entry{evidence.Select(x, evidence.RoleAttack, true, "complete proof")}}
	require.False(t, e.recordMatchesResult(&record, result), "finding cache must not bypass the writer's fidelity-sensitive identity")
	record.CaptureRequestState, record.CaptureResponseState = "", ""
	require.True(t, e.recordMatchesInput(&record, complete), "complete legacy compatibility does not infer captured execution identity")
	require.False(t, e.recordMatchesInput(&record, truncated), "a legacy UUID cannot erase a known partial observation")
	record.CaptureRequestState, record.CaptureResponseState = evidence.StateComplete, evidence.StateComplete
	record.BodyCompaction = &database.BodyCompaction{Response: &database.CompactedBody{OriginalLength: 99, KeptLength: 1}}
	require.False(t, e.recordMatchesInput(&record, complete), "explicit compaction affects the effective supplied fidelity")
	require.True(t, e.recordMatchesInput(&record, truncated))
}
