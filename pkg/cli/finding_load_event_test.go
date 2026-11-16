package cli

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestFindingResultEventImportNamedAndLegacyNumericEnums(t *testing.T) {
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "proof")
	entry.OccurrenceID = "event-occurrence"
	event := output.ResultEvent{
		ModuleID: "test", Host: "https://app.test/finding", Type: "http",
		Info:           output.Info{Name: "Test module", Description: "description", Tags: []string{"tag"}, Reference: []string{"https://reference.test"}, Severity: severity.High, Confidence: severity.Certain},
		Evidence:       []evidence.Entry{entry, {ExchangeID: "missing", Role: evidence.RoleControl}},
		EvidenceStatus: "unclassified", AdditionalEvidence: []string{"legacy unknown"},
	}
	named, err := json.Marshal(event)
	require.NoError(t, err)
	var legacy map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(named, &legacy))
	legacy["info"] = json.RawMessage(`{"name":"Test module","description":"description","tags":["tag"],"reference":["https://reference.test"],"severity":5,"confidence":3}`)
	numeric, err := json.Marshal(legacy)
	require.NoError(t, err)
	for name, data := range map[string][]byte{"named": named, "legacy-numeric": numeric} {
		t.Run(name, func(t *testing.T) {
			var decoded output.ResultEvent
			require.NoError(t, unmarshalFindingResultEvent(data, &decoded))
			require.Equal(t, event.Info, decoded.Info)
			require.Equal(t, event.Evidence, decoded.Evidence)
			f, err := tryParseSingleResultEvent(string(data), "scan", "project")
			require.NoError(t, err)
			require.Equal(t, "high", f.Severity)
			require.Equal(t, "certain", f.Confidence)
			require.Equal(t, "project", f.ProjectUUID)
			require.Equal(t, "scan", f.ScanUUID)
			require.Equal(t, event.Evidence, f.Evidence)
			require.Equal(t, event.AdditionalEvidence, f.AdditionalEvidence)
			findings, err := tryParseResultEventJSONL(string(data)+"\n"+string(data), "scan", "project")
			require.NoError(t, err)
			require.Len(t, findings, 2)
			for _, finding := range findings {
				require.Equal(t, event.Evidence, finding.Evidence)
				require.Equal(t, "unclassified", finding.EvidenceStatus)
			}
		})
	}
}

func TestFindingResultEventImportRejectsInvalidEnumNamesAndTypes(t *testing.T) {
	for _, raw := range []string{
		`{"template-id":"test","info":{"severity":"urgent"}}`,
		`{"template-id":"test","info":{"confidence":"maybe"}}`,
		`{"template-id":"test","info":{"severity":{}}}`,
		`{"template-id":"test","info":{"confidence":[]}}`,
	} {
		_, err := tryParseSingleResultEvent(raw, "", "project")
		require.Error(t, err)
		_, err = tryParseResultEventJSONL(raw, "", "project")
		require.Error(t, err)
	}
}
