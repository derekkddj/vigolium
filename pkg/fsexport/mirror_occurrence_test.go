package fsexport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func TestSelectedEvidenceMirrorOccurrencesMergeHistoryWithoutReplacingEarlierSidecars(t *testing.T) {
	dir := t.TempDir()
	m, err := newMirror(dir, false, 8, time.Second)
	require.NoError(t, err)
	first := &database.Finding{ID: 7, ProjectUUID: "project-a", FindingHash: "canonical", Hostname: "app.test", ModuleID: "test", EvidenceStatus: "unclassified", Request: "historical legacy bytes", Evidence: []evidence.Entry{{ExchangeID: "historic", Role: evidence.RoleUnknown, OccurrenceID: "historic-occurrence"}}}
	m.OnFindingOccurrence(first)
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "later selection")
	entry.OccurrenceID = "later-occurrence"
	later := &database.Finding{ID: 7, ProjectUUID: "project-a", FindingHash: "canonical", Hostname: "app.test", ModuleID: "test", EvidenceStatus: "selected", Evidence: []evidence.Entry{entry}}
	m.OnFindingOccurrence(later)
	later.Evidence[0].Exchange.Response[0] = 'X' // queue must own the snapshot
	later.Evidence[0].Role = evidence.RoleUnknown
	m.start()
	m.Close()
	root := filepath.Join(dir, "findings")
	firstPath := filepath.Join(root, "app.test", "0001.evidence.json")
	firstBytes, err := os.ReadFile(firstPath)
	require.NoError(t, err)
	secondBytes, err := os.ReadFile(filepath.Join(root, "app.test", "0002.evidence-0001.response.bin"))
	require.NoError(t, err)
	require.Equal(t, x.Response, secondBytes)
	index := readJSONLines(t, filepath.Join(root, "index.jsonl"))
	require.Len(t, index, 2, "occurrence hook must not also mirror new-row hook")
	historyRel := index[1]["evidence_history"].(string)
	require.Equal(t, index[0]["evidence_history"], historyRel)
	readHistory := func() mirrorFindingHistory {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(historyRel)))
		require.NoError(t, err)
		var history mirrorFindingHistory
		require.NoError(t, json.Unmarshal(data, &history))
		return history
	}
	history := readHistory()
	require.Equal(t, "unclassified", history.FirstMirroredEvidenceStatus)
	require.Len(t, history.Occurrences, 2)
	require.Len(t, history.Evidence, 2)
	require.Equal(t, evidence.RoleUnknown, history.Evidence[0].Role)
	require.Equal(t, evidence.RoleAttack, history.Evidence[1].Role)
	require.Nil(t, history.Evidence[1].Exchange, "merged history is metadata-only, bytes stay in immutable files")
	require.NotEmpty(t, history.Evidence[1].ResponseFile)
	md, err := os.ReadFile(filepath.Join(root, "app.test", "0002.md"))
	require.NoError(t, err)
	require.Contains(t, string(md), "Incoming occurrence evidence status: selected")
	require.NotContains(t, string(md), "Stored finding evidence status: selected")

	// Resume with a manifest-only occurrence; it must append without hydrating
	// or substituting the previous receipt and retain the complete prior history.
	m2, err := NewMirror(dir, false)
	require.NoError(t, err)
	m2.OnFindingOccurrence(&database.Finding{ID: 7, ProjectUUID: "project-a", FindingHash: "canonical", Hostname: "app.test", EvidenceStatus: "missing", Evidence: []evidence.Entry{{ExchangeID: "missing", Role: evidence.RoleObservation, Primary: true, OccurrenceID: "third-occurrence"}}})
	m2.Close()
	history = readHistory()
	require.Equal(t, "unclassified", history.FirstMirroredEvidenceStatus)
	require.Len(t, history.Occurrences, 3)
	require.Len(t, history.Evidence, 3)
	require.Equal(t, "third-occurrence", history.Evidence[2].OccurrenceID)
	require.Empty(t, history.Evidence[2].RequestFile)
	preserved, err := os.ReadFile(firstPath)
	require.NoError(t, err)
	require.Equal(t, firstBytes, preserved)
	preserved, err = os.ReadFile(filepath.Join(root, "app.test", "0002.evidence-0001.response.bin"))
	require.NoError(t, err)
	require.Equal(t, secondBytes, preserved)
	_, err = os.Stat(filepath.Join(root, "app.test", "0003.evidence-0001.request.bin"))
	require.True(t, os.IsNotExist(err), "missing receipt must not invent bytes")
}

func TestSelectedEvidenceMirrorBootstrapsEarlierManifestBeforeIncomingSubset(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "findings", "app.test")
	require.NoError(t, os.MkdirAll(host, 0o700))
	x := evidence.NewExchange("https://app.test:443", "https://app.test/old", []byte("old request\x00\xff"), []byte("old response\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleUnknown, true, "historic capture")
	entry.OccurrenceID = "historical"
	f := &database.Finding{ID: 7, ProjectUUID: "project-a", FindingHash: "canonical", Hostname: "app.test", EvidenceStatus: "unclassified", Evidence: []evidence.Entry{entry}}
	require.NoError(t, WriteFindingEvidenceFiles(host, "0001", f, 0o600))
	m, err := NewMirror(dir, false)
	require.NoError(t, err)
	m.OnFindingOccurrence(&database.Finding{ID: 7, ProjectUUID: "project-a", FindingHash: "canonical", Hostname: "app.test", EvidenceStatus: "missing", Evidence: []evidence.Entry{{ExchangeID: "later-missing", Role: evidence.RoleObservation, Primary: true, OccurrenceID: "later"}}})
	m.Close()
	index := readJSONLines(t, filepath.Join(dir, "findings", "index.jsonl"))
	require.Len(t, index, 1)
	data, err := os.ReadFile(filepath.Join(dir, "findings", filepath.FromSlash(index[0]["evidence_history"].(string))))
	require.NoError(t, err)
	var history mirrorFindingHistory
	require.NoError(t, json.Unmarshal(data, &history))
	require.Equal(t, "unclassified", history.FirstMirroredEvidenceStatus)
	require.Len(t, history.Evidence, 2)
	require.Equal(t, "historical", history.Evidence[0].OccurrenceID)
	require.Nil(t, history.Evidence[0].Exchange)
	require.NotEmpty(t, history.Evidence[0].ResponseFile)
	require.Empty(t, history.Evidence[1].ResponseFile)
	old, err := os.ReadFile(filepath.Join(host, "0001.evidence-0001.response.bin"))
	require.NoError(t, err)
	require.Equal(t, x.Response, old)
}

func TestSelectedEvidenceMirrorDoesNotCrossLinkForeignLegacyRecord(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMirror(dir, false)
	require.NoError(t, err)
	rec := sampleRecord("foreign-record")
	rec.ProjectUUID = "foreign-project"
	m.OnRecord(rec)
	m.OnFindingOccurrence(&database.Finding{ID: 7, ProjectUUID: "own-project", Hostname: "own.test", HTTPRecordUUIDs: []string{rec.UUID}})
	m.Close()
	index := readJSONLines(t, filepath.Join(dir, "findings", "index.jsonl"))
	require.Len(t, index, 1)
	traffic, _ := index[0]["traffic"].([]any)
	require.Empty(t, traffic)
	md, err := os.ReadFile(filepath.Join(dir, "findings", "own.test", "0001.md"))
	require.NoError(t, err)
	require.NotContains(t, string(md), "GET /users HTTP/1.1")
}

func TestSelectedEvidenceMirrorResumeDoesNotOverwriteOrphanOccurrenceBundle(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "findings", "app.test")
	require.NoError(t, os.MkdirAll(host, 0o700))
	path := filepath.Join(host, "0007.evidence.json")
	require.NoError(t, os.WriteFile(path, []byte("orphan immutable occurrence"), 0o600))
	m, err := NewMirror(dir, false)
	require.NoError(t, err)
	m.OnFindingOccurrence(&database.Finding{ID: 7, ProjectUUID: "project-a", Hostname: "app.test", EvidenceStatus: "missing"})
	m.Close()
	bytes, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "orphan immutable occurrence", string(bytes))
	_, err = os.Stat(filepath.Join(host, "0008.evidence.json"))
	require.NoError(t, err)
}
