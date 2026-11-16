package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
)

// These exports are explicitly default-project scoped. The generic traffic
// fixture intentionally has a blank project, so assign its owner before linking
// it or expecting it to appear in a project-scoped bundle.
func seedSelectedEvidenceDBRecord(t *testing.T, db *database.DB, suffix string) {
	t.Helper()
	seedRecordWithBodies(t, db, suffix)
	_, err := db.NewUpdate().Model((*database.HTTPRecord)(nil)).
		Set("project_uuid = ?", database.DefaultProjectUUID).
		Where("uuid = ?", "rec-"+suffix).Exec(context.Background())
	require.NoError(t, err)
}

func TestFindingSelectedEvidenceDBJSONLEnvelopesReceiptOnlyAndNoDuplicates(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	repo := database.NewRepository(db)
	seedSelectedEvidenceDBRecord(t, db, "one")
	seedSelectedEvidenceDBRecord(t, db, "two")
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte("response\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleObservation, true, "observation")
	entry.OccurrenceID = "receipt-occurrence"
	for i, refs := range [][]string{nil, {"rec-one", "rec-two"}} {
		f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: fmt.Sprintf("jsonl-%d", i), ModuleID: "test", ModuleName: "Test", RecordKind: database.RecordKindFinding, Severity: "high", Confidence: "firm", URL: "https://app.test/finding", Remediation: "full remediation", HTTPRecordUUIDs: refs, EvidenceStatus: "unclassified", Evidence: []evidence.Entry{entry, {ExchangeID: "missing", Role: evidence.RoleControl, OccurrenceID: "historic"}}}
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}
	foreign := &database.Finding{ProjectUUID: "foreign", FindingHash: "foreign-jsonl", ModuleID: "test", Severity: "high", Evidence: []evidence.Entry{entry}}
	require.NoError(t, repo.SaveFindingDirect(ctx, foreign))
	var out bytes.Buffer
	n, err := exportFindingJSONL(ctx, db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}, &out)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	seen := map[int64]bool{}
	dec := json.NewDecoder(&out)
	for i := 0; i < n; i++ {
		var envelope struct {
			Type string           `json:"type"`
			Data database.Finding `json:"data"`
		}
		require.NoError(t, dec.Decode(&envelope))
		require.Equal(t, "finding", envelope.Type)
		f := envelope.Data
		require.False(t, seen[f.ID], "a second HTTP link duplicated the finding")
		seen[f.ID] = true
		require.Equal(t, database.DefaultProjectUUID, f.ProjectUUID)
		require.Equal(t, "full remediation", f.Remediation)
		require.Equal(t, "unclassified", f.EvidenceStatus)
		require.Len(t, f.Evidence, 2)
		require.Equal(t, "receipt-occurrence", f.Evidence[0].OccurrenceID)
		require.Equal(t, x.Response, f.Evidence[0].Exchange.Response)
		require.Nil(t, f.Evidence[1].Exchange)
	}
	var extra any
	require.ErrorIs(t, dec.Decode(&extra), io.EOF)
}

func TestFindingSelectedEvidenceDBBundleStreamsRawOutsideReport(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	db.SQLDB().SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	seedSelectedEvidenceDBRecord(t, db, "one")
	x := evidence.NewExchange("https://app.test:443", "https://app.test/proof", []byte("request\x00\xff"), []byte("RAW-SELECTED-MARKER\xff\x00"), evidence.ProvenanceCaptured)
	entry := evidence.Select(x, evidence.RoleAttack, true, "proof")
	entry.OccurrenceID = "bundle-occurrence"
	f := &database.Finding{ProjectUUID: database.DefaultProjectUUID, FindingHash: "bundle-receipt-only", ModuleID: "test", EvidenceStatus: "unclassified", Evidence: []evidence.Entry{entry}}
	require.NoError(t, database.NewRepository(db).SaveFindingDirect(ctx, f))
	originalRenderer := renderDBBundleHTML
	t.Cleanup(func() { renderDBBundleHTML = originalRenderer })
	renderDBBundleHTML = func(produce output.ReportItemProducer, path string, meta output.HTMLReportMeta) error {
		count := 0
		err := produce(func(item any) error {
			data, err := json.Marshal(item)
			if err != nil {
				return err
			}
			require.NotContains(t, string(data), base64.StdEncoding.EncodeToString(x.Response))
			require.NotContains(t, string(data), "RAWBODYMARKER")
			if strings.Contains(string(data), `"type":"finding"`) {
				require.Contains(t, string(data), `"evidence_source":{"path":"data.jsonl","line":`)
				require.Contains(t, string(data), "bundle-occurrence")
				require.NotContains(t, string(data), `"exchange":`)
			}
			count++
			return nil
		})
		require.GreaterOrEqual(t, count, 2)
		if err != nil {
			return err
		}
		return originalRenderer(produce, path, meta)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	stats, err := writeDBBundleMembers(ctx, db, database.DefaultProjectUUID, tw)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.Equal(t, 1, stats.counts["finding"])
	members := map[string][]byte{}
	tr := tar.NewReader(&archive)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		members[h.Name], err = io.ReadAll(tr)
		require.NoError(t, err)
	}
	require.Contains(t, string(members["data.jsonl"]), base64.StdEncoding.EncodeToString(x.Response))
	require.NotContains(t, string(members["report.html"]), base64.StdEncoding.EncodeToString(x.Response))
	require.Contains(t, string(members["report.html"]), "evidence_source")
	require.Contains(t, string(members["metadata.json"]), `"finding": 1`)
}

func TestFindingSelectedEvidenceDBBundleRenderFailureKeepsPreviousArchive(t *testing.T) {
	db := newDBAtPath(t, ":memory:")
	seedSelectedEvidenceDBRecord(t, db, "one")
	original := renderDBBundleHTML
	t.Cleanup(func() { renderDBBundleHTML = original })
	renderDBBundleHTML = func(output.ReportItemProducer, string, output.HTMLReportMeta) error {
		return errors.New("report failure")
	}
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	require.NoError(t, os.WriteFile(path, []byte("previous archive"), 0o600))
	_, err := publishTarGz(path, func(tw *tar.Writer) (dbBundleStats, error) {
		return writeDBBundleMembers(context.Background(), db, database.DefaultProjectUUID, tw)
	})
	require.ErrorContains(t, err, "report.html")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "previous archive", string(data))
}
