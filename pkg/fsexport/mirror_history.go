package fsexport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

func mirrorRecordKey(project, id string) string {
	if project == "" {
		project = database.DefaultProjectUUID
	}
	return project + "\x00" + id
}

// The merged manifest is metadata-only. Immutable occurrence bundles/sidecars
// remain the byte authority; a later subset cannot replace earlier associations.
type mirrorFindingHistory struct {
	ProjectUUID                 string                     `json:"project_uuid"`
	FindingID                   int64                      `json:"finding_id"`
	FindingHash                 string                     `json:"finding_hash,omitempty"`
	FirstMirroredEvidenceStatus string                     `json:"first_mirrored_evidence_status"`
	Occurrences                 []mirrorHistoryOccurrence  `json:"occurrences"`
	Evidence                    []mirrorHistoryAssociation `json:"evidence"`
}

type mirrorHistoryOccurrence struct {
	Snapshot       string `json:"snapshot"`
	EvidenceStatus string `json:"evidence_status"`
	FindingURL     string `json:"finding_url,omitempty"`
	ScanUUID       string `json:"scan_uuid,omitempty"`
}

type mirrorHistoryAssociation struct {
	evidence.Entry
	Snapshot     string `json:"snapshot"`
	RequestFile  string `json:"request_file,omitempty"`
	ResponseFile string `json:"response_file,omitempty"`
}

// bootstrapFindingHistory upgrades earlier mirror trees without changing any
// occurrence files. Decode only association metadata: the shallower exchange
// placeholder masks Entry.Exchange, so base64 bodies never enter the history.
func (m *Mirror) bootstrapFindingHistory(history *mirrorFindingHistory, current string) error {
	var earliest time.Time
	return filepath.WalkDir(m.findingsRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path == filepath.Join(m.findingsRoot, "history") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".evidence.json") {
			return nil
		}
		rel, err := filepath.Rel(m.findingsRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == current+".evidence.json" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		var snapshot struct {
			ProjectUUID    string `json:"project_uuid"`
			FindingID      int64  `json:"finding_id"`
			FindingHash    string `json:"finding_hash"`
			EvidenceStatus string `json:"evidence_status"`
			Evidence       []struct {
				evidence.Entry
				ExchangeMetadata *struct{} `json:"exchange"`
			} `json:"evidence"`
		}
		if err := json.NewDecoder(f).Decode(&snapshot); err != nil {
			return fmt.Errorf("read prior occurrence %s: %w", rel, err)
		}
		project := snapshot.ProjectUUID
		if project == "" {
			project = database.DefaultProjectUUID
		}
		if project != history.ProjectUUID || snapshot.FindingID != history.FindingID {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if earliest.IsZero() || info.ModTime().Before(earliest) {
			earliest = info.ModTime()
			history.FirstMirroredEvidenceStatus = snapshot.EvidenceStatus
		}
		history.Occurrences = append(history.Occurrences, mirrorHistoryOccurrence{Snapshot: rel, EvidenceStatus: snapshot.EvidenceStatus})
		prefix := strings.TrimSuffix(rel, ".evidence.json")
		for i, entry := range snapshot.Evidence {
			association := mirrorHistoryAssociation{Entry: entry.Entry.Manifest(), Snapshot: rel}
			if entry.ExchangeMetadata != nil {
				request := fmt.Sprintf("%s.evidence-%04d.request.bin", prefix, i+1)
				response := fmt.Sprintf("%s.evidence-%04d.response.bin", prefix, i+1)
				if _, err := os.Stat(filepath.Join(m.findingsRoot, filepath.FromSlash(request))); err == nil {
					association.RequestFile = request
				}
				if _, err := os.Stat(filepath.Join(m.findingsRoot, filepath.FromSlash(response))); err == nil {
					association.ResponseFile = response
				}
			}
			history.Evidence = append(history.Evidence, association)
		}
		return nil
	})
}

// mergeFindingHistory runs on the single mirror writer. Identity hashes keep
// project/producer text out of paths, and canonical IDs group later dedup saves.
func (m *Mirror) mergeFindingHistory(f *database.Finding, snapshotPrefix string) (string, error) {
	project := f.ProjectUUID
	if project == "" {
		project = database.DefaultProjectUUID
	}
	identity, err := json.Marshal([]any{project, f.ID})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(identity)
	rel := "history/" + hex.EncodeToString(hash[:]) + ".manifest.json"
	path := filepath.Join(m.findingsRoot, filepath.FromSlash(rel))
	history := mirrorFindingHistory{ProjectUUID: project, FindingID: f.ID, FindingHash: f.FindingHash, FirstMirroredEvidenceStatus: f.EvidenceStatus}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &history); err != nil {
			return "", fmt.Errorf("read existing mirror history: %w", err)
		}
		if history.ProjectUUID != project || history.FindingID != f.ID {
			return "", fmt.Errorf("mirror history identity mismatch")
		}
	} else if !os.IsNotExist(err) {
		return "", err // never replace an unreadable prior manifest
	} else {
		// An upgraded/restarted mirror may have immutable snapshots but no merged
		// history yet. Import their manifests before appending the incoming subset.
		if err := m.bootstrapFindingHistory(&history, snapshotPrefix); err != nil {
			return "", err
		}
	}
	snapshot := snapshotPrefix + ".evidence.json"
	history.Occurrences = append(history.Occurrences, mirrorHistoryOccurrence{snapshot, f.EvidenceStatus, f.URL, f.ScanUUID})
	for i, entry := range f.Evidence {
		association := mirrorHistoryAssociation{Entry: entry.Manifest(), Snapshot: snapshot}
		if entry.Exchange != nil {
			prefix := fmt.Sprintf("%s.evidence-%04d", snapshotPrefix, i+1)
			association.RequestFile, association.ResponseFile = prefix+".request.bin", prefix+".response.bin"
		}
		history.Evidence = append(history.Evidence, association)
	}
	data, err = json.MarshalIndent(history, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), mirrorDirMode); err != nil {
		return "", err
	}
	if err := writeFileAtomic(path, append(data, '\n'), mirrorFileMode); err != nil {
		return "", err
	}
	return rel, nil
}
