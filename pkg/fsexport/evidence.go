package fsexport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// WriteFindingEvidenceFiles preserves selected captured messages without target
// markers, gzip decoding, text conversion or preview truncation. The JSON bundle
// carries every association, including missing receipts and occurrence roles.
func WriteFindingEvidenceFiles(dir, id string, f *database.Finding, perm os.FileMode) error {
	return writeFindingEvidenceFiles(dir, id, f, perm, "stored_finding")
}

func writeFindingEvidenceFiles(dir, id string, f *database.Finding, perm os.FileMode, statusScope string) error {
	bundle := struct {
		ProjectUUID         string           `json:"project_uuid"`
		FindingID           int64            `json:"finding_id"`
		EvidenceStatus      string           `json:"evidence_status"`
		Evidence            []evidence.Entry `json:"evidence"`
		EvidenceStatusScope string           `json:"evidence_status_scope"`
		FindingHash         string           `json:"finding_hash,omitempty"`
	}{f.ProjectUUID, f.ID, f.EvidenceStatus, f.Evidence, statusScope, f.FindingHash}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, id+".evidence.json"), append(data, '\n'), perm); err != nil {
		return err
	}
	for i, entry := range f.Evidence {
		if entry.Exchange == nil {
			continue
		}
		// Producer-supplied identities are metadata, never filesystem paths.
		prefix := filepath.Join(dir, fmt.Sprintf("%s.evidence-%04d", id, i+1))
		if err := writeFileAtomic(prefix+".request.bin", entry.Exchange.Request, perm); err != nil {
			return err
		}
		if err := writeFileAtomic(prefix+".response.bin", entry.Exchange.Response, perm); err != nil {
			return err
		}
	}
	return nil
}
