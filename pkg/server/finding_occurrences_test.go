package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
)

type findingOccurrenceDetail struct {
	OccurrenceID   string           `json:"occurrence_id"`
	ScanUUID       string           `json:"scan_uuid"`
	Entries        []evidence.Entry `json:"entries"`
	EvidenceStatus string           `json:"evidence_status"`
}

func TestFindingDetailSeparatesInlineAndPerOccurrenceEvidence(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	ctx := context.Background()

	firstExchange := evidence.NewExchange("https://app.test:443", "https://app.test/first",
		[]byte("GET /first HTTP/1.1\r\nHost: app.test\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nfirst proof"), evidence.ProvenanceCaptured)
	first := &database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ScanUUID: "scan-a", FindingHash: "redetected-finding",
		ModuleID: "test-module", ModuleName: "Test module", Severity: "high", Confidence: "firm",
		Request:  "GET /first HTTP/1.1\r\nHost: app.test\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\nfirst inline proof", Payload: "payload-a",
		EvidenceStatus: "missing",
		Evidence:       []evidence.Entry{evidence.Select(firstExchange, evidence.RoleControl, false, "control")},
	}
	if err := repo.SaveFindingDirect(ctx, first); err != nil {
		t.Fatalf("save first finding: %v", err)
	}

	secondExchange := evidence.NewExchange("https://app.test:443", "https://app.test/second",
		[]byte("GET /second HTTP/1.1\r\nHost: app.test\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nsecond proof"), evidence.ProvenanceCaptured)
	second := &database.Finding{
		ProjectUUID: database.DefaultProjectUUID, ScanUUID: "scan-b", FindingHash: first.FindingHash,
		ModuleID: first.ModuleID, ModuleName: first.ModuleName, Severity: first.Severity, Confidence: first.Confidence,
		Request:  "GET /second HTTP/1.1\r\nHost: app.test\r\n\r\n",
		Response: "HTTP/1.1 200 OK\r\n\r\nsecond inline proof", Payload: "payload-b",
		EvidenceStatus: "selected",
		Evidence:       []evidence.Entry{evidence.Select(secondExchange, evidence.RoleAttack, true, "attack")},
	}
	if err := repo.SaveFindingDirect(ctx, second); err != nil {
		t.Fatalf("redetect finding: %v", err)
	}

	h := newBasicHandlers(t, ServerConfig{}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Use(ProjectUUIDMiddleware(repo))
	app.Get("/api/findings/:id", h.findingsHandler().HandleGetFinding)
	status, body := doGet(t, app, fmt.Sprintf("/api/findings/%d", first.ID), nil)
	if status != http.StatusOK {
		t.Fatalf("GET finding status=%d body=%s", status, body)
	}
	var detail struct {
		database.Finding
		InlineEvidenceScanUUID string                    `json:"inline_evidence_scan_uuid"`
		Occurrences            []findingOccurrenceDetail `json:"occurrences"`
	}
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatalf("decode finding detail: %v", err)
	}

	if detail.ScanUUID != "scan-b" {
		t.Errorf("row scan_uuid = %q, want latest scan-b", detail.ScanUUID)
	}
	if detail.EvidenceStatus != "selected" {
		t.Errorf("row evidence_status = %q, want latest selected", detail.EvidenceStatus)
	}
	if detail.Request != first.Request || detail.Response != first.Response || detail.Payload != first.Payload {
		t.Errorf("redetection rewrote first inline proof: request=%q response=%q payload=%q", detail.Request, detail.Response, detail.Payload)
	}
	if detail.InlineEvidenceScanUUID != "scan-a" {
		t.Errorf("inline_evidence_scan_uuid = %q, want first scan-a", detail.InlineEvidenceScanUUID)
	}
	if len(detail.Occurrences) != 2 {
		t.Fatalf("occurrences = %+v, want two per-scan occurrence groups; body=%s", detail.Occurrences, body)
	}
	if detail.Occurrences[0].ScanUUID != "scan-a" || detail.Occurrences[1].ScanUUID != "scan-b" {
		t.Errorf("occurrences are not ordered by their first finding_evidence.id: %+v", detail.Occurrences)
	}
	byScan := make(map[string]findingOccurrenceDetail, len(detail.Occurrences))
	for _, occurrence := range detail.Occurrences {
		byScan[occurrence.ScanUUID] = occurrence
	}
	for scan, want := range map[string]struct {
		status string
		role   evidence.Role
	}{
		"scan-a": {status: "missing", role: evidence.RoleControl},
		"scan-b": {status: "selected", role: evidence.RoleAttack},
	} {
		occurrence, ok := byScan[scan]
		if !ok {
			t.Errorf("occurrence for %s missing: %+v", scan, detail.Occurrences)
			continue
		}
		if occurrence.EvidenceStatus != want.status {
			t.Errorf("%s occurrence evidence_status = %q, want %q", scan, occurrence.EvidenceStatus, want.status)
		}
		if len(occurrence.Entries) != 1 || occurrence.Entries[0].Role != want.role {
			t.Errorf("%s occurrence entries = %+v, want one %s entry", scan, occurrence.Entries, want.role)
		}
	}
}
