package database

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// borrowedString models a request-scoped string view whose bytes can be reused
// after admission. Keep the backing slice alive in each test until the write has
// completed; production callers must not be able to retarget an admitted write.
func borrowedString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func TestFindingWriterOwnsQueuedIdentityStrings(t *testing.T) {
	moduleBytes := []byte("module-before")
	recordBytes := []byte("record-before")
	scanBytes := []byte("scan-before")
	projectBytes := []byte("project-before")
	exchangeBytes := []byte("exchange-before")
	occurrenceBytes := []byte("occurrence-before")
	evidenceScanBytes := []byte("evidence-scan-before")
	hashBytes := []byte("hash-before")
	moduleID := borrowedString(moduleBytes)
	recordUUID := borrowedString(recordBytes)
	scanUUID := borrowedString(scanBytes)
	projectUUID := borrowedString(projectBytes)

	entered := make(chan struct{})
	release := make(chan struct{})
	persisted := make(chan FindingWrite, 1)
	writer := NewFindingWriter(nil, FindingWriterConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
		saveBatch: func(_ context.Context, writes []FindingWrite) []FindingSaveResult {
			close(entered)
			<-release
			persisted <- writes[0]
			return []FindingSaveResult{{Inserted: true}}
		},
	})
	event := &output.ResultEvent{
		ModuleID: moduleID,
		Info:     output.Info{Name: moduleID, Severity: severity.High},
		Evidence: []evidence.Entry{{
			ExchangeID:   borrowedString(exchangeBytes),
			OccurrenceID: borrowedString(occurrenceBytes),
			ScanUUID:     borrowedString(evidenceScanBytes),
			Exchange: &evidence.Exchange{
				ID:          borrowedString(exchangeBytes),
				ContentHash: borrowedString(hashBytes),
			},
		}},
	}
	if err := writer.Save(context.Background(), event, []string{recordUUID}, scanUUID, projectUUID); err != nil {
		t.Fatalf("Save: %v", err)
	}
	<-entered

	copy(moduleBytes, []byte("module-after!"))
	copy(recordBytes, []byte("record-after!"))
	copy(scanBytes, []byte("scan-after!"))
	copy(projectBytes, []byte("project-after!"))
	copy(exchangeBytes, []byte("exchange-after!"))
	copy(occurrenceBytes, []byte("occurrence-after!"))
	copy(evidenceScanBytes, []byte("evidence-scan-after!"))
	copy(hashBytes, []byte("hash-after!"))
	close(release)
	writer.Close()
	got := <-persisted
	e := got.Event.Evidence[0]
	if got.Event.ModuleID != "module-before" || got.Event.Info.Name != "module-before" ||
		len(got.HTTPRecordUUIDs) != 1 || got.HTTPRecordUUIDs[0] != "record-before" ||
		got.ScanUUID != "scan-before" || got.ProjectUUID != "project-before" ||
		e.ExchangeID != "exchange-before" || e.OccurrenceID != "occurrence-before" || e.ScanUUID != "evidence-scan-before" ||
		e.Exchange.ID != "exchange-before" || e.Exchange.ContentHash != "hash-before" {
		t.Fatalf("queued finding identities changed after admission: module=%q name=%q records=%q scan=%q project=%q evidence=%+v",
			got.Event.ModuleID, got.Event.Info.Name, got.HTTPRecordUUIDs, got.ScanUUID, got.ProjectUUID, e)
	}
	// Keep the borrowed storage live through the assertions above.
	_ = moduleBytes[0] + recordBytes[0] + scanBytes[0] + projectBytes[0] + exchangeBytes[0] + occurrenceBytes[0] + evidenceScanBytes[0] + hashBytes[0]
}

func TestFindingWriterOwnsEvidenceExchangeHashInputs(t *testing.T) {
	serviceBytes := []byte("service-before")
	urlBytes := []byte("https://one.example/path")
	exchange := evidence.NewExchange(
		borrowedString(serviceBytes), borrowedString(urlBytes),
		[]byte("GET / HTTP/1.1\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\n"), evidence.ProvenanceCaptured,
	)
	if err := exchange.Validate(); err != nil {
		t.Fatalf("new exchange should be valid before admission: %v", err)
	}

	ctx := context.Background()
	repo := NewRepository(newTestDB(t))
	entered := make(chan struct{})
	release := make(chan struct{})
	persisted := make(chan []FindingSaveResult, 1)
	writer := NewFindingWriter(repo, FindingWriterConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
		saveBatch: func(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
			close(entered)
			<-release
			results := repo.SaveFindingsBatchResults(ctx, writes)
			persisted <- results
			return results
		},
	})
	event := &output.ResultEvent{
		ModuleID: "evidence-identity-test",
		Info:     output.Info{Name: "evidence identity test", Severity: severity.High},
		Host:     "example.test",
		URL:      "https://example.test/finding",
		Evidence: []evidence.Entry{evidence.Select(exchange, evidence.RoleObservation, true, "captured exchange")},
	}
	if err := writer.Save(ctx, event, nil, "", "project-evidence"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	<-entered

	copy(serviceBytes, []byte("service-after!"))
	copy(urlBytes, []byte("https://two.example/path"))
	close(release)
	writer.Close()
	results := <-persisted
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("queued finding persistence results = %+v, want one successful save", results)
	}
	stored, err := repo.GetEvidenceExchange(ctx, exchange.ID, "project-evidence")
	if err != nil {
		t.Fatalf("GetEvidenceExchange: %v", err)
	}
	if stored.Service != "service-before" || stored.URL != "https://one.example/path" {
		t.Fatalf("persisted exchange hash inputs service=%q URL=%q, want original values", stored.Service, stored.URL)
	}
	_ = serviceBytes[0] + urlBytes[0]
}

func TestRecordWriterOwnsQueuedIdentityStrings(t *testing.T) {
	scanBytes := []byte("scan-before")
	projectBytes := []byte("project-before")
	parentBytes := []byte("parent-before")
	rootBytes := []byte("root-before")
	entered := make(chan struct{})
	release := make(chan struct{})
	persisted := make(chan [4]string, 1)
	repo := NewRepository(newTestDB(t))
	writer := NewRecordWriter(repo, RecordWriterConfig{
		BatchSize: 1,
		ScanUUID:  borrowedString(scanBytes),
		insertBatch: func(_ context.Context, records []*HTTPRecord) error {
			close(entered)
			<-release
			persisted <- [4]string{records[0].ScanUUID, records[0].ProjectUUID, records[0].ParentUUID, records[0].RootUUID}
			records[0].UUID = "stored-record"
			return nil
		},
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.WriteWithLineage(context.Background(), makeTestRequest(0), "test", borrowedString(projectBytes), RecordLineage{
			ParentUUID: borrowedString(parentBytes),
			RootUUID:   borrowedString(rootBytes),
		})
		writeDone <- err
	}()
	<-entered
	copy(scanBytes, []byte("scan-after!"))
	copy(projectBytes, []byte("project-after!"))
	copy(parentBytes, []byte("parent-after!"))
	copy(rootBytes, []byte("root-after!"))
	close(release)
	if err := <-writeDone; err != nil {
		t.Fatalf("WriteWithLineage: %v", err)
	}
	got := <-persisted
	if got != [4]string{"scan-before", "project-before", "parent-before", "root-before"} {
		t.Fatalf("queued record identities = scan:%q project:%q parent:%q root:%q, want original values", got[0], got[1], got[2], got[3])
	}
	writer.Close()
	_ = scanBytes[0] + projectBytes[0] + parentBytes[0] + rootBytes[0]
}

func TestRecordWriterOwnsLineageScanUUID(t *testing.T) {
	lineageScanBytes := []byte("lineage-before")
	entered := make(chan struct{})
	release := make(chan struct{})
	repo := NewRepository(newTestDB(t))
	writer := NewRecordWriter(repo, RecordWriterConfig{
		BatchSize: 1,
		ScanUUID:  "config-scan",
		insertBatch: func(ctx context.Context, records []*HTTPRecord) error {
			close(entered)
			<-release
			_, err := repo.SaveRecordsBatch(ctx, records)
			return err
		},
	})
	type writeResult struct {
		uuid string
		err  error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		uuid, err := writer.WriteWithLineage(context.Background(), makeTestRequest(0), "test", "project-lineage", RecordLineage{
			ScanUUID: borrowedString(lineageScanBytes),
		})
		writeDone <- writeResult{uuid: uuid, err: err}
	}()
	<-entered
	copy(lineageScanBytes, []byte("lineage-after!"))
	close(release)
	result := <-writeDone
	if result.err != nil {
		t.Fatalf("WriteWithLineage: %v", result.err)
	}
	writer.Close()
	stored, err := repo.GetRecordByUUID(context.Background(), result.uuid)
	if err != nil {
		t.Fatalf("GetRecordByUUID: %v", err)
	}
	if stored.ScanUUID != "lineage-before" {
		t.Fatalf("stored record scan UUID = %q, want lineage override %q", stored.ScanUUID, "lineage-before")
	}
	_ = lineageScanBytes[0]
}

func TestScanLoggerOwnsCapturedIdentityStrings(t *testing.T) {
	scanBytes := []byte("scan-before")
	projectBytes := []byte("project-before")
	logger := NewScanLogger(&Repository{}, borrowedString(scanBytes), borrowedString(projectBytes))
	copy(scanBytes, []byte("scan-after!"))
	copy(projectBytes, []byte("project-after!"))

	var got *ScanLog
	logger.writeBatch = func(_ context.Context, entries []*ScanLog) error {
		got = entries[0]
		return nil
	}
	logger.Trace("discovery", "captured scope")
	if err := logger.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got == nil || got.ScanUUID != "scan-before" || got.ProjectUUID != "project-before" {
		t.Fatalf("scan logger identities changed after construction: log=%+v", got)
	}
	_ = scanBytes[0] + projectBytes[0]
}

func TestSaveFindingRejectsKnownForeignScanProjectWithoutHistory(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	if err := repo.CreateScan(ctx, &Scan{UUID: "owned-scan", ProjectUUID: "project-a", Name: "native", Status: "running"}); err != nil {
		t.Fatal(err)
	}

	err := repo.SaveFinding(ctx, &output.ResultEvent{
		ModuleID: "identity-test",
		Info:     output.Info{Name: "identity-test", Severity: severity.High},
		Host:     "example.test",
		URL:      "https://example.test/path",
	}, nil, "owned-scan", "project-b")
	if !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("SaveFinding error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings WHERE project_uuid = 'project-b'"); n != 0 {
		t.Fatalf("mismatched save left %d finding rows", n)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'owned-scan'"); n != 0 {
		t.Fatalf("mismatched save left %d occurrence rows", n)
	}
}

func TestSaveFindingDirectRejectsKnownForeignScanProjectWithoutHistory(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	if err := repo.CreateScan(ctx, &Scan{UUID: "direct-owned-scan", ProjectUUID: "project-a", Name: "native", Status: "running"}); err != nil {
		t.Fatal(err)
	}

	finding := &Finding{
		ProjectUUID: "project-b", HTTPRecordUUIDs: []string{}, ScanUUID: "direct-owned-scan",
		ModuleID: "direct-identity-test", ModuleName: "direct identity test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: "direct-foreign-scan-hash",
	}
	if err := repo.SaveFindingDirect(ctx, finding); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("SaveFindingDirect error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings WHERE finding_hash = 'direct-foreign-scan-hash'"); n != 0 {
		t.Fatalf("mismatched direct save left %d finding rows", n)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'direct-owned-scan'"); n != 0 {
		t.Fatalf("mismatched direct save left %d occurrence rows", n)
	}
}

func TestSaveFindingsBatchRejectsKnownForeignScanProject(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	if err := repo.CreateScan(ctx, &Scan{UUID: "batch-owned-scan", ProjectUUID: "project-a", Name: "native", Status: "running"}); err != nil {
		t.Fatal(err)
	}

	results := repo.SaveFindingsBatchResults(ctx, []FindingWrite{{
		Event:       makeFindingEvent("batch-identity-test", "/path", severity.High),
		ScanUUID:    "batch-owned-scan",
		ProjectUUID: "project-b",
	}})
	if len(results) != 1 || !errors.Is(results[0].Err, ErrScanProjectMismatch) {
		t.Fatalf("batch results = %+v, want one ErrScanProjectMismatch", results)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings WHERE project_uuid = 'project-b'"); n != 0 {
		t.Fatalf("mismatched batch left %d finding rows", n)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'batch-owned-scan'"); n != 0 {
		t.Fatalf("mismatched batch left %d occurrence rows", n)
	}
}

func TestFindingHashCollisionForeignScanLeavesSurvivorHistoryAndEvidenceUntouched(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	for _, scan := range []*Scan{
		{UUID: "survivor-scan", ProjectUUID: "project-a", Name: "native", Status: "running"},
		{UUID: "foreign-scan", ProjectUUID: "project-b", Name: "native", Status: "running"},
	} {
		if err := repo.CreateScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	recordA := insertRecordP(t, repo, "project-a", "GET", "example.test", "/first", 200)
	recordB := insertRecordP(t, repo, "project-a", "GET", "example.test", "/second", 200)
	first := makeFindingEvent("collision-identity-test", "/same", severity.High)
	if err := repo.SaveFinding(ctx, first, []string{recordA}, "survivor-scan", "project-a"); err != nil {
		t.Fatalf("initial finding: %v", err)
	}
	var before Finding
	if err := db.NewSelect().Model(&before).Where("project_uuid = ?", "project-a").Where("module_id = ?", "collision-identity-test").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	originalAdditional := append([]string(nil), before.AdditionalEvidence...)
	second := makeFindingEvent("collision-identity-test", "/same", severity.High)
	second.Request = "GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n"
	second.Response = "HTTP/1.1 200 OK\r\nX-New: evidence\r\n\r\n"
	if err := repo.SaveFinding(ctx, second, []string{recordB}, "foreign-scan", "project-a"); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("foreign-scan re-detection error = %v, want ErrScanProjectMismatch", err)
	}

	var stored Finding
	if err := db.NewSelect().Model(&stored).Where("project_uuid = ?", "project-a").Where("module_id = ?", "collision-identity-test").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if stored.ScanUUID != "survivor-scan" || stored.Request != first.Request || stored.Response != first.Response || !slices.Equal(stored.AdditionalEvidence, originalAdditional) {
		t.Fatalf("rejected collision changed survivor attribution/evidence: %+v", stored)
	}
	var refs []string
	if err := db.NewRaw("SELECT record_uuid FROM finding_records WHERE finding_id = ? ORDER BY record_uuid", stored.ID).Scan(ctx, &refs); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != recordA || len(stored.HTTPRecordUUIDs) != 1 || stored.HTTPRecordUUIDs[0] != recordA {
		t.Fatalf("survivor record refs junction=%v array=%v, want only original %q", refs, stored.HTTPRecordUUIDs, recordA)
	}
	observations, err := repo.ListFindingObservations(ctx, "project-a", stored.ID)
	if err != nil || len(observations) != 1 || observations[0].ScanUUID != "survivor-scan" {
		t.Fatalf("survivor observations=%+v err=%v, want only original scan", observations, err)
	}
}

func TestSaveFindingAllowsKnownSameProjectRescanHistory(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	for _, scanUUID := range []string{"first-scan", "second-scan"} {
		if err := repo.CreateScan(ctx, &Scan{UUID: scanUUID, ProjectUUID: "project-a", Name: "native", Status: "running"}); err != nil {
			t.Fatal(err)
		}
	}
	event := makeFindingEvent("same-project-rescan", "/same", severity.High)
	if err := repo.SaveFinding(ctx, event, nil, "first-scan", "project-a"); err != nil {
		t.Fatalf("first finding: %v", err)
	}
	if err := repo.SaveFinding(ctx, event, nil, "second-scan", "project-a"); err != nil {
		t.Fatalf("same-project re-detection: %v", err)
	}
	var finding Finding
	if err := db.NewSelect().Model(&finding).Where("project_uuid = ?", "project-a").Where("module_id = ?", "same-project-rescan").Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if finding.ScanUUID != "second-scan" {
		t.Fatalf("latest finding scan = %q, want second-scan", finding.ScanUUID)
	}
	observations, err := repo.ListFindingObservations(ctx, "project-a", finding.ID)
	if err != nil || len(observations) != 2 || observations[0].ScanUUID != "first-scan" || observations[1].ScanUUID != "second-scan" {
		t.Fatalf("same-project observations=%+v err=%v, want both scans", observations, err)
	}
}

func TestSaveFindingKeepsUnknownCorrelationScanIDs(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	if err := repo.SaveFinding(ctx, &output.ResultEvent{
		ModuleID: "imported-identity-test",
		Info:     output.Info{Name: "imported-identity-test", Severity: severity.High},
	}, nil, "external-correlation-id", "project-import"); err != nil {
		t.Fatalf("SaveFinding with an unregistered correlation ID: %v", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = 'external-correlation-id' AND project_uuid = 'project-import'"); n != 1 {
		t.Fatalf("unregistered correlation observation count = %d, want 1", n)
	}
}
