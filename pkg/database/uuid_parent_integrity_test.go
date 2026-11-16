package database

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func assertAgenticParentUnchanged(t *testing.T, repo *Repository, runUUID, projectUUID, status, parentUUID string) {
	t.Helper()
	run, err := repo.GetAgenticScan(context.Background(), runUUID)
	if err != nil {
		t.Fatalf("GetAgenticScan(%s): %v", runUUID, err)
	}
	if run.ProjectUUID != projectUUID || run.Status != status || run.ParentAgenticScanUUID != parentUUID {
		t.Fatalf("agentic parent changed: project=%q status=%q parent=%q; want %q/%q/%q",
			run.ProjectUUID, run.Status, run.ParentAgenticScanUUID, projectUUID, status, parentUUID)
	}
}

func TestCreateAgenticScanParentProjectOwnership(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)

	foreignParentUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: foreignParentUUID, ProjectUUID: "parent-project", Mode: "swarm", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan(parent): %v", err)
	}

	foreignChildUUID := uuid.NewString()
	err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: foreignChildUUID, ProjectUUID: "child-project", ParentAgenticScanUUID: foreignParentUUID,
		Mode: "audit", Status: "running",
	})
	if !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateAgenticScan with known foreign parent error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM agentic_scans WHERE uuid = '"+foreignChildUUID+"'"); n != 0 {
		t.Fatalf("rejected child run write left %d agentic scan rows", n)
	}
	assertAgenticParentUnchanged(t, repo, foreignParentUUID, "parent-project", "running", "")

	// Explicit same-project nesting remains valid.
	sameProjectParent := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: sameProjectParent, ProjectUUID: "nested-project", Mode: "swarm", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan(same-project parent): %v", err)
	}
	sameProjectChild := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: sameProjectChild, ProjectUUID: "nested-project", ParentAgenticScanUUID: sameProjectParent,
		Mode: "audit", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan with same-project parent: %v", err)
	}

	// Empty project values on both rows normalize to the shared default project.
	defaultParent := uuid.NewString()
	parentRun := &AgenticScan{UUID: defaultParent, Mode: "swarm", Status: "running"}
	if err := repo.CreateAgenticScan(ctx, parentRun); err != nil {
		t.Fatalf("CreateAgenticScan(default parent): %v", err)
	}
	if parentRun.ProjectUUID != DefaultProjectUUID {
		t.Fatalf("default parent project = %q, want %q", parentRun.ProjectUUID, DefaultProjectUUID)
	}
	defaultChild := &AgenticScan{
		UUID: uuid.NewString(), ParentAgenticScanUUID: defaultParent, Mode: "audit", Status: "running",
	}
	if err := repo.CreateAgenticScan(ctx, defaultChild); err != nil {
		t.Fatalf("CreateAgenticScan(default-project child): %v", err)
	}
	if defaultChild.ProjectUUID != DefaultProjectUUID {
		t.Fatalf("default child project = %q, want %q", defaultChild.ProjectUUID, DefaultProjectUUID)
	}

	// Missing historical parent rows remain accepted soft references.
	legacyParent := "unregistered-parent-" + uuid.NewString()
	legacyChild := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: legacyChild, ProjectUUID: "legacy-project", ParentAgenticScanUUID: legacyParent,
		Mode: "audit", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan with unknown legacy parent: %v", err)
	}
	stored, err := repo.GetAgenticScan(ctx, legacyChild)
	if err != nil {
		t.Fatalf("GetAgenticScan(legacy child): %v", err)
	}
	if stored.ParentAgenticScanUUID != legacyParent {
		t.Fatalf("legacy parent UUID = %q, want %q", stored.ParentAgenticScanUUID, legacyParent)
	}
}

func TestCreateScanRejectsKnownForeignAgenticRun(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	parentUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: parentUUID, ProjectUUID: "parent-project", Mode: "swarm", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}

	childUUID := uuid.NewString()
	err := repo.CreateScan(ctx, &Scan{
		UUID: childUUID, ProjectUUID: "child-project", AgenticScanUUID: parentUUID,
		Name: "native child", Status: "running",
	})
	if !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateScan error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM scans WHERE uuid = '"+childUUID+"'"); n != 0 {
		t.Fatalf("rejected child write left %d scan rows", n)
	}
	assertAgenticParentUnchanged(t, repo, parentUUID, "parent-project", "running", "")

	// Known same-project and normalized default-project parents remain valid.
	sameProjectChild := uuid.NewString()
	if err := repo.CreateScan(ctx, &Scan{
		UUID: sameProjectChild, ProjectUUID: "parent-project", AgenticScanUUID: parentUUID,
		Name: "same-project child", Status: "running",
	}); err != nil {
		t.Fatalf("CreateScan with same-project parent: %v", err)
	}
	defaultParent := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: defaultParent, Mode: "swarm", Status: "running"}); err != nil {
		t.Fatalf("CreateAgenticScan(default parent): %v", err)
	}
	defaultChild := &Scan{UUID: uuid.NewString(), AgenticScanUUID: defaultParent, Name: "default child", Status: "running"}
	if err := repo.CreateScan(ctx, defaultChild); err != nil {
		t.Fatalf("CreateScan(default project child): %v", err)
	}
	if defaultChild.ProjectUUID != DefaultProjectUUID {
		t.Fatalf("default scan project = %q, want %q", defaultChild.ProjectUUID, DefaultProjectUUID)
	}

	// Unknown parent UUIDs are legacy/import soft references and remain accepted.
	legacyParent := "unregistered-parent-" + uuid.NewString()
	legacyChild := uuid.NewString()
	if err := repo.CreateScan(ctx, &Scan{
		UUID: legacyChild, ProjectUUID: "child-project", AgenticScanUUID: legacyParent,
		Name: "legacy child", Status: "running",
	}); err != nil {
		t.Fatalf("CreateScan with unknown legacy parent: %v", err)
	}
	stored, err := repo.GetScanByUUID(ctx, legacyChild)
	if err != nil {
		t.Fatalf("GetScanByUUID: %v", err)
	}
	if stored.AgenticScanUUID != legacyParent {
		t.Fatalf("legacy parent UUID = %q, want %q", stored.AgenticScanUUID, legacyParent)
	}
}

func TestDeduplicatedFindingCannotAcquireKnownForeignAgenticRun(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	parentUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: parentUUID, ProjectUUID: "parent-project", Mode: "autopilot", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}

	findingHash := uuid.NewString()
	original := &Finding{
		ProjectUUID: "finding-project", HTTPRecordUUIDs: []string{},
		ModuleID: "parent-grouping-test", ModuleName: "parent grouping test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: findingHash,
	}
	if err := repo.SaveFindingDirect(ctx, original); err != nil {
		t.Fatalf("save original finding: %v", err)
	}
	incoming := &Finding{
		ProjectUUID: "finding-project", HTTPRecordUUIDs: []string{},
		AgenticScanUUID: parentUUID, ModuleID: "parent-grouping-test", ModuleName: "parent grouping test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: findingHash,
	}
	if err := repo.SaveFindingDirect(ctx, incoming); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("deduplicated SaveFindingDirect error = %v, want ErrScanProjectMismatch", err)
	}
	stored := &Finding{}
	if err := db.NewSelect().Model(stored).Where("finding_hash = ?", findingHash).Scan(ctx); err != nil {
		t.Fatalf("load canonical finding: %v", err)
	}
	if stored.AgenticScanUUID != "" {
		t.Fatalf("rejected occurrence assigned foreign parent %q to canonical finding", stored.AgenticScanUUID)
	}
	assertAgenticParentUnchanged(t, repo, parentUUID, "parent-project", "running", "")
}

func TestSaveFindingDirectRejectsKnownForeignAgenticRun(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	parentUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: parentUUID, ProjectUUID: "parent-project", Mode: "autopilot", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan: %v", err)
	}

	findingHash := uuid.NewString()
	finding := &Finding{
		ProjectUUID: "finding-project", HTTPRecordUUIDs: []string{},
		AgenticScanUUID: parentUUID, ModuleID: "parent-identity-test", ModuleName: "parent identity test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: findingHash,
	}
	if err := repo.SaveFindingDirect(ctx, finding); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("SaveFindingDirect error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings WHERE finding_hash = '"+findingHash+"'"); n != 0 {
		t.Fatalf("rejected finding write left %d finding rows", n)
	}
	assertAgenticParentUnchanged(t, repo, parentUUID, "parent-project", "running", "")

	// Historical/imported references may name a run absent from this database.
	// They remain valid soft references; only a known foreign owner is rejected.
	legacyParent := "unregistered-parent-" + uuid.NewString()
	legacyHash := uuid.NewString()
	legacyFinding := &Finding{
		ProjectUUID: "finding-project", HTTPRecordUUIDs: []string{},
		AgenticScanUUID: legacyParent, ModuleID: "legacy-parent-test", ModuleName: "legacy parent test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: legacyHash,
	}
	if err := repo.SaveFindingDirect(ctx, legacyFinding); err != nil {
		t.Fatalf("SaveFindingDirect with unknown legacy parent: %v", err)
	}
	stored := &Finding{}
	if err := db.NewSelect().Model(stored).Where("finding_hash = ?", legacyHash).Scan(ctx); err != nil {
		t.Fatalf("load legacy-parent finding: %v", err)
	}
	if stored.AgenticScanUUID != legacyParent {
		t.Fatalf("legacy finding parent UUID = %q, want %q", stored.AgenticScanUUID, legacyParent)
	}

	// Known same-project parents and normalized default-project ownership remain valid.
	sameProjectParent := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: sameProjectParent, ProjectUUID: "finding-project", Mode: "autopilot", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan(same-project parent): %v", err)
	}
	sameProjectHash := uuid.NewString()
	if err := repo.SaveFindingDirect(ctx, &Finding{
		ProjectUUID: "finding-project", HTTPRecordUUIDs: []string{}, AgenticScanUUID: sameProjectParent,
		ModuleID: "same-project-parent-test", ModuleName: "same-project parent test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: sameProjectHash,
	}); err != nil {
		t.Fatalf("SaveFindingDirect with same-project parent: %v", err)
	}

	defaultParent := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{UUID: defaultParent, Mode: "autopilot", Status: "running"}); err != nil {
		t.Fatalf("CreateAgenticScan(default parent): %v", err)
	}
	defaultFinding := &Finding{
		HTTPRecordUUIDs: []string{}, AgenticScanUUID: defaultParent,
		ModuleID: "default-parent-test", ModuleName: "default parent test",
		Severity: SeverityHigh, Confidence: "firm", FindingHash: uuid.NewString(),
	}
	if err := repo.SaveFindingDirect(ctx, defaultFinding); err != nil {
		t.Fatalf("SaveFindingDirect(default project): %v", err)
	}
	if defaultFinding.ProjectUUID != DefaultProjectUUID {
		t.Fatalf("default finding project = %q, want %q", defaultFinding.ProjectUUID, DefaultProjectUUID)
	}
}

func TestPg_AgenticParentOwnershipGuards(t *testing.T) {
	ctx := context.Background()
	db := openPGTestDB(t)
	repo := NewRepository(db)
	parentUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: parentUUID, ProjectUUID: "pg-parent-project", Mode: "swarm", Status: "running",
	}); err != nil {
		t.Fatalf("CreateAgenticScan(parent): %v", err)
	}

	agenticChildUUID := uuid.NewString()
	if err := repo.CreateAgenticScan(ctx, &AgenticScan{
		UUID: agenticChildUUID, ProjectUUID: "pg-child-project", ParentAgenticScanUUID: parentUUID,
		Mode: "audit", Status: "running",
	}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateAgenticScan foreign parent error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM agentic_scans WHERE uuid = '"+agenticChildUUID+"'"); n != 0 {
		t.Fatalf("rejected agentic child left %d rows", n)
	}

	scanUUID := uuid.NewString()
	if err := repo.CreateScan(ctx, &Scan{
		UUID: scanUUID, ProjectUUID: "pg-child-project", AgenticScanUUID: parentUUID,
		Name: "native child", Status: "running",
	}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("CreateScan foreign parent error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM scans WHERE uuid = '"+scanUUID+"'"); n != 0 {
		t.Fatalf("rejected native child left %d rows", n)
	}

	findingHash := uuid.NewString()
	if err := repo.SaveFindingDirect(ctx, &Finding{
		ProjectUUID: "pg-child-project", HTTPRecordUUIDs: []string{}, AgenticScanUUID: parentUUID,
		ModuleID: "pg-parent-guard", ModuleName: "pg parent guard", Severity: SeverityHigh,
		Confidence: "firm", FindingHash: findingHash,
	}); !errors.Is(err, ErrScanProjectMismatch) {
		t.Fatalf("SaveFindingDirect foreign parent error = %v, want ErrScanProjectMismatch", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings WHERE finding_hash = '"+findingHash+"'"); n != 0 {
		t.Fatalf("rejected finding left %d rows", n)
	}
	assertAgenticParentUnchanged(t, repo, parentUUID, "pg-parent-project", "running", "")
}
