package database

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type updateAttributionOperationKey struct{}

type updateAttributionLockHook struct {
	mu sync.Mutex

	firstAttempted map[string]chan struct{}
	firstAcquired  map[string]chan struct{}
	secondAttempt  map[string]chan struct{}
	attemptCount   map[string]int
	completeCount  map[string]int
	attemptTable   map[string]string
	acquiredTable  map[string]string
	forceRelease   chan struct{}
	forceOnce      sync.Once
}

func newUpdateAttributionLockHook() *updateAttributionLockHook {
	return &updateAttributionLockHook{
		firstAttempted: map[string]chan struct{}{
			"update": make(chan struct{}), "attribute": make(chan struct{}),
		},
		firstAcquired: map[string]chan struct{}{
			"update": make(chan struct{}), "attribute": make(chan struct{}),
		},
		secondAttempt: map[string]chan struct{}{
			"update": make(chan struct{}), "attribute": make(chan struct{}),
		},
		attemptCount:  make(map[string]int),
		completeCount: make(map[string]int),
		attemptTable:  make(map[string]string),
		acquiredTable: make(map[string]string),
		forceRelease:  make(chan struct{}),
	}
}

func (h *updateAttributionLockHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	operation, ok := ctx.Value(updateAttributionOperationKey{}).(string)
	if !ok {
		return ctx
	}
	table := updateAttributionLockedTable(event.Query)
	if table == "" {
		return ctx
	}

	h.mu.Lock()
	h.attemptCount[operation]++
	switch h.attemptCount[operation] {
	case 1:
		h.attemptTable[operation] = table
		close(h.firstAttempted[operation])
	case 2:
		close(h.secondAttempt[operation])
	}
	h.mu.Unlock()
	return ctx
}

func (h *updateAttributionLockHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	operation, ok := ctx.Value(updateAttributionOperationKey{}).(string)
	if !ok {
		return
	}
	table := updateAttributionLockedTable(event.Query)
	if table == "" {
		return
	}

	h.mu.Lock()
	h.completeCount[operation]++
	first := h.completeCount[operation] == 1
	if first {
		h.acquiredTable[operation] = table
		close(h.firstAcquired[operation])
	}
	h.mu.Unlock()
	if !first {
		return
	}

	other := "attribute"
	if operation == "attribute" {
		other = "update"
	}
	if !h.wait(ctx, h.firstAttempted[other]) {
		return
	}

	h.mu.Lock()
	sameLock := h.acquiredTable[operation] == h.attemptTable[other]
	h.mu.Unlock()
	if sameLock {
		// With consistent parent-first ordering, one operation waits on the
		// same parent row. Let the holder proceed to commit rather than making
		// the test harness itself wait for two simultaneous acquisitions.
		return
	}

	// For the current inverse ordering, attribution owns the parent lock and
	// waits until the updater is about to request it. The updater is released
	// as soon as attribution owns its distinct first lock. This advances both
	// transactions to their conflicting second lock without making both hook
	// callbacks wait on each other.
	if !h.wait(ctx, h.firstAcquired[other]) {
		return
	}
	if operation == "attribute" {
		_ = h.wait(ctx, h.secondAttempt[other])
	}
}

func (h *updateAttributionLockHook) wait(ctx context.Context, signal <-chan struct{}) bool {
	select {
	case <-signal:
		return true
	case <-ctx.Done():
		return false
	case <-h.forceRelease:
		return false
	}
}

func (h *updateAttributionLockHook) release() {
	h.forceOnce.Do(func() { close(h.forceRelease) })
}

func (h *updateAttributionLockHook) lockAttempts(operation string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attemptCount[operation]
}

func updateAttributionLockedTable(query string) string {
	query = strings.ToLower(query)
	if !strings.Contains(query, "for update") {
		return ""
	}
	if strings.Contains(query, `"agentic_scans"`) {
		return "agentic_scans"
	}
	if strings.Contains(query, `"scans"`) {
		return "scans"
	}
	return ""
}

func TestPg_ConcurrentScanUpdateAndAttribution(t *testing.T) {
	for _, updateKind := range []string{"full", "partial"} {
		t.Run(updateKind, func(t *testing.T) {
			db := openPGTestDB(t)
			repo := NewRepository(db)
			ctx := context.Background()
			projectUUID := "update-attribution-project"
			parentUUID := uuid.NewString()
			scanUUID := uuid.NewString()
			parent := &AgenticScan{
				UUID: parentUUID, ProjectUUID: projectUUID, Mode: "swarm", AgentName: "lock-parent", Status: "running",
			}
			if err := repo.CreateAgenticScan(ctx, parent); err != nil {
				t.Fatalf("CreateAgenticScan(parent): %v", err)
			}
			scan := &Scan{
				UUID: scanUUID, ProjectUUID: projectUUID, Name: "lock-order scan", Status: "running",
			}
			if err := repo.CreateScan(ctx, scan); err != nil {
				t.Fatalf("CreateScan(child): %v", err)
			}
			historicalParent := "historical-parent-" + uuid.NewString()
			findingID := saveFindingFull(t, repo, &Finding{
				ProjectUUID: projectUUID, ScanUUID: scanUUID, AgenticScanUUID: historicalParent,
				FindingHash: uuid.NewString(), ModuleID: "lock-order", ModuleName: "lock-order",
			})
			occurrencesBefore := scalarInt(t, db, fmt.Sprintf("SELECT COUNT(*) FROM finding_observations WHERE finding_id = %d", findingID))

			hook := newUpdateAttributionLockHook()
			db.AddQueryHook(hook)
			updateCtx, cancelUpdate := context.WithTimeout(context.WithValue(context.Background(), updateAttributionOperationKey{}, "update"), 10*time.Second)
			attributeCtx, cancelAttribute := context.WithTimeout(context.WithValue(context.Background(), updateAttributionOperationKey{}, "attribute"), 10*time.Second)
			t.Cleanup(func() {
				cancelUpdate()
				cancelAttribute()
				hook.release()
			})

			start := make(chan struct{})
			type operationResult struct {
				operation string
				err       error
			}
			results := make(chan operationResult, 2)
			go func() {
				<-start
				var err error
				if updateKind == "full" {
					patch, readErr := repo.GetScanByUUID(updateCtx, scanUUID)
					if readErr != nil {
						results <- operationResult{operation: "update", err: fmt.Errorf("read scan for full update: %w", readErr)}
						return
					}
					patch.AgenticScanUUID = parentUUID
					patch.Status = "paused"
					err = repo.UpdateScan(updateCtx, patch)
				} else {
					err = repo.UpdateScanPartial(updateCtx, &Scan{
						UUID: scanUUID, AgenticScanUUID: parentUUID, Status: "paused",
					})
				}
				results <- operationResult{operation: "update", err: err}
			}()
			go func() {
				<-start
				results <- operationResult{operation: "attribute", err: repo.AttributeScanToAgenticScan(attributeCtx, scanUUID, parentUUID)}
			}()
			close(start)

			var updateErr, attributeErr error
			for range 2 {
				result := <-results
				if result.operation == "update" {
					updateErr = result.err
				} else {
					attributeErr = result.err
				}
			}
			if updateErr != nil {
				t.Errorf("concurrent %s scan update: %v", updateKind, updateErr)
			}
			if attributeErr != nil {
				t.Errorf("concurrent attribution: %v", attributeErr)
			}
			if updateErr != nil || attributeErr != nil {
				return
			}
			if got := hook.lockAttempts("update"); got != 2 {
				t.Fatalf("query hook observed %d updater row locks, want 2", got)
			}
			if got := hook.lockAttempts("attribute"); got != 2 {
				t.Fatalf("query hook observed %d attribution row locks, want 2", got)
			}

			stored, err := repo.GetScanByUUID(ctx, scanUUID)
			if err != nil {
				t.Fatalf("GetScanByUUID: %v", err)
			}
			if stored.ProjectUUID != projectUUID || stored.AgenticScanUUID != parentUUID || stored.Status != "paused" {
				t.Fatalf("unexpected final scan owner/parent/status = %q/%q/%q", stored.ProjectUUID, stored.AgenticScanUUID, stored.Status)
			}
			storedFinding := &Finding{}
			if err := db.NewSelect().Model(storedFinding).Where("id = ?", findingID).Scan(ctx); err != nil {
				t.Fatalf("read historical finding: %v", err)
			}
			if storedFinding.ProjectUUID != projectUUID || storedFinding.ScanUUID != scanUUID || storedFinding.AgenticScanUUID != historicalParent {
				t.Fatalf("historical finding attribution changed: project/scan/parent=%q/%q/%q", storedFinding.ProjectUUID, storedFinding.ScanUUID, storedFinding.AgenticScanUUID)
			}
			occurrencesAfter := scalarInt(t, db, fmt.Sprintf("SELECT COUNT(*) FROM finding_observations WHERE finding_id = %d", findingID))
			if occurrencesAfter != occurrencesBefore {
				t.Fatalf("attribution changed occurrence history: before=%d after=%d", occurrencesBefore, occurrencesAfter)
			}
		})
	}
}
