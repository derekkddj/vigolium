package cli

import (
	"context"
	"fmt"
	"slices"

	"github.com/vigolium/vigolium/pkg/database"
)

// Pending OAST metadata is independent of findings and crawl traffic. Keep the
// context and actual execution as separate, binary-safe importer envelopes.
// Search/URL dedup must not substitute planting intent or discard pending proof.
func streamPendingOAST(ctx context.Context, db *database.DB, projectUUID, scanUUID string, emit func(string, any) error) error {
	scans := topExportScanUUIDs
	if scanUUID != "" {
		if len(scans) > 0 && !slices.Contains(scans, scanUUID) {
			return nil
		}
		scans = []string{scanUUID}
	}
	repo := database.NewRepository(db)
	// The caller gates on the "oast" export type, which covers both envelopes.
	if err := repo.WalkOASTPayloadContexts(ctx, projectUUID, scans, func(p *database.OASTPayload) error {
		return emit("oast_payload", p)
	}); err != nil {
		return fmt.Errorf("export pending OAST context: %w", err)
	}
	if err := repo.WalkOASTPlantingReceipts(ctx, projectUUID, scans, func(row *database.OASTPlantingReceipt) error {
		return emit("oast_planting_receipt", row)
	}); err != nil {
		return fmt.Errorf("export pending OAST planting receipts: %w", err)
	}
	return nil
}
