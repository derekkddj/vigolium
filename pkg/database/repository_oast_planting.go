package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/oast/planting"
)

// OASTPlantingReceipt binds an actual execution to project+nonce+scan until a
// late callback selects it. Canonical bytes live ONLY in evidence_exchanges.
// Receipt is nonpersisted JSON/base64 compatibility data, materialized for one
// owned binding at an import/export boundary, never exposed by generic table APIs.
type OASTPlantingReceipt struct {
	bun.BaseModel `bun:"table:oast_planting_receipts,alias:opr" json:"-"`
	ProjectUUID   string `bun:"project_uuid,pk" json:"project_uuid"`
	Nonce         string `bun:"nonce,pk" json:"nonce"`
	ScanUUID      string `bun:"scan_uuid,notnull" json:"scan_uuid"`
	ExchangeID    string `bun:"exchange_id,notnull" json:"exchange_id,omitempty"`
	Receipt       string `bun:"-" json:"receipt"`
}

var ErrOASTPlantingReceiptConflict = errors.New("OAST planting receipt identity conflict")

// Exchange validates retained bytes, not planting intent. Imports cannot use a
// cached observation, absent request, or substring of another nonce as proof.
func (row *OASTPlantingReceipt) Exchange() (*evidence.Exchange, error) {
	if row == nil || strings.TrimSpace(row.ProjectUUID) == "" || row.Nonce == "" {
		return nil, fmt.Errorf("OAST planting receipt has no project/nonce binding")
	}
	for _, b := range []byte(row.Nonce) {
		if !planting.NonceByte(b) {
			return nil, fmt.Errorf("invalid OAST planting nonce")
		}
	}
	var x evidence.Exchange
	if err := json.Unmarshal([]byte(row.Receipt), &x); err != nil {
		return nil, fmt.Errorf("decode OAST planting receipt: %w", err)
	}
	if err := x.Validate(); err != nil {
		return nil, err
	}
	if row.ExchangeID != "" && row.ExchangeID != x.ID {
		return nil, fmt.Errorf("%w: binding does not match execution identity", ErrOASTPlantingReceiptConflict)
	}
	if x.Provenance != evidence.ProvenanceCaptured || x.RequestState == evidence.StateMissing || len(x.Request) == 0 || !oastRequestContainsNonce(x.Request, row.Nonce) {
		return nil, fmt.Errorf("OAST planting receipt has no captured nonce-bearing request")
	}
	return &x, nil
}

func oastRequestContainsNonce(raw []byte, nonce string) bool {
	return planting.ContainsNonceToken(raw, nonce)
}

// No URL/hash matching: declared context must occur in its actual emitted slot.
// Older contexts without the human label may certify headers only when their
// explicit class is header-harvest; a nonce in an incidental Referer is rejected.
func validateOASTPlantingContext(row *OASTPlantingReceipt, x *evidence.Exchange, p *OASTPayload) error {
	if x.Provenance != evidence.ProvenanceCaptured || x.RequestState == evidence.StateMissing || len(x.Request) == 0 {
		return fmt.Errorf("%w: context has no actual captured request", ErrOASTPlantingReceiptConflict)
	}
	if p.ProjectUUID != row.ProjectUUID || p.Nonce != row.Nonce || p.ScanUUID != row.ScanUUID {
		return fmt.Errorf("%w: nonce context belongs to another project/scan", ErrOASTPlantingReceiptConflict)
	}
	header := p.Class == string(oastclass.HeaderHarvest) || strings.Contains(strings.ToLower(p.InjectionType), "header")
	if !planting.MatchesSlot(x.Request, row.Nonce, p.Param, p.Payload, header) {
		return fmt.Errorf("%w: nonce is absent from its declared planting slot/context", ErrOASTPlantingReceiptConflict)
	}
	return nil
}

// hydrateOASTPlantingReceipt resolves only an already-owned OAST binding. The
// internal canonical lookup is deliberately not a new generic pending-raw API.
func hydrateOASTPlantingReceipt(ctx context.Context, idb bun.IDB, row *OASTPlantingReceipt) error {
	var stored EvidenceExchange
	if err := idb.NewSelect().Model(&stored).Where("project_uuid = ?", row.ProjectUUID).
		Where("id = ?", row.ExchangeID).Scan(ctx); err != nil {
		return err
	}
	data, err := json.Marshal(stored.exchange())
	if err != nil {
		return err
	}
	row.Receipt = string(data)
	_, err = row.Exchange()
	return err
}

// GetOASTPlantingReceipt requires the full ownership tuple, never a global-last
// receipt. It is for OAST recovery/export; public raw APIs still require a finding.
func (r *Repository) GetOASTPlantingReceipt(ctx context.Context, project, nonce, scan string) (*OASTPlantingReceipt, error) {
	var row OASTPlantingReceipt
	if err := r.db.NewSelect().Model(&row).Where("project_uuid = ?", defaultProjectUUID(project)).
		Where("nonce = ?", nonce).Where("scan_uuid = ?", scan).Scan(ctx); err != nil {
		return nil, err
	}
	if err := hydrateOASTPlantingReceipt(ctx, r.db, &row); err != nil {
		return nil, err
	}
	return &row, nil
}

func equalOASTPlantingReceipts(a, b *OASTPlantingReceipt) error {
	x, err := a.Exchange()
	if err != nil {
		return fmt.Errorf("%w: existing receipt invalid: %v", ErrOASTPlantingReceiptConflict, err)
	}
	y, err := b.Exchange()
	if err != nil {
		return fmt.Errorf("%w: incoming receipt invalid: %v", ErrOASTPlantingReceiptConflict, err)
	}
	if a.ProjectUUID != b.ProjectUUID || a.Nonce != b.Nonce || a.ScanUUID != b.ScanUUID || !equalEvidenceExchanges(x, y) {
		return fmt.Errorf("%w: nonce %s changed execution, bytes, capture time or ownership", ErrOASTPlantingReceiptConflict, b.Nonce)
	}
	return nil
}

// SaveOASTPlantingReceipt is append-only and scoped. It never migrates the store
// in a transport callback; callers must use CreateSchema/EnsureSchemaReady first.
func (r *Repository) SaveOASTPlantingReceipt(ctx context.Context, row *OASTPlantingReceipt) error {
	x, err := row.Exchange()
	if err != nil {
		return err
	}
	// Own caller data before entering the transaction; Receipt never becomes a
	// database column and canonical insertion plus binding commit atomically.
	owned := *row
	owned.ExchangeID = x.ID
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		var p OASTPayload
		err := tx.NewSelect().Model(&p).Where("nonce = ?", owned.Nonce).Scan(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if err := validateOASTPlantingContext(&owned, x, &p); err != nil {
				return err
			}
		}
		if err := persistEvidenceExchange(ctx, tx, owned.ProjectUUID, x); err != nil {
			return fmt.Errorf("%w: %v", ErrOASTPlantingReceiptConflict, err)
		}
		if _, err := tx.NewInsert().Model(&owned).On("CONFLICT (project_uuid, nonce) DO NOTHING").Exec(ctx); err != nil {
			return err
		}
		var old OASTPlantingReceipt
		if err := tx.NewSelect().Model(&old).Where("project_uuid = ?", owned.ProjectUUID).Where("nonce = ?", owned.Nonce).Scan(ctx); err != nil {
			return err
		}
		if old.ScanUUID != owned.ScanUUID || old.ExchangeID != owned.ExchangeID {
			return fmt.Errorf("%w: nonce changed execution or ownership", ErrOASTPlantingReceiptConflict)
		}
		return nil
	})
}

// ImportOASTPayloadContext retains exported nonce context without silently
// overriding an existing nonce's intent or moving it to another project/scan.
func (r *Repository) ImportOASTPayloadContext(ctx context.Context, p *OASTPayload) error {
	if p == nil || p.Nonce == "" || strings.TrimSpace(p.ProjectUUID) == "" || p.CreatedAt.IsZero() {
		return fmt.Errorf("OAST payload context has no nonce/project/time binding")
	}
	return r.db.RunInTx(ctx, &sql.TxOptions{}, func(ctx context.Context, tx bun.Tx) error {
		var conflicts int
		if err := tx.NewRaw("SELECT COUNT(*) FROM oast_planting_receipts WHERE nonce = ? AND (project_uuid <> ? OR scan_uuid <> ?)", p.Nonce, p.ProjectUUID, p.ScanUUID).Scan(ctx, &conflicts); err != nil {
			return err
		}
		if conflicts > 0 {
			return fmt.Errorf("%w: nonce receipt belongs to another project/scan", ErrOASTPlantingReceiptConflict)
		}
		var binding OASTPlantingReceipt
		err := tx.NewSelect().Model(&binding).Where("project_uuid = ?", p.ProjectUUID).Where("nonce = ?", p.Nonce).Scan(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if err := hydrateOASTPlantingReceipt(ctx, tx, &binding); err != nil {
				return err
			}
			x, err := binding.Exchange()
			if err != nil {
				return err
			}
			if err := validateOASTPlantingContext(&binding, x, p); err != nil {
				return err
			}
		}
		res, err := tx.NewInsert().Model(p).On("CONFLICT (nonce) DO NOTHING").
			Value("created_at", "?", evidenceCaptureTime(p.CreatedAt)).Exec(ctx)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n > 0 {
			return nil
		}
		var old OASTPayload
		if err := tx.NewSelect().Model(&old).Where("nonce = ?", p.Nonce).Scan(ctx); err != nil {
			return err
		}
		if old.ProjectUUID != p.ProjectUUID || old.ScanUUID != p.ScanUUID || old.Class != p.Class || old.InjectionType != p.InjectionType || old.ModuleID != p.ModuleID || old.TargetURL != p.TargetURL || old.Param != p.Param || old.RequestHash != p.RequestHash || old.Payload != p.Payload || !old.CreatedAt.Equal(p.CreatedAt) {
			return fmt.Errorf("%w: nonce payload context changed", ErrOASTPlantingReceiptConflict)
		}
		return nil
	})
}

// Catalog errors are not mistaken for a historical table's absence.
func (r *Repository) oastTableExists(ctx context.Context, table string) (bool, error) {
	query := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?"
	if r.db.Driver() == "postgres" {
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?"
	}
	var n int
	err := r.db.NewRaw(query, table).Scan(ctx, &n)
	return n > 0, err
}

func (r *Repository) oastColumnExists(ctx context.Context, table, column string) (bool, error) {
	query := "SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?"
	if r.db.Driver() == "postgres" {
		query = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?"
	}
	var n int
	err := r.db.NewRaw(query, table, column).Scan(ctx, &n)
	return n > 0, err
}

// WalkOASTPayloadContexts streams pending nonce attribution, including contexts
// without findings. No planting proof is inferred from these intent rows.
func (r *Repository) WalkOASTPayloadContexts(ctx context.Context, projectUUID string, scanUUIDs []string, emit func(*OASTPayload) error) error {
	if exists, err := r.oastTableExists(ctx, "oast_payloads"); err != nil {
		return err
	} else if !exists {
		return nil
	}
	hasLabel, err := r.oastColumnExists(ctx, "oast_payloads", "injection_type")
	if err != nil {
		return err
	}
	var nonce string
	for {
		var row OASTPayload
		q := r.db.NewSelect().Model(&row).OrderExpr("nonce ASC").Limit(1)
		if !hasLabel {
			q.ExcludeColumn("injection_type")
		}
		if projectUUID != "" {
			q.Where("project_uuid = ?", projectUUID)
		}
		if len(scanUUIDs) > 0 {
			q.Where("scan_uuid IN (?)", bun.List(scanUUIDs))
		}
		if nonce != "" {
			q.Where("nonce > ?", nonce)
		}
		err := q.Scan(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if row.Nonce == "" || row.ProjectUUID == "" {
			return fmt.Errorf("OAST context has no nonce/project binding")
		}
		if err := emit(&row); err != nil {
			return err
		}
		nonce = row.Nonce
	}
}

// WalkOASTPlantingReceipts closes each one-row keyset read before yielding, so
// consumers may resolve context even with a single database connection. Empty
// project explicitly requests a whole-store export; scan filters remain exact.
func (r *Repository) WalkOASTPlantingReceipts(ctx context.Context, projectUUID string, scanUUIDs []string, emit func(*OASTPlantingReceipt) error) error {
	if exists, err := r.oastTableExists(ctx, "oast_planting_receipts"); err != nil {
		return err
	} else if !exists {
		return nil
	}
	legacy, err := r.oastColumnExists(ctx, "oast_planting_receipts", "receipt")
	if err != nil {
		return err
	}
	var project, nonce string
	for {
		var row OASTPlantingReceipt
		q := r.db.NewSelect().Model(&row).OrderExpr("project_uuid ASC, nonce ASC").Limit(1)
		if legacy {
			q.ExcludeColumn("exchange_id")
		}
		if projectUUID != "" {
			q.Where("project_uuid = ?", projectUUID)
		}
		if len(scanUUIDs) > 0 {
			q.Where("scan_uuid IN (?)", bun.List(scanUUIDs))
		}
		if nonce != "" {
			q.Where("(project_uuid > ? OR (project_uuid = ? AND nonce > ?))", project, project, nonce)
		}
		err := q.Scan(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if legacy {
			// Read-only legacy exports are an import boundary, not a schema
			// repair. Decode one old row without retaining a TEXT authority in
			// any new store, and never synthesize bytes from crawl context.
			if err := r.db.NewRaw("SELECT receipt FROM oast_planting_receipts WHERE project_uuid = ? AND nonce = ?", row.ProjectUUID, row.Nonce).Scan(ctx, &row.Receipt); err != nil {
				return err
			}
			x, err := row.Exchange()
			if err != nil {
				return err
			}
			row.ExchangeID = x.ID
		} else if err := hydrateOASTPlantingReceipt(ctx, r.db, &row); err != nil {
			return err
		}
		if err := emit(&row); err != nil {
			return err
		}
		project, nonce = row.ProjectUUID, row.Nonce
	}
}
