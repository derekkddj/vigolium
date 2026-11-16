package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/vigolium/vigolium/pkg/evidence"
)

// EvidenceExchange is immutable after insertion. Its identity is an execution
// receipt, never a request hash or a URL. Both messages use binary columns.
type EvidenceExchange struct {
	bun.BaseModel `bun:"table:evidence_exchanges,alias:ee" json:"-"`
	ProjectUUID   string              `bun:"project_uuid,pk"`
	ID            string              `bun:"id,pk"`
	URL           string              `bun:"url,notnull"`
	Service       string              `bun:"service,notnull"`
	Request       []byte              `bun:"raw_request"`
	Response      []byte              `bun:"raw_response"`
	RequestState  evidence.State      `bun:"request_state,notnull"`
	ResponseState evidence.State      `bun:"response_state,notnull"`
	Provenance    evidence.Provenance `bun:"provenance,notnull"`
	ContentHash   string              `bun:"content_hash,notnull"`
	CapturedAt    time.Time           `bun:"captured_at,notnull,type:text"`
}

// Fixed fractional width also makes the portable UTC metadata sortable. Receipt
// capture time must not lose nanoseconds through a backend timestamp formatter.
func evidenceCaptureTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func exchangeRow(project string, x *evidence.Exchange) *EvidenceExchange {
	return &EvidenceExchange{ProjectUUID: defaultProjectUUID(project), ID: x.ID,
		URL: x.URL, Service: x.Service, Request: x.Request, Response: x.Response,
		RequestState: x.RequestState, ResponseState: x.ResponseState,
		Provenance: x.Provenance, ContentHash: x.ContentHash, CapturedAt: x.CapturedAt}
}

func (row *EvidenceExchange) exchange() *evidence.Exchange {
	return (&evidence.Exchange{ID: row.ID, URL: row.URL, Service: row.Service,
		Request: row.Request, Response: row.Response, RequestState: row.RequestState,
		ResponseState: row.ResponseState, Provenance: row.Provenance,
		ContentHash: row.ContentHash, CapturedAt: row.CapturedAt}).Clone()
}

// FindingEvidence is scoped through its finding. Every role/primary selection,
// label, URL, scan and occurrence is retained, including across grouping.
type FindingEvidence struct {
	bun.BaseModel   `bun:"table:finding_evidence,alias:fe" json:"-"`
	ID              int64         `bun:"id,pk,autoincrement"`
	FindingID       int64         `bun:"finding_id,notnull"`
	AssociationHash string        `bun:"association_hash,notnull"`
	ExchangeID      string        `bun:"exchange_id,notnull"`
	Role            evidence.Role `bun:"role,notnull"`
	Primary         bool          `bun:"is_primary,notnull"`
	Label           string        `bun:"label,notnull"`
	OccurrenceID    string        `bun:"occurrence_id,notnull"`
	FindingURL      string        `bun:"finding_url,notnull"`
	ScanUUID        string        `bun:"scan_uuid,notnull"`
}

func (row *FindingEvidence) entry() evidence.Entry {
	return evidence.Entry{ExchangeID: row.ExchangeID, Role: row.Role, Primary: row.Primary,
		Label: row.Label, OccurrenceID: row.OccurrenceID, FindingURL: row.FindingURL, ScanUUID: row.ScanUUID}
}

func evidenceAssociationHash(entry evidence.Entry) string {
	// Manifest fields are a fixed struct of scalars; JSON provides unambiguous
	// framing even for labels/URLs containing delimiters or NUL bytes.
	b, _ := json.Marshal(entry.Manifest())
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// prepareFindingEvidence owns receipt bytes, preserves unsafe incoming legacy
// binary text before projecting it for SQL TEXT, and normalizes missing association
// context. It never infers a proof role or execution service/URL from legacy text.
// Done before transactions so generated occurrence IDs survive batch retries.
func prepareFindingEvidence(f *Finding) error {
	f.Evidence = evidence.CloneEntries(f.Evidence)
	prepareFindingLegacyText(f)
	occurrence := ""
	for i := range f.Evidence {
		e := &f.Evidence[i]
		if e.Exchange != nil {
			if err := e.Exchange.Validate(); err != nil {
				return err
			}
			if e.ExchangeID == "" {
				e.ExchangeID = e.Exchange.ID
			}
			if e.ExchangeID != e.Exchange.ID {
				return fmt.Errorf("evidence association identity does not match receipt")
			}
		}
		if e.ExchangeID == "" {
			return fmt.Errorf("evidence association has no exchange identity")
		}
		if e.Role == "" {
			e.Role = evidence.RoleUnknown
		}
		if !evidence.ValidRole(e.Role) {
			return fmt.Errorf("invalid evidence role %q", e.Role)
		}
		if e.OccurrenceID == "" {
			if occurrence == "" {
				occurrence = uuid.NewString()
			}
			e.OccurrenceID = occurrence
		}
		if e.FindingURL == "" {
			e.FindingURL = f.URL
		}
		if e.ScanUUID == "" {
			e.ScanUUID = f.ScanUUID
		}
	}
	return nil
}

// persistEvidenceExchange is shared by selected findings and pending OAST
// bindings. Callers supply their transaction; it creates no finding association.
// A reused identity must match every immutable field, including actual bytes.
func persistEvidenceExchange(ctx context.Context, idb bun.IDB, project string, x *evidence.Exchange) error {
	if err := x.Validate(); err != nil {
		return err
	}
	row := exchangeRow(project, x)
	res, err := idb.NewInsert().Model(row).On("CONFLICT (project_uuid, id) DO NOTHING").
		Value("captured_at", "?", evidenceCaptureTime(x.CapturedAt)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("insert evidence exchange: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		var stored EvidenceExchange
		if err := idb.NewSelect().Model(&stored).Where("project_uuid = ?", row.ProjectUUID).
			Where("id = ?", x.ID).Scan(ctx); err != nil {
			return err
		}
		if !equalEvidenceExchanges(stored.exchange(), x) {
			return fmt.Errorf("immutable evidence exchange %s identity/content mismatch", x.ID)
		}
	}
	return nil
}

func equalEvidenceExchanges(a, b *evidence.Exchange) bool {
	return a.ID == b.ID && a.URL == b.URL && a.Service == b.Service &&
		a.Provenance == b.Provenance && a.RequestState == b.RequestState &&
		a.ResponseState == b.ResponseState && a.ContentHash == b.ContentHash &&
		a.CapturedAt.Equal(b.CapturedAt) && bytes.Equal(a.Request, b.Request) && bytes.Equal(a.Response, b.Response)
}

func (r *Repository) persistFindingEvidence(ctx context.Context, idb bun.IDB, f *Finding) error {
	for _, e := range f.Evidence {
		if e.Exchange != nil {
			if err := persistEvidenceExchange(ctx, idb, f.ProjectUUID, e.Exchange); err != nil {
				return err
			}
		}
		row := &FindingEvidence{FindingID: f.ID, AssociationHash: evidenceAssociationHash(e),
			ExchangeID: e.ExchangeID, Role: e.Role, Primary: e.Primary, Label: e.Label,
			OccurrenceID: e.OccurrenceID, FindingURL: e.FindingURL, ScanUUID: e.ScanUUID}
		if _, err := idb.NewInsert().Model(row).On("CONFLICT (finding_id, association_hash) DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("insert finding evidence: %w", err)
		}
	}
	return nil
}

// GetEvidenceExchange resolves an exact identity within one project. Blank
// project means default, NEVER all projects. Missing identities return
// sql.ErrNoRows; there is deliberately no crawl-record or URL fallback.
func (r *Repository) GetEvidenceExchange(ctx context.Context, id, projectUUID string) (*evidence.Exchange, error) {
	row := &EvidenceExchange{}
	if err := r.db.NewSelect().Model(row).Where("id = ?", id).
		Where("project_uuid = ?", defaultProjectUUID(projectUUID)).Scan(ctx); err != nil {
		return nil, err
	}
	x := row.exchange()
	if err := x.Validate(); err != nil {
		return nil, err
	}
	return x, nil
}

// HydrateFindingEvidenceManifest loads association metadata only. Project checks
// match each requested finding before exposing its associations. No raw bytes,
// joins by URL, historical inference, or writes are performed.
func (r *Repository) HydrateFindingEvidenceManifest(ctx context.Context, findings []*Finding) error {
	byProject := make(map[string]map[int64][]*Finding)
	for _, f := range findings {
		if f == nil || f.ID == 0 {
			continue
		}
		project := defaultProjectUUID(f.ProjectUUID)
		if byProject[project] == nil {
			byProject[project] = make(map[int64][]*Finding)
		}
		byProject[project][f.ID] = append(byProject[project][f.ID], f)
		f.Evidence = nil
	}
	for project, idx := range byProject {
		ids := make([]int64, 0, len(idx))
		for id := range idx {
			ids = append(ids, id)
		}
		for chunk := range slices.Chunk(ids, SQLChunkSize) {
			var rows []*FindingEvidence
			if err := r.db.NewSelect().Model(&rows).ColumnExpr("fe.*").
				Join("JOIN findings f ON f.id = fe.finding_id").
				Where("f.project_uuid = ?", project).Where("fe.finding_id IN (?)", bun.List(chunk)).
				OrderExpr("fe.finding_id ASC, fe.id ASC").Scan(ctx); err != nil {
				return err
			}
			for _, row := range rows {
				for _, f := range idx[row.FindingID] {
					f.Evidence = append(f.Evidence, row.entry())
				}
			}
		}
	}
	return nil
}

// HydrateFindingEvidenceForExport loads receipts for ONE selected finding. An
// unavailable receipt remains a manifest entry rather than fabricated bytes.
// Exporters can stream findings and release each finding's bytes afterwards.
func (r *Repository) HydrateFindingEvidenceForExport(ctx context.Context, f *Finding) error {
	if f == nil {
		return nil
	}
	if err := r.HydrateFindingEvidenceManifest(ctx, []*Finding{f}); err != nil {
		return err
	}
	for i := range f.Evidence {
		x, err := r.GetEvidenceExchange(ctx, f.Evidence[i].ExchangeID, f.ProjectUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
		f.Evidence[i].Exchange = x
	}
	return nil
}

// migrateFindingEvidenceTx keeps all association metadata and primary flags,
// without replacing any survivor selection. It never hydrates receipt bodies.
func migrateFindingEvidenceTx(ctx context.Context, tx bun.Tx, survivorID int64, dupIDs []int64) error {
	for chunk := range slices.Chunk(dupIDs, SQLChunkSize) {
		if _, err := tx.NewRaw(`INSERT INTO finding_evidence
			(finding_id, association_hash, exchange_id, role, is_primary, label, occurrence_id, finding_url, scan_uuid)
			SELECT ?, fe.association_hash, fe.exchange_id, fe.role, fe.is_primary, fe.label, fe.occurrence_id, fe.finding_url, fe.scan_uuid
			FROM finding_evidence fe JOIN findings d ON d.id = fe.finding_id
			JOIN findings s ON s.id = ? AND s.project_uuid = d.project_uuid
			WHERE fe.finding_id IN (?) ORDER BY fe.id ASC
			ON CONFLICT (finding_id, association_hash) DO NOTHING`, survivorID, survivorID, bun.List(chunk)).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
