package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/evidence"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// hydrateFindingReaderEvidence must hydrate legacy fields BEFORE selected receipts:
// legacy hydration reloads the manifest and discards previously hydrated exchanges.
func hydrateFindingReaderEvidence(ctx context.Context, repo *database.Repository, findings []*database.Finding, inline, raw bool) error {
	if inline && repo != nil {
		if err := repo.HydrateFindingEvidence(ctx, findings); err != nil {
			return fmt.Errorf("failed to load inline finding evidence: %w", err)
		}
	}
	if repo != nil {
		if err := repo.HydrateFindingRecordRefs(ctx, findings); err != nil {
			return fmt.Errorf("failed to load finding record references: %w", err)
		}
	}
	for _, f := range findings {
		if err := hydrateSelectedFindingEvidence(ctx, repo, f, raw); err != nil {
			return fmt.Errorf("failed to load selected finding evidence: %w", err)
		}
	}
	return nil
}

// hydrateSelectedFindingEvidence preserves manifest roles and occurrence metadata.
// Bodies are read per exact receipt, scoped to the stored finding project; neither
// URL matches nor linked-record order can supply a missing proof.
func hydrateSelectedFindingEvidence(ctx context.Context, repo *database.Repository, f *database.Finding, raw bool) error {
	if repo == nil {
		return nil
	}
	if f.ID != 0 {
		if err := repo.HydrateFindingEvidenceManifest(ctx, []*database.Finding{f}); err != nil {
			return err
		}
	}
	if !raw {
		return nil
	}
	for i := range f.Evidence {
		e := &f.Evidence[i]
		if e.Exchange != nil {
			continue
		}
		if f.ProjectUUID == "" {
			return fmt.Errorf("finding %d has no captured project for evidence read", f.ID)
		}
		if e.ExchangeID == "" {
			continue
		}
		x, err := repo.GetEvidenceExchange(ctx, e.ExchangeID, f.ProjectUUID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		} // keep unavailable association, never substitute
		if err != nil {
			return fmt.Errorf("finding %d exchange %s: %w", f.ID, e.ExchangeID, err)
		}
		e.Exchange = x
	}
	return nil
}

// selectedReceiptURL takes the destination and request path from a restorable
// receipt, not the finding/display URL. Response-only views may keep a display
// path, but never use it to recover a captured service.
func selectedReceiptURL(x *evidence.Exchange) (*url.URL, error) {
	item, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		return nil, err
	}
	if len(x.Request) > 0 {
		u, err := item.URL()
		if err != nil {
			return nil, err
		}
		return u.URL, nil // owned copy; the pinned service wins over absolute form
	}
	target := x.Service
	if target == "" {
		target = x.URL
	} // FromEvidenceExchange checked supplied provenance
	destination, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if display, err := url.Parse(x.URL); err == nil {
		destination.Path, destination.RawPath = display.Path, display.RawPath
		destination.RawQuery, destination.ForceQuery = display.RawQuery, display.ForceQuery
	}
	return destination, nil
}

func sourceFromSelectedFinding(f *database.Finding) (*replaySource, error) {
	entry := primaryFindingEntry(f)
	if entry == nil || entry.Exchange == nil || entry.ExchangeID != entry.Exchange.ID || entry.Exchange.RequestState != evidence.StateComplete || len(entry.Exchange.Request) == 0 {
		return nil, fmt.Errorf("finding #%d has no single available complete primary receipt; no legacy fallback replayed", f.ID)
	}
	x := entry.Exchange
	item, err := httpmsg.FromEvidenceExchange(x)
	if err != nil {
		return nil, fmt.Errorf("finding #%d selected receipt: %w", f.ID, err)
	}
	target, err := selectedReceiptURL(x)
	if err != nil {
		return nil, err
	}
	svc := item.Service()
	src := &replaySource{BaselineRequest: item.Request().Raw(), Scheme: svc.Protocol(), Hostname: svc.Host(), Port: svc.Port(),
		URL: target.String(), FindingID: f.ID, InputType: "selected_exchange",
		OriginLabel: fmt.Sprintf("finding #%d exchange %s occurrence %s role=%s (reproduction, not a verdict)", f.ID, entry.ExchangeID, entry.OccurrenceID, entry.Role)}
	if x.ResponseState == evidence.StateComplete && item.Response() != nil {
		src.BaselineResponse, src.BaselineStatus = item.Response().Raw(), item.Response().StatusCode()
	}
	return src, nil
}

func primaryFindingEntry(f *database.Finding) *evidence.Entry {
	var selected *evidence.Entry
	for i := range f.Evidence {
		e := &f.Evidence[i]
		if e.Primary && (e.Role == evidence.RoleAttack || e.Role == evidence.RoleObservation || e.Role == evidence.RoleConfirmation) {
			if selected != nil {
				return nil
			} // multiple occurrences require explicit selection, not first-link inference
			selected = e
		}
	}
	return selected
}
