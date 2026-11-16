package server

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/vigolium/vigolium/pkg/database"
)

// findingsHandlers serves the /api/findings endpoints. It depends only on the
// database + repository, so it can be constructed and tested in isolation from
// the full Handlers god-struct. It is composed into Handlers (see the findings
// field) and wired in NewHandlers.
type findingsHandlers struct {
	db *database.DB
	// readDB is the read-intent pool (nil: db serves reads too).
	readDB *database.DB
	repo   *database.Repository
}

// reader is the pool the list/get queries use.
func (h *findingsHandlers) reader() *database.DB {
	if h.readDB != nil {
		return h.readDB
	}
	return h.db
}

// findingsHandler returns the findings sub-handler, lazily constructing it from
// the shared db + repo. NewHandlers wires it eagerly, but a Handlers built via a
// struct literal (e.g. in tests) leaves the field nil; routing through this
// accessor keeps the /api/findings routes safe to register on any Handlers value
// rather than nil-derefing on the first request.
func (h *Handlers) findingsHandler() *findingsHandlers {
	if h.findings == nil {
		h.findings = &findingsHandlers{db: h.db, readDB: h.readDB, repo: h.repo}
	}
	return h.findings
}

// parseFindingQueryFilters keeps filters shared by finding lists and host aggregates.
func parseFindingQueryFilters(c fiber.Ctx) (database.QueryFilters, error) {
	filters := database.QueryFilters{ProjectUUID: getProjectUUID(c)}

	if domain := c.Query("domain"); domain != "" {
		filters.HostPattern = domain
	}
	if sev := c.Query("severity"); sev != "" {
		for _, value := range strings.Split(sev, ",") {
			value = strings.TrimSpace(strings.ToLower(value))
			if value != "" {
				filters.Severity = append(filters.Severity, value)
			}
		}
	}
	filters.ScanUUID = c.Query("scan_uuid")
	filters.ModuleName = c.Query("module_name")
	filters.ModuleType = c.Query("module_type")
	filters.FindingSource = c.Query("finding_source")
	if kinds := c.Query("record_kind"); kinds != "" {
		for _, raw := range strings.Split(kinds, ",") {
			kind := strings.TrimSpace(strings.ToLower(raw))
			switch kind {
			case database.RecordKindFinding, database.RecordKindCandidate, database.RecordKindObservation:
				filters.RecordKinds = append(filters.RecordKinds, kind)
			case "":
				continue
			default:
				return database.QueryFilters{}, fmt.Errorf("invalid record_kind: %s", raw)
			}
		}
	}
	filters.RepoName = c.Query("repo_name")
	if statuses := c.Query("status"); statuses != "" {
		for _, value := range strings.Split(statuses, ",") {
			value = strings.TrimSpace(strings.ToLower(value))
			if value != "" {
				filters.Status = append(filters.Status, value)
			}
		}
	}
	filters.SearchTerm = c.Query("search")

	if sort := c.Query("sort"); sort != "" {
		if err := database.ValidateFindingSort(sort); err != nil {
			return database.QueryFilters{}, err
		}
		filters.SortBy = sort
	}
	if order := c.Query("order"); order != "" {
		switch strings.ToLower(order) {
		case "asc":
			filters.SortAsc = true
		case "desc":
			filters.SortAsc = false
		default:
			return database.QueryFilters{}, fmt.Errorf("invalid order: must be asc or desc")
		}
	}

	limit := 50
	if value, err := strconv.Atoi(c.Query("limit")); err == nil && value > 0 {
		limit = value
	}
	if limit > 500 {
		limit = 500
	}
	filters.Limit = limit
	if value, err := strconv.Atoi(c.Query("offset")); err == nil && value >= 0 {
		filters.Offset = value
	}
	return filters, nil
}

// HandleListFindings handles GET /api/findings
func (h *findingsHandlers) HandleListFindings(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	filters, err := parseFindingQueryFilters(c)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, err.Error())
	}
	projectUUID := filters.ProjectUUID
	fqb := database.NewFindingsQueryBuilder(h.reader(), filters)
	ctx := c.Context()

	// One round-trip for the page and its total, rather than Execute + Count.
	var (
		findings []*database.Finding
		total    int64
	)
	if err := retryRead(ctx, func() error {
		var err error
		findings, total, err = fqb.ExecuteWithCount(ctx)
		return err
	}); err != nil {
		return respondQueryError(c, err)
	}

	if err := h.repo.HydrateFindingEvidenceManifest(ctx, findings); err != nil {
		return respondQueryError(c, err)
	}
	return respondList(c, PaginatedResponse{
		ProjectUUID: projectUUID,
		Data:        findings,
		Total:       total,
		Limit:       filters.Limit,
		Offset:      filters.Offset,
		HasMore:     int64(filters.Offset+filters.Limit) < total,
	})
}

// HandleListFindingHosts handles GET /api/findings/hosts and returns complete
// hostname counts for the active project and finding filters, independent of the
// current finding page.
func (h *findingsHandlers) HandleListFindingHosts(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}
	filters, err := parseFindingQueryFilters(c)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, err.Error())
	}
	var hosts []database.FindingHostCount
	if err := retryRead(c.Context(), func() error {
		var queryErr error
		hosts, queryErr = database.NewFindingsQueryBuilder(h.reader(), filters).GroupByHostname(c.Context())
		return queryErr
	}); err != nil {
		return respondQueryError(c, err)
	}
	return respondList(c, PaginatedResponse{
		ProjectUUID: filters.ProjectUUID,
		Data:        hosts,
		Total:       int64(len(hosts)),
		Limit:       len(hosts),
		Offset:      0,
		HasMore:     false,
	})
}

// HandleDeleteFinding handles DELETE /api/findings/:id — deletes a single finding by numeric ID.
func (h *findingsHandlers) HandleDeleteFinding(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	idStr := c.Params("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid finding ID: must be a number")
	}

	// Verify the finding exists and belongs to the request's project. Only the
	// project is needed, so don't load the finding's evidence to delete it.
	existingProject, err := h.repo.FindingProjectUUID(c.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve finding: %w", err))
	}
	if !inRequestProject(c, existingProject) {
		return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
	}

	if err := h.repo.DeleteFinding(c.Context(), id); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to delete finding: %w", err))
	}

	return c.JSON(fiber.Map{
		"message": "finding deleted",
		"id":      id,
	})
}

// UpdateFindingStatusRequest is the JSON body for PATCH /api/findings/:id/status.
type UpdateFindingStatusRequest struct {
	Status string `json:"status"`
}

// findingStatusActorAPI is the actor recorded on status changes made through
// the REST API.
const findingStatusActorAPI = "api"

// HandleUpdateFindingStatus handles PATCH /api/findings/:id/status — updates the
// lifecycle status of a finding (one of database.FindingStatuses: draft → triaged → confirmed → fixed, or
// false_positive / accepted_risk).
func (h *findingsHandlers) HandleUpdateFindingStatus(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid finding ID: must be a number")
	}

	var req UpdateFindingStatusRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
	}

	status := strings.ToLower(strings.TrimSpace(req.Status))
	if !database.IsValidFindingStatus(status) {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid status: must be one of "+strings.Join(database.FindingStatuses, ", "))
	}

	// Scope the mutation to the request's project: the project predicate is part
	// of the UPDATE, so an operator scoped to one engagement can't flip another
	// project's finding via a raw id. A finding outside the project is reported
	// as not found, exactly like a missing one. The updated finding is re-loaded
	// in full below, after the write, for the response body. Like every status
	// writer it goes through the scoped writer, so the change is stamped with
	// its actor and lands in finding_status_events.
	if err := h.repo.SetFindingStatus(c.Context(), getProjectUUID(c), id, status, "", findingStatusActorAPI); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to update finding status: %w", err))
	}

	finding, err := h.repo.GetFindingByID(c.Context(), id)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve updated finding: %w", err))
	}
	return c.JSON(finding)
}

// HandleGetFinding handles GET /api/findings/:id — returns a single finding by numeric ID.
func (h *findingsHandlers) HandleGetFinding(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	idStr := c.Params("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid finding ID: must be a number")
	}

	finding, err := h.repo.GetFindingByID(c.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
		}
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to retrieve finding: %w", err))
	}
	if !inRequestProject(c, finding.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
	}

	// Detail-only hydration. Do not infer proof from a matching URL: the exact
	// refs may point at a different exchange, or be unavailable legacy ghosts.
	if err := h.repo.HydrateFindingRecordRefs(c.Context(), []*database.Finding{finding}); err != nil {
		return respondQueryError(c, err)
	}
	if err := h.repo.HydrateFindingOccurrences(c.Context(), finding); err != nil {
		return respondQueryError(c, err)
	}
	// Ordinary detail returns the reference inventory, not the uncapped linked
	// traffic corpus. Bodies are loaded lazily via /http-records/:uuid.
	available, err := h.repo.GetFindingRecordUUIDsScoped(c.Context(), finding.ProjectUUID, finding.HTTPRecordUUIDs)
	if err != nil {
		return respondQueryError(c, err)
	}
	loaded := make(map[string]bool, len(available))
	for _, ref := range available {
		loaded[ref] = true
	}
	var unavailable []string
	for _, ref := range finding.HTTPRecordUUIDs {
		if !loaded[ref] {
			unavailable = append(unavailable, ref)
		}
	}
	return c.JSON(struct {
		*database.Finding
		RecordsTotal int      `json:"records_total"`
		Unavailable  []string `json:"records_unavailable,omitempty"`
	}{finding, len(finding.HTTPRecordUUIDs), unavailable})
}
