package server

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v3"
)

// HandleGetFindingEvidence loads one exact selected receipt. Exchange visibility
// alone is insufficient: the requested finding must own a manifest association.
// Never recover a missing receipt using a URL, linked traffic or another project.
func (h *findingsHandlers) HandleGetFindingEvidence(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil || id <= 0 {
		return respondErrorMsg(c, fiber.StatusBadRequest, "invalid finding ID: must be a positive number")
	}
	f, err := h.repo.GetFindingByID(c.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
	}
	if err != nil {
		return respondQueryError(c, err)
	}
	if f.ProjectUUID == "" || !inRequestProject(c, f.ProjectUUID) {
		return respondError(c, fiber.StatusNotFound, ErrFindingNotFound)
	}
	exchangeID := c.Params("exchange_id")
	associated := false
	for _, entry := range f.Evidence {
		if entry.ExchangeID != "" && entry.ExchangeID == exchangeID {
			associated = true
			break
		}
	}
	if !associated {
		return respondErrorMsg(c, fiber.StatusNotFound, "selected evidence exchange not found")
	}
	x, err := h.repo.GetEvidenceExchange(c.Context(), exchangeID, f.ProjectUUID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && x == nil {
		return respondErrorMsg(c, fiber.StatusNotFound, "selected evidence exchange unavailable")
	}
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to load selected evidence: %w", err))
	}
	return c.JSON(x)
}
