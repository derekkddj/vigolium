package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// HandleListProjects handles GET /api/projects
func (h *Handlers) HandleListProjects(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	ownerUUID := c.Query("owner")
	projects, err := h.repo.ListProjects(c.Context(), ownerUUID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("query failed: %w", err))
	}

	// Bulk-fetch stats for all projects
	allStats, err := h.repo.GetAllProjectsStats(c.Context())
	if err != nil {
		// Non-fatal: return projects without stats
		allStats = make(map[string]*database.ProjectStatsRow)
	}

	result := make([]ProjectWithStats, 0, len(projects))
	for _, p := range projects {
		ps := buildProjectStats(allStats[p.UUID])
		result = append(result, ProjectWithStats{Project: p, Stats: ps})
	}

	return respondBespokeList(c, result, PaginatedResponse{Data: result, Total: int64(len(result))}, nil)
}

// HandleCreateProject handles POST /api/projects
func (h *Handlers) HandleCreateProject(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	var req ProjectRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
	}

	if req.Name == "" {
		return respondErrorMsg(c, fiber.StatusBadRequest, "name is required")
	}

	// Honor a client-supplied UUID when present so the cloud console can
	// keep the scanner row in sync with the Convex-side project record.
	// When absent (CLI / standalone API users) the scanner mints one.
	projectUUID := req.UUID
	if projectUUID == "" {
		projectUUID = uuid.NewString()
	} else {
		canonicalUUID, err := database.CanonicalUUID(projectUUID)
		if err != nil {
			return respondErrorMsg(c, fiber.StatusBadRequest, "uuid is not a valid UUID")
		}
		projectUUID = canonicalUUID
		if existing, err := h.repo.GetProjectByUUID(c.Context(), projectUUID); err == nil && existing.UUID != "" {
			// Idempotent: if the canonical row already exists, return it as-is.
			// This makes the eager-ensure flow safe to retry on the cloud side.
			return c.Status(fiber.StatusOK).JSON(existing)
		}
	}

	now := time.Now()
	project := &database.Project{
		UUID:        projectUUID,
		Name:        req.Name,
		Description: req.Description,
		OwnerUUID:   req.OwnerUUID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := h.repo.CreateProject(c.Context(), project); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to create project: %w", err))
	}

	return c.Status(fiber.StatusCreated).JSON(project)
}

// HandleGetProject handles GET /api/projects/:uuid
func (h *Handlers) HandleGetProject(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	projectUUID := c.Params("uuid")
	project, err := h.repo.GetProjectByUUID(c.Context(), projectUUID)
	if err != nil {
		return respondError(c, fiber.StatusNotFound, ErrProjectNotFound)
	}

	statsRow, err := h.repo.GetProjectStats(c.Context(), projectUUID)
	if err != nil {
		statsRow = nil // non-fatal
	}

	return c.JSON(ProjectWithStats{
		Project: project,
		Stats:   buildProjectStats(statsRow),
	})
}

// HandleGetProjectStats handles GET /api/projects/:uuid/stats — returns just the
// aggregated stats for a project, without the project metadata. Useful when the UI
// needs to refresh stats independently of the project record.
func (h *Handlers) HandleGetProjectStats(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	projectUUID := c.Params("uuid")
	if _, err := h.repo.GetProjectByUUID(c.Context(), projectUUID); err != nil {
		return respondError(c, fiber.StatusNotFound, ErrProjectNotFound)
	}

	statsRow, err := h.repo.GetProjectStats(c.Context(), projectUUID)
	if err != nil {
		statsRow = nil // non-fatal: return zeroed stats
	}

	return c.JSON(buildProjectStats(statsRow))
}

// HandleUpdateProject handles PUT /api/projects/:uuid
func (h *Handlers) HandleUpdateProject(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	projectUUID := c.Params("uuid")
	project, err := h.repo.GetProjectByUUID(c.Context(), projectUUID)
	if err != nil {
		return respondError(c, fiber.StatusNotFound, ErrProjectNotFound)
	}

	var req ProjectRequest
	if err := c.Bind().JSON(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
	}

	if req.Name != "" {
		project.Name = req.Name
	}
	if req.Description != "" {
		project.Description = req.Description
	}
	if req.OwnerUUID != "" {
		project.OwnerUUID = req.OwnerUUID
	}
	project.UpdatedAt = time.Now()

	if err := h.repo.UpdateProject(c.Context(), project); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to update project: %w", err))
	}

	return c.JSON(project)
}

// buildProjectStats converts a database ProjectStatsRow into the API response type.
func buildProjectStats(row *database.ProjectStatsRow) ProjectStats {
	if row == nil {
		return ProjectStats{}
	}
	return ProjectStats{
		HTTPRecords: ProjectHTTPRecordStats{
			Total:     row.HTTPRecords,
			Success:   row.HTTP2xx,
			Redirect:  row.HTTP3xx,
			ClientErr: row.HTTP4xx,
			ServerErr: row.HTTP5xx,
		},
		Findings: ProjectFindingStats{
			Total:    row.Findings,
			Critical: row.Critical,
			High:     row.High,
			Medium:   row.Medium,
			Low:      row.Low,
			Info:     row.Info,
		},
		Scans:            row.Scans,
		AgenticScans:     row.AgenticScans,
		OASTInteractions: row.OASTInteractions,
	}
}

// DeleteProjectResponse describes the selected project-deletion mode and its outcome.
type DeleteProjectResponse struct {
	Message              string           `json:"message"`
	UUID                 string           `json:"uuid"`
	Mode                 string           `json:"mode"`
	RowsDeleted          map[string]int64 `json:"rows_deleted,omitempty"`
	ConfigDirDeleted     bool             `json:"config_dir_deleted"`
	SessionDirsDeleted   int              `json:"session_dirs_deleted"`
	DiskDeletionFailures []string         `json:"disk_deletion_failures"`
}

// HandleDeleteProject handles DELETE /api/projects/:uuid. By default it
// reassigns the project's rows to DefaultProjectUUID for compatibility;
// ?delete_data=true explicitly purges its rows and owned on-disk directories.
func (h *Handlers) HandleDeleteProject(c fiber.Ctx) error {
	if h.db == nil {
		return respondError(c, fiber.StatusServiceUnavailable, ErrDatabaseRequired)
	}

	projectUUID := c.Params("uuid")
	if projectUUID == database.DefaultProjectUUID {
		return respondErrorMsg(c, fiber.StatusBadRequest, "cannot delete the default project")
	}

	deleteData := false
	if value := c.Query("delete_data"); value != "" {
		switch value {
		case "true":
			deleteData = true
		case "false":
		default:
			return respondErrorMsg(c, fiber.StatusBadRequest, "delete_data must be true or false")
		}
	}

	if !deleteData {
		// Preserve the existing default: move all data to Default before deleting.
		if err := h.repo.ReassignProjectData(c.Context(), projectUUID, database.DefaultProjectUUID); err != nil {
			return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to reassign project data: %w", err))
		}
		if err := h.repo.DeleteProject(c.Context(), projectUUID); err != nil {
			return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to delete project: %w", err))
		}
		return c.JSON(DeleteProjectResponse{
			Message:              "project deleted; data reassigned to the default project",
			UUID:                 projectUUID,
			Mode:                 "reassign_to_default",
			DiskDeletionFailures: []string{},
		})
	}

	if !database.ValidRunID(projectUUID) {
		return respondErrorMsg(c, fiber.StatusBadRequest, "uuid must be a canonical UUID")
	}
	if _, err := h.repo.GetProjectByUUID(c.Context(), projectUUID); err != nil {
		return respondError(c, fiber.StatusNotFound, ErrProjectNotFound)
	}

	settings, err := h.settingsForProject(projectUUID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to load project settings: %w", err))
	}
	sessionDirs, err := h.repo.ProjectSessionDirs(
		c.Context(),
		projectUUID,
		settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
		settings.Agent.EffectiveSessionsDir(),
	)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to collect project session directories: %w", err))
	}

	rowsDeleted, err := h.repo.PurgeProjectDataWithCounts(c.Context(), projectUUID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to purge project data: %w", err))
	}
	if err := h.repo.DeleteProject(c.Context(), projectUUID); err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to delete project: %w", err))
	}
	rowsDeleted["projects"] = 1

	removeAll := h.removeAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	response := DeleteProjectResponse{
		Message:              "project and its data purged",
		UUID:                 projectUUID,
		Mode:                 "purge",
		RowsDeleted:          rowsDeleted,
		DiskDeletionFailures: make([]string, 0),
	}

	configDir := config.ProjectConfigDir(projectUUID)
	if removed, removeErr := removeProjectPurgeDir(configDir, filepath.Dir(configDir), projectUUID, removeAll); removeErr != nil {
		response.DiskDeletionFailures = append(response.DiskDeletionFailures, configDir)
	} else {
		response.ConfigDirDeleted = removed
	}
	for _, sessionDir := range sessionDirs {
		if removed, removeErr := removeProjectPurgeDir(sessionDir.Path, sessionDir.Root, sessionDir.UUID, removeAll); removeErr != nil {
			response.DiskDeletionFailures = append(response.DiskDeletionFailures, sessionDir.Path)
		} else if removed {
			response.SessionDirsDeleted++
		}
	}

	return c.JSON(response)
}

// removeProjectPurgeDir removes only a canonical UUID directory that is a direct
// child of its expected root. Both the lexical path and its symlink-resolved form
// are checked before RemoveAll so persisted identifiers cannot escape the root.
func removeProjectPurgeDir(path, root, expectedUUID string, removeAll func(string) error) (bool, error) {
	if !database.ValidRunID(expectedUUID) {
		return false, fmt.Errorf("directory identifier is not a canonical UUID")
	}
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	if filepath.Base(cleanPath) != expectedUUID {
		return false, fmt.Errorf("directory basename does not match UUID")
	}
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return false, fmt.Errorf("resolve target path: %w", err)
	}
	absRoot, err := filepath.Abs(cleanRoot)
	if err != nil {
		return false, fmt.Errorf("resolve root path: %w", err)
	}
	if filepath.Dir(absPath) != absRoot {
		return false, fmt.Errorf("directory is not a direct child of its expected root")
	}

	resolvedRoot, err := resolvePurgePath(absRoot)
	if err != nil {
		return false, fmt.Errorf("resolve expected root: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if errors.Is(err, os.ErrNotExist) {
		resolvedPath = filepath.Join(resolvedRoot, expectedUUID)
	} else if err != nil {
		return false, fmt.Errorf("resolve target path: %w", err)
	} else if resolvedPath, err = filepath.Abs(resolvedPath); err != nil {
		return false, fmt.Errorf("resolve target path: %w", err)
	}
	if filepath.Base(resolvedPath) != expectedUUID || !pathIsUnderDir(resolvedPath, resolvedRoot) || resolvedPath == resolvedRoot {
		return false, fmt.Errorf("resolved directory escapes its expected root")
	}

	if _, err := os.Lstat(absPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect target directory: %w", err)
	}
	if err := removeAll(absPath); err != nil {
		return false, fmt.Errorf("remove target directory: %w", err)
	}
	return true, nil
}

func resolvePurgePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return filepath.Abs(resolved)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return filepath.Abs(filepath.Clean(path))
}
