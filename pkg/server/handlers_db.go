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

// --- Schema introspection ---

// HandleListDBTables returns all database tables with row counts.
// GET /api/db/tables
func (h *Handlers) HandleListDBTables(c fiber.Ctx) error {
	tables, err := database.ListTablesWithCounts(c.Context(), h.db)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to list tables: %w", err))
	}
	return respondBespokeList(c, fiber.Map{
		"tables": tables,
		"total":  len(tables),
	}, PaginatedResponse{Data: tables, Total: int64(len(tables))}, nil)
}

// HandleListDBTableColumns returns column metadata for a specific table.
// GET /api/db/tables/:table/columns
func (h *Handlers) HandleListDBTableColumns(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateTableName(c.Context(), h.db, tableName); err != nil {
		return respondError(c, fiber.StatusNotFound, err)
	}

	columns, err := database.ListColumns(c.Context(), h.db, tableName)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, fmt.Errorf("failed to list columns: %w", err))
	}

	pk, _ := database.DetectPrimaryKey(c.Context(), h.db, tableName)

	return respondBespokeList(c, fiber.Map{
		"table":       tableName,
		"columns":     columns,
		"primary_key": pk.Columns,
		"total":       len(columns),
	}, PaginatedResponse{Data: columns, Total: int64(len(columns))}, fiber.Map{
		"table":       tableName,
		"primary_key": pk.Columns,
	})
}

// --- Generic CRUD ---

// HandleListDBRecords returns paginated, filtered records from any table.
// GET /api/db/tables/:table/records
func (h *Handlers) HandleListDBRecords(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateGenericTableAccess(tableName); err != nil {
		return respondError(c, fiber.StatusForbidden, err)
	}

	opts, err := parseGenericQueryOptions(c)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, err)
	}

	// Project scoping: a table with a project_uuid column is filtered
	// to the request's project; all_projects=true lifts that for admins only.
	// A table without one (users, projects, finding_records, …) is admin-only.
	scoped, err := h.tableProjectScoped(c, tableName)
	if err != nil {
		return respondError(c, fiber.StatusNotFound, err)
	}
	projectScopedFilter := false
	admin := isAdminRequest(c)
	if !scoped && !admin {
		return respondErrorMsg(c, fiber.StatusForbidden, "table is not project-scoped; admin only")
	}
	if scoped {
		allProjects := c.Query("all_projects", "false") == "true"
		if allProjects && !admin {
			return respondErrorMsg(c, fiber.StatusForbidden, "all_projects requires the admin role")
		}
		if !allProjects {
			projectScopedFilter = true
			opts.Filters = append(opts.Filters, database.GenericFilter{
				Column:   "project_uuid",
				Operator: "eq",
				Value:    getProjectUUID(c),
			})
		}
	}

	records, columns, total, err := database.QueryGenericTableFiltered(c.Context(), h.db, tableName, opts)
	if err != nil {
		status := fiber.StatusInternalServerError
		if errors.Is(err, database.ErrTableNotFound) {
			status = fiber.StatusNotFound
		}
		return respondError(c, status, err)
	}

	return respondBespokeListScoped(c, fiber.Map{
		"table":   tableName,
		"total":   total,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
		"columns": columns,
		"records": records,
	}, PaginatedResponse{
		Data:   records,
		Total:  int64(total),
		Limit:  opts.Limit,
		Offset: opts.Offset,
	}, fiber.Map{
		"table":   tableName,
		"columns": columns,
	}, projectScopedFilter)
}

// HandleGetDBRecord returns a single record by primary key.
// GET /api/db/tables/:table/records/:id
func (h *Handlers) HandleGetDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateGenericTableAccess(tableName); err != nil {
		return respondError(c, fiber.StatusForbidden, err)
	}
	pkValue := c.Params("id")

	scoped, err := h.tableProjectScoped(c, tableName)
	if err != nil {
		return respondError(c, fiber.StatusNotFound, err)
	}
	if !scoped && !isAdminRequest(c) {
		return respondErrorMsg(c, fiber.StatusForbidden, "table is not project-scoped; admin only")
	}

	record, err := h.getScopedGenericDBRecord(c, tableName, pkValue, false)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondErrorMsg(c, fiber.StatusNotFound, "record not found")
		}
		status := fiber.StatusInternalServerError
		if errors.Is(err, database.ErrTableNotFound) || errors.Is(err, database.ErrCompositePKUnsupported) {
			status = fiber.StatusBadRequest
		}
		return respondError(c, status, err)
	}
	// A record from another project is "not found", never 403: cross-project
	// existence must not leak.
	if scoped && !inRequestProject(c, fmt.Sprint(record["project_uuid"])) {
		return respondErrorMsg(c, fiber.StatusNotFound, "record not found")
	}

	return c.JSON(fiber.Map{
		"table":  tableName,
		"record": record,
	})
}

// HandleCreateDBRecord inserts a new record into a table.
// POST /api/db/tables/:table/records
func (h *Handlers) HandleCreateDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateGenericTableAccess(tableName); err != nil {
		return respondError(c, fiber.StatusForbidden, err)
	}
	if strings.EqualFold(tableName, "http_records") {
		return respondError(c, fiber.StatusForbidden, database.ErrGenericInsertUnsupported)
	}

	var fields map[string]interface{}
	if err := c.Bind().JSON(&fields); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
	}

	// Auto-inject project_uuid for project-scoped tables
	if scoped, err := h.tableProjectScoped(c, tableName); err != nil {
		return respondError(c, fiber.StatusNotFound, err)
	} else if scoped {
		projectUUID := getProjectUUID(c)
		if supplied, ok := fields["project_uuid"]; ok && supplied != projectUUID {
			return respondErrorMsg(c, fiber.StatusForbidden, "generic inserts cannot target another project")
		}
		fields["project_uuid"] = projectUUID
	}

	if err := database.InsertGenericRecord(c.Context(), h.db, tableName, fields); err != nil {
		status := fiber.StatusInternalServerError
		if errors.Is(err, database.ErrInvalidColumn) || errors.Is(err, database.ErrNoValidFields) {
			status = fiber.StatusBadRequest
		}
		return respondError(c, status, err)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"table":   tableName,
		"message": "record created",
	})
}

// HandleUpdateDBRecord updates fields on an existing record.
// PUT /api/db/tables/:table/records/:id
func (h *Handlers) HandleUpdateDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateGenericTableAccess(tableName); err != nil {
		return respondError(c, fiber.StatusForbidden, err)
	}
	pkValue := c.Params("id")

	var fields map[string]interface{}
	if err := c.Bind().JSON(&fields); err != nil {
		return respondError(c, fiber.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
	}

	if h.projectScopedTable(c, tableName) {
		if _, err := h.getScopedGenericDBRecord(c, tableName, pkValue, true); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return respondErrorMsg(c, fiber.StatusNotFound, "record not found")
			}
			return respondError(c, fiber.StatusBadRequest, err)
		}
		if _, ok := fields["project_uuid"]; ok {
			return respondErrorMsg(c, fiber.StatusForbidden, "generic updates cannot change project ownership")
		}
	}

	if err := database.UpdateGenericRecord(c.Context(), h.db, tableName, pkValue, fields); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondErrorMsg(c, fiber.StatusNotFound, "record not found")
		}
		status := fiber.StatusInternalServerError
		if errors.Is(err, database.ErrInvalidColumn) || errors.Is(err, database.ErrImmutablePrimaryKey) || errors.Is(err, database.ErrNoValidFields) {
			status = fiber.StatusBadRequest
		}
		if errors.Is(err, database.ErrImmutableRecordExchange) {
			status = fiber.StatusForbidden
		}
		return respondError(c, status, err)
	}

	return c.JSON(fiber.Map{
		"table":   tableName,
		"id":      pkValue,
		"message": "record updated",
	})
}

// HandleDeleteDBRecord deletes a record by primary key.
// DELETE /api/db/tables/:table/records/:id
func (h *Handlers) HandleDeleteDBRecord(c fiber.Ctx) error {
	tableName := c.Params("table")
	if err := database.ValidateGenericTableAccess(tableName); err != nil {
		return respondError(c, fiber.StatusForbidden, err)
	}
	pkValue := c.Params("id")

	if h.projectScopedTable(c, tableName) {
		if _, err := h.getScopedGenericDBRecord(c, tableName, pkValue, true); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return respondErrorMsg(c, fiber.StatusNotFound, "record not found")
			}
			return respondError(c, fiber.StatusBadRequest, err)
		}
	}

	if err := database.DeleteGenericRecord(c.Context(), h.db, tableName, pkValue); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return respondErrorMsg(c, fiber.StatusNotFound, "record not found")
		}
		status := fiber.StatusInternalServerError
		if errors.Is(err, database.ErrTableNotFound) || errors.Is(err, database.ErrCompositePKUnsupported) {
			status = fiber.StatusBadRequest
		}
		return respondError(c, status, err)
	}

	return c.JSON(fiber.Map{
		"table":   tableName,
		"id":      pkValue,
		"message": "record deleted",
	})
}

// --- Helpers ---

// getScopedGenericDBRecord checks ownership before loading a record's body or
// allowing metadata edits. all_projects never bypasses single-record ownership.
func (h *Handlers) getScopedGenericDBRecord(c fiber.Ctx, tableName, pkValue string, metadataOnly bool) (map[string]interface{}, error) {
	if !h.projectScopedTable(c, tableName) {
		return database.GetGenericRecord(c.Context(), h.db, tableName, pkValue)
	}
	if err := database.ValidateTableName(c.Context(), h.db, tableName); err != nil {
		return nil, err
	}
	pk, err := database.DetectPrimaryKey(c.Context(), h.db, tableName)
	if err != nil {
		return nil, err
	}
	if len(pk.Columns) != 1 {
		return nil, database.ErrCompositePKUnsupported
	}
	opts := database.GenericQueryOptions{Limit: 1, Filters: []database.GenericFilter{
		{Column: pk.Columns[0], Operator: "eq", Value: pkValue},
		{Column: "project_uuid", Operator: "eq", Value: getProjectUUID(c)},
	}}
	if metadataOnly {
		opts.Columns = []string{pk.Columns[0], "project_uuid"}
	}
	records, _, _, err := database.QueryGenericTableFiltered(c.Context(), h.db, tableName, opts)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, sql.ErrNoRows
	}
	return records[0], nil
}

// parseGenericQueryOptions extracts GenericQueryOptions from query parameters.
func parseGenericQueryOptions(c fiber.Ctx) (database.GenericQueryOptions, error) {
	opts := database.GenericQueryOptions{
		Limit:  100,
		Offset: 0,
	}

	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return opts, err
		}
		opts.Limit = n
	}

	if v := c.Query("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return opts, err
		}
		opts.Offset = n
	}

	if v := c.Query("sort"); v != "" {
		opts.SortBy = v
	}

	if v := c.Query("order"); v != "" {
		opts.SortAsc = strings.EqualFold(v, "asc")
	}

	if v := c.Query("columns"); v != "" {
		opts.Columns = strings.Split(v, ",")
		for i := range opts.Columns {
			opts.Columns[i] = strings.TrimSpace(opts.Columns[i])
		}
	}

	if v := c.Query("search"); v != "" {
		opts.SearchTerm = v
	}

	if v := c.Query("truncate"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return opts, err
		}
		opts.Truncate = n
	}

	// Parse filter.* query params
	// Supported forms: filter.column=value, filter.column__op=value
	queries := c.Queries()
	for key, val := range queries {
		if !strings.HasPrefix(key, "filter.") {
			continue
		}
		rest := strings.TrimPrefix(key, "filter.")

		var column, operator string
		if idx := strings.LastIndex(rest, "__"); idx > 0 {
			column = rest[:idx]
			operator = rest[idx+2:]
		} else {
			column = rest
			operator = "eq"
		}

		opts.Filters = append(opts.Filters, database.GenericFilter{
			Column:   column,
			Operator: operator,
			Value:    val,
		})
	}

	return opts, nil
}

// tableProjectScoped reports whether tableName has a project_uuid column, by
// introspection rather than a hand-kept list: the list missed every
// table added after it (host_observations, …), and those were served across
// projects. An unknown table is an error.
func (h *Handlers) tableProjectScoped(c fiber.Ctx, tableName string) (bool, error) {
	if err := database.ValidateTableName(c.Context(), h.db, tableName); err != nil {
		return false, err
	}
	cols, err := database.ListColumns(c.Context(), h.db, tableName)
	if err != nil {
		return false, err
	}
	for _, col := range cols {
		if strings.EqualFold(col.Name, "project_uuid") {
			return true, nil
		}
	}
	return false, nil
}

// projectScopedTable is tableProjectScoped for callers that already validated
// the table: a table whose columns cannot be read is treated as unscoped, and
// the generic access checks that follow reject it.
func (h *Handlers) projectScopedTable(c fiber.Ctx, tableName string) bool {
	scoped, err := h.tableProjectScoped(c, tableName)
	return err == nil && scoped
}

// isAdminRequest reports whether the caller holds the admin role. With auth
// disabled (--no-auth) there is no user and every caller is the operator of
// a local server, treated as admin — the same rule RoleGuard applies.
func isAdminRequest(c fiber.Ctx) bool {
	user := getAuthUser(c)
	return user == nil || user.Role == RoleAdmin
}
