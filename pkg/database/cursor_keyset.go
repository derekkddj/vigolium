package database

import (
	"time"

	"github.com/uptrace/bun"
)

// dbCursorTimeExpr is the timestamp key used by cursor predicates AND ordering.
// column must be a trusted internal SQL identifier, never user input. PostgreSQL
// compares native timestamps; SQLite compares text and needs one representation
// for CURRENT_TIMESTAMP, Bun's UTC suffix, and fractional cursor writes. Strip
// only the known UTC suffix and insignificant fractional zeros, without lossy
// datetime/julianday conversions (which discard sub-millisecond precision).
func dbCursorTimeExpr(driver, column string) string {
	if driver != driverSQLite {
		return column
	}
	utc := "replace(" + column + ", '+00:00', '')"
	return "(CASE WHEN instr(" + utc + ", '.') > 0 THEN rtrim(rtrim(" + utc + ", '0'), '.') ELSE " + utc + " END)"
}

// dbCursorTimeValue matches dbCursorTimeExpr, preserving SQLite nanoseconds.
// Whole seconds have no decimal suffix, matching CURRENT_TIMESTAMP. Other
// drivers receive native time values, leaving their timestamp precision to SQL.
// This is only for cursor keys/bounds, not unrelated timestamp fields.
func dbCursorTimeValue(driver string, at time.Time) any {
	if driver == driverSQLite {
		return at.UTC().Format("2006-01-02 15:04:05.999999999")
	}
	return at.UTC()
}

// applyRecordsAfterCursor shares the strict keyset predicate between feeds,
// repository pages, and counters. Callers retain their project/host/source scope.
func applyRecordsAfterCursor(q *bun.SelectQuery, driver string, at time.Time, id string) *bun.SelectQuery {
	if at.IsZero() {
		return q
	}
	key := dbCursorTimeExpr(driver, "created_at")
	bound := dbCursorTimeValue(driver, at)
	return q.Where("("+key+" > ? OR ("+key+" = ? AND uuid > ?))", bound, bound, id)
}
