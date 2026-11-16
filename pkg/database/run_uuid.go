package database

import "github.com/google/uuid"

// ValidRunID reports whether id is a canonical lowercase UUID. It is intended
// for externally supplied scan/run identities; persisted legacy IDs remain
// readable and may use other safe path-segment formats.
func ValidRunID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}
