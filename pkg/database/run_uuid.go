package database

import "github.com/google/uuid"

// CanonicalUUID parses a UUID in any spelling accepted by google/uuid and
// returns the canonical lowercase, hyphenated form.
func CanonicalUUID(id string) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// ValidRunID reports whether id is a canonical lowercase UUID. It is intended
// for externally supplied scan/run identities; persisted legacy IDs remain
// readable and may use other safe path-segment formats.
func ValidRunID(id string) bool {
	canonical, err := CanonicalUUID(id)
	return err == nil && canonical == id
}
