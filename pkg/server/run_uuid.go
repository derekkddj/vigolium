package server

import (
	"errors"
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
)

var errInvalidRunUUID = errors.New("scan_uuid must be a canonical lowercase UUID")

func validateOptionalRunUUID(runUUID string) error {
	if runUUID != "" && !database.ValidRunID(runUUID) {
		return fmt.Errorf("%w: %q", errInvalidRunUUID, runUUID)
	}
	return nil
}
