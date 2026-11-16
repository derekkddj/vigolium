package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestIngestGeneratedScanUUIDIsCanonical(t *testing.T) {
	id := newIngestScanUUID()
	require.True(t, database.ValidRunID(id), "ingest-generated scan UUID %q must be a canonical UUID", id)
}

func TestServerReceiveGeneratedScanUUIDIsCanonical(t *testing.T) {
	id := newServerReceiveScanUUID()
	require.True(t, database.ValidRunID(id), "scan-on-receive UUID %q must be a canonical UUID", id)
}
