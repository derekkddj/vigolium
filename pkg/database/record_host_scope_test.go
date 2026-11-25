package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func testRecordHostScopesMatchSQL(t *testing.T, db *DB) {
	t.Helper()
	ctx := context.Background()
	origins := []HostTarget{
		{Scheme: "http", Hostname: "actual.test", Port: 8080},
		{Scheme: "https", Hostname: "actual.test", Port: 443},
		{Scheme: "HTTP", Hostname: "Actual.test", Port: 8080},
		{Scheme: "http", Hostname: "other.test", Port: 80},
		{Scheme: "", Hostname: "", Port: 0},
	}
	for i, origin := range origins {
		record := toRecord(t, makeTestRequest(i), RecordSourceIngestCLI)
		record.ProjectUUID = DefaultProjectUUID
		record.Scheme, record.Hostname, record.Port = origin.Scheme, origin.Hostname, origin.Port
		record.URL = "https://attribution-only.test/proof"
		_, err := db.NewInsert().Model(record).Exec(ctx)
		require.NoError(t, err)
		for j, scopes := range [][]HostTarget{
			nil,
			{{Hostname: "actual.test"}},
			{{Scheme: "http", Hostname: "actual.test"}},
			{{Hostname: "actual.test", Port: 8080}},
			{{Scheme: "https", Hostname: "actual.test", Port: 443}},
			{{Scheme: "https", Hostname: "actual.test", Port: 8080}},
			{{Hostname: "attribution-only.test"}},
			{{Hostname: "Actual.test"}},
			{{Hostname: "other.test"}, {Scheme: "http", Hostname: "actual.test", Port: 8080}},
			{{}},
		} {
			t.Run(fmt.Sprintf("origin=%d/scope=%d", i, j), func(t *testing.T) {
				q := db.NewSelect().Model((*HTTPRecord)(nil)).Where("uuid = ?", record.UUID)
				matched, err := applyHostScopeFilter(q, scopes).Exists(ctx)
				require.NoError(t, err)
				require.Equal(t, matched, RecordMatchesHostScopes(record, scopes))
			})
		}
	}
	require.False(t, RecordMatchesHostScopes(nil, nil))
}

func TestRecordHostScopesMatchSQL(t *testing.T) {
	testRecordHostScopesMatchSQL(t, newTestDB(t))
}

func TestPg_RecordHostScopesMatchSQL(t *testing.T) {
	testRecordHostScopesMatchSQL(t, openPGTestDB(t))
}
