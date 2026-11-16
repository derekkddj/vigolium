package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const scopedRecordPrefix = "c0ffee00"

func seedProjectScopedRecord(t *testing.T, repo *database.Repository, id, projectUUID, host string) *database.HTTPRecord {
	t.Helper()
	ctx := context.Background()
	raw := fmt.Sprintf("GET /?owner=%s HTTP/1.1\r\nHost: %s\r\n\r\n", projectUUID, host)
	rr, err := httpmsg.ParseRawRequestWithURL(raw, "https://"+host+"/?owner="+projectUUID)
	require.NoError(t, err)
	rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")))
	generatedID, err := repo.SaveRecordWithLineage(ctx, rr, "scope-test", projectUUID, database.RecordLineage{})
	require.NoError(t, err)
	if generatedID != id {
		_, err = repo.DB().NewUpdate().Model((*database.HTTPRecord)(nil)).
			Set("uuid = ?", id).Where("uuid = ?", generatedID).Exec(ctx)
		require.NoError(t, err)
	}
	record, err := repo.GetRecordByUUID(ctx, id)
	require.NoError(t, err)
	return record
}

func TestRecordToolsResolvePrefixesWithinCurrentProject(t *testing.T) {
	repo := newVigtoolTestRepo(t)
	projectA, projectB := uuid.NewString(), uuid.NewString()
	recordAID := scopedRecordPrefix + "-0000-4000-8000-000000000001"
	recordBID := scopedRecordPrefix + "-0000-4000-8000-000000000002"
	recordDefaultID := scopedRecordPrefix + "-0000-4000-8000-000000000003"
	recordA := seedProjectScopedRecord(t, repo, recordAID, projectA, "project-a.scope.invalid")
	recordB := seedProjectScopedRecord(t, repo, recordBID, projectB, "project-b.scope.invalid")
	recordDefault := seedProjectScopedRecord(t, repo, recordDefaultID, database.DefaultProjectUUID, "default.scope.invalid")

	for _, tc := range []struct {
		name      string
		project   string
		expected  *database.HTTPRecord
		otherUUID string
	}{
		{name: "project A", project: projectA, expected: recordA, otherUUID: recordB.UUID},
		{name: "project B", project: projectB, expected: recordB, otherUUID: recordA.UUID},
		{name: "empty context defaults to default project", project: "", expected: recordDefault, otherUUID: recordA.UUID},
	} {
		t.Run(tc.name+"/inspect", func(t *testing.T) {
			res, err := NewInspectRecordTool(&SessionsContext{Repo: repo, ProjectUUID: tc.project}).Execute(
				context.Background(), map[string]any{"uuid": scopedRecordPrefix}, nil)
			require.NoError(t, err)
			require.False(t, res.IsError, res.Content)
			var inspected inspectRecordOut
			require.NoError(t, json.Unmarshal([]byte(res.Content), &inspected))
			require.Equal(t, tc.expected.UUID, inspected.UUID)
			require.Equal(t, tc.expected.URL, inspected.URL)
			require.NotContains(t, res.Content, tc.otherUUID, "another project's UUID must not appear in the result")
		})

		t.Run(tc.name+"/replay", func(t *testing.T) {
			res, err := NewReplayRequestTool(&SessionsContext{Repo: repo, ProjectUUID: tc.project}).Execute(
				context.Background(), map[string]any{"record_uuid": scopedRecordPrefix}, nil)
			require.NoError(t, err)
			// No mutation was supplied, so reaching this validation error proves
			// that lookup found the in-project record instead of returning the
			// cross-project ambiguity (or reading another project's record).
			require.True(t, res.IsError)
			require.Contains(t, res.Content, "provide either 'mutations' or 'raw_request'")
			require.NotContains(t, res.Content, tc.otherUUID)
		})
	}
}
