package autopilot

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

func seedReportFindingRecord(t *testing.T, repo *database.Repository, projectUUID, host, recordUUID string) string {
	t.Helper()
	ctx := context.Background()
	raw := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", uuid.NewString(), host)
	rr, err := httpmsg.ParseRawRequestWithURL(raw, "https://"+host+"/evidence")
	require.NoError(t, err)
	generatedUUID, err := repo.SaveRecord(ctx, rr, "report-finding-test", projectUUID)
	require.NoError(t, err)
	if recordUUID == "" {
		return generatedUUID
	}
	_, err = repo.DB().NewUpdate().Model((*database.HTTPRecord)(nil)).
		Set("uuid = ?", recordUUID).Set("root_uuid = ?", recordUUID).
		Where("uuid = ?", generatedUUID).Exec(ctx)
	require.NoError(t, err)
	return recordUUID
}

func reportFindingArgs(title string, recordRefs ...string) map[string]any {
	refs := make([]any, len(recordRefs))
	for i, ref := range recordRefs {
		refs[i] = ref
	}
	return map[string]any{
		"title":        title,
		"severity":     "high",
		"description":  "A reproducible security issue.",
		"record_uuids": refs,
	}
}

func executeReportFinding(t *testing.T, ctx *ReportFindingContext, args map[string]any) tool.Result {
	t.Helper()
	result, err := NewReportFindingTool(ctx).Execute(context.Background(), args, nil)
	require.NoError(t, err)
	return result
}

func requireFindingNotSaved(t *testing.T, repo *database.Repository, projectUUID, title string) {
	t.Helper()
	_, err := repo.GetFindingByHash(context.Background(), hashFinding(title, "high", "", "", "A reproducible security issue."), projectUUID)
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestReportFindingResolvesRecordReferencesInProject(t *testing.T) {
	t.Run("prefix persists canonical UUID and relation", func(t *testing.T) {
		repo := newSectionTestRepo(t)
		projectUUID := uuid.NewString()
		recordUUID := seedReportFindingRecord(t, repo, projectUUID, "proof.project.invalid", "")
		title := "report finding valid record prefix"
		ctx := &ReportFindingContext{Repo: repo, ProjectUUID: projectUUID}

		result := executeReportFinding(t, ctx, reportFindingArgs(title, recordUUID[:8]))
		require.False(t, result.IsError, result.Content)

		finding, err := repo.GetFindingByHash(context.Background(), hashFinding(title, "high", "", "", "A reproducible security issue."), projectUUID)
		require.NoError(t, err)
		var refs []string
		err = repo.DB().NewRaw("SELECT record_uuid FROM finding_records WHERE finding_id = ?", finding.ID).Scan(context.Background(), &refs)
		require.NoError(t, err)
		require.Equal(t, []string{recordUUID}, refs)
	})

	t.Run("nonexistent UUID is rejected without saving", func(t *testing.T) {
		repo := newSectionTestRepo(t)
		projectUUID := uuid.NewString()
		nonexistent := uuid.NewString()
		title := "report finding nonexistent record"
		ctx := &ReportFindingContext{Repo: repo, ProjectUUID: projectUUID}

		result := executeReportFinding(t, ctx, reportFindingArgs(title, nonexistent))
		require.True(t, result.IsError, result.Content)
		require.Contains(t, result.Content, nonexistent)
		requireFindingNotSaved(t, repo, projectUUID, title)
	})

	t.Run("foreign-project UUID is rejected without saving", func(t *testing.T) {
		repo := newSectionTestRepo(t)
		projectUUID, otherProjectUUID := uuid.NewString(), uuid.NewString()
		foreignUUID := seedReportFindingRecord(t, repo, otherProjectUUID, "foreign.project.invalid", "")
		title := "report finding foreign record"
		ctx := &ReportFindingContext{Repo: repo, ProjectUUID: projectUUID}

		result := executeReportFinding(t, ctx, reportFindingArgs(title, foreignUUID))
		require.True(t, result.IsError, result.Content)
		require.Contains(t, result.Content, foreignUUID)
		requireFindingNotSaved(t, repo, projectUUID, title)
	})

	t.Run("ambiguous prefix reports only in-project candidates and does not save", func(t *testing.T) {
		repo := newSectionTestRepo(t)
		projectUUID, otherProjectUUID := uuid.NewString(), uuid.NewString()
		const prefix = "c0ffee00"
		candidateA := seedReportFindingRecord(t, repo, projectUUID, "candidate-a.project.invalid", prefix+"-0000-4000-8000-000000000001")
		candidateB := seedReportFindingRecord(t, repo, projectUUID, "candidate-b.project.invalid", prefix+"-0000-4000-8000-000000000002")
		foreignCandidate := seedReportFindingRecord(t, repo, otherProjectUUID, "candidate-foreign.project.invalid", prefix+"-0000-4000-8000-000000000003")
		title := "report finding ambiguous record prefix"
		ctx := &ReportFindingContext{Repo: repo, ProjectUUID: projectUUID}

		result := executeReportFinding(t, ctx, reportFindingArgs(title, prefix))
		require.True(t, result.IsError, result.Content)
		require.Contains(t, result.Content, candidateA)
		require.Contains(t, result.Content, candidateB)
		require.NotContains(t, result.Content, foreignCandidate)
		requireFindingNotSaved(t, repo, projectUUID, title)
	})
}
