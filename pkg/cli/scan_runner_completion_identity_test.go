package cli

import (
	"context"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestRunnerScanURLCompletionUsesAdmittedScanUUID(t *testing.T) {
	resetProjectScopeGlobals(t)
	directRowFixture(t)
	swapGlobal(t, &globalScanUUID, "")
	swapGlobal(t, &globalSilent, false)
	swapGlobal(t, &scanURLNoPassive, true)
	swapGlobal(t, &scanPrintFinding, true)
	swapGlobal(t, &scanFailOn, "high")
	oldGate := failOnGateTriggered
	failOnGateTriggered = false
	t.Cleanup(func() { failOnGateTriggered = oldGate })

	srv := bareServer(t)
	target := srv.URL + "/completion-scope"
	parsed, err := url.Parse(target)
	require.NoError(t, err)
	port, err := strconv.Atoi(parsed.Port())
	require.NoError(t, err)

	db, err := getDB()
	require.NoError(t, err)
	repo := database.NewRepository(db)
	ctx := context.Background()
	const project = database.DefaultProjectUUID
	const priorScanUUID = "prior-project-scan"
	const priorFindingUUID = "prior-project-record"
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{
		UUID: priorScanUUID, ProjectUUID: project, Name: "earlier", Status: "completed",
		Target: target,
	}))
	require.NoError(t, repo.SaveFindingDirect(ctx, &database.Finding{
		ProjectUUID: project, ScanUUID: priorScanUUID,
		HTTPRecordUUIDs: []string{priorFindingUUID},
		ModuleID:        "prior-project-module", ModuleName: "Prior project finding",
		Severity: "high", Confidence: "firm", FindingHash: "prior-project-finding-hash",
		URL: target, Hostname: parsed.Hostname(),
	}))
	_, err = db.NewInsert().Model(&database.HTTPRecord{
		UUID: priorFindingUUID, ProjectUUID: project, Scheme: parsed.Scheme,
		Hostname: parsed.Hostname(), Port: port, Method: "GET", Path: parsed.RequestURI(),
		URL: target, HTTPVersion: "HTTP/1.1", RequestHash: "prior-project-request-hash",
		RawRequest: []byte("GET " + parsed.RequestURI() + " HTTP/1.1\r\nHost: " + parsed.Host + "\r\n\r\n"),
	}).Exec(ctx)
	require.NoError(t, err)

	in := directInput(t, target)
	var runErr error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			runErr = runRunnerScan(nil, in.rr, in.target)
		})
	})
	require.NoError(t, runErr)

	var scans []*database.Scan
	require.NoError(t, db.NewSelect().Model(&scans).Where("project_uuid = ?", project).Scan(ctx))
	var admitted *database.Scan
	for _, scan := range scans {
		if scan.Target == target && scan.UUID != priorScanUUID {
			require.Nil(t, admitted, "one runner-backed scan should be admitted for this input")
			admitted = scan
		}
	}
	require.NotNil(t, admitted, "runner-backed scan row must exist")
	require.NotEmpty(t, admitted.UUID)
	require.Equal(t, "completed", admitted.Status)
	require.Contains(t, stderr, "Scan ID: "+admitted.UUID, "completion output must identify the admitted scan")

	// The prior high finding is in the same project and on the same target, but
	// belongs to an earlier scan. Completion must use the newly admitted scan ID
	// for both the gate and --print-finding rather than falling back to project scope.
	assert.False(t, failOnGateTriggered, "a prior project finding must not trip this scan's --fail-on gate")
	require.NotContains(t, stdout, "Prior project finding", "--print-finding must exclude earlier scans")
	require.Contains(t, stderr, "Findings: no issues found", "the completion summary must describe this scan only")
}
