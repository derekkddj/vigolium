package runner

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestFindingAdmissionPersistenceNativeRejectionIsIncomplete(t *testing.T) {
	logCore, logs := observer.New(zap.WarnLevel)
	t.Cleanup(zap.ReplaceGlobals(zap.New(logCore)))
	r := &Runner{}
	tr := newLedger(string(PhaseDynamicAssessment))
	r.currentPhase.Store(tr)
	w := database.NewFindingWriter(nil, database.FindingWriterConfig{MaxPendingBytes: 1})
	t.Cleanup(w.Close)
	require.Error(t, w.Save(context.Background(), &output.ResultEvent{ModuleID: "oversize"}, nil, "scan", "project"))

	o := r.shutdownWriters(tr.phase, w)
	assert.Equal(t, int64(1), o.Rejected)
	assert.Zero(t, o.Accepted)
	assert.Zero(t, o.Failed)
	out := tr.finish(context.Background(), nil)
	assert.Equal(t, database.PhasePartial, out.State)
	assert.Equal(t, []string{database.ReasonPersistence}, out.Reasons)
	require.NotNil(t, out.Persistence)
	assert.Equal(t, o, *out.Persistence)
	r.scanOutcome.append(out)
	completion := r.Completion()
	assert.Equal(t, database.CompletenessPartial, completion.Completeness)
	assert.Equal(t, database.ReasonPersistence, completion.StopReason)
	assert.Contains(t, partialBannerSuffix(completion), database.ReasonPersistence)

	entries := logs.FilterMessage("phase persistence incomplete").All()
	require.Len(t, entries, 1, "native diagnostics must not omit rejected-only loss")
	assert.Equal(t, int64(1), entries[0].ContextMap()["rejected"])
	assert.Equal(t, int64(0), entries[0].ContextMap()["accepted"])
}

func TestFindingAdmissionPersistenceNativeDirectAndWriterFailures(t *testing.T) {
	tr := newLedger(string(PhaseDynamicAssessment))
	// Direct repository failures have no writer to drain. Writer-backed Save
	// errors must NOT be included in this executor counter (covered in core).
	tr.noteExecution(core.ExecutionReport{FindingStoreFailed: 2})
	tr.addPersistence(database.PersistenceOutcome{
		Writer:   database.PersistenceWriterFindings,
		Accepted: 3, Committed: 1, Failed: 2, Rejected: 1,
	})
	tr.noteExecution(core.ExecutionReport{})

	out := tr.finish(context.Background(), nil)
	require.NotNil(t, out.Persistence)
	o := *out.Persistence
	assert.Equal(t, int64(5), o.Accepted)
	assert.Equal(t, int64(1), o.Committed)
	assert.Equal(t, int64(4), o.Failed, "two direct, one inline and one async failure")
	assert.Equal(t, int64(1), o.Rejected, "admission loss stays outside accepted failures")
	assert.Zero(t, o.Unknown)
	assert.Equal(t, o.Accepted, o.Committed+o.Failed+o.Unknown)
	assert.Equal(t, database.PhasePartial, out.State)
	assert.Equal(t, []string{database.ReasonPersistence}, out.Reasons, "one shared persistence reason")
}

func TestFindingAdmissionPersistencePhaseEventIsCurtailed(t *testing.T) {
	buf := withEventStream(t)
	r := &Runner{}
	tr := r.beginPhase(context.Background(), string(PhaseDynamicAssessment), nil)
	tr.addPersistence(database.PersistenceOutcome{Writer: database.PersistenceWriterFindings, Rejected: 1})
	out := tr.finish(context.Background(), nil)

	assert.Equal(t, database.PhasePartial, out.State)
	finished := eventsOfType(t, buf, scanevents.TypePhaseFinished)
	require.Len(t, finished, 1)
	assert.Equal(t, scanevents.StatusCurtailed, finished[0]["status"])
	assert.Equal(t, []any{database.ReasonPersistence}, finished[0]["reasons"])
}

func TestFindingAdmissionPersistenceDirectCompletion(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failed      int64
		interrupted bool
		complete    string
		stop        string
	}{
		{name: "clean", complete: database.CompletenessComplete},
		{name: "save failure", failed: 2, complete: database.CompletenessPartial, stop: database.ReasonPersistence},
		{name: "cancellation outranks loss", failed: 2, interrupted: true, complete: database.CompletenessPartial, stop: database.ReasonCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DirectScanCompletion(core.ExecutionReport{Responded: 1, FindingStoreFailed: tc.failed},
				true, tc.interrupted, nil, database.TargetTally{})
			assert.Equal(t, tc.complete, c.Completeness)
			assert.Equal(t, tc.stop, c.StopReason)
			require.Len(t, c.Phases, 1)
			da := c.Phases[0]
			if tc.failed == 0 {
				assert.Nil(t, da.Persistence, "no failure subset is reported on the clean direct path")
				return
			}
			require.NotNil(t, da.Persistence)
			assert.Equal(t, tc.failed, da.Persistence.Accepted)
			assert.Equal(t, tc.failed, da.Persistence.Failed)
			assert.Zero(t, da.Persistence.Rejected)
			assert.Zero(t, da.Persistence.Committed)
			assert.Zero(t, da.Persistence.Unknown)
			assert.Contains(t, da.Reasons, database.ReasonPersistence)
			assert.Equal(t, database.PhasePartial, da.State)
		})
	}
}
