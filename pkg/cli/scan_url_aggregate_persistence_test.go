package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestFindingAdmissionPersistencePinnedAggregate(t *testing.T) {
	var aggregate directScanAggregate
	aggregate.add(core.ExecutionReport{Responded: 1, FindingStoreFailed: 2}, true, false, nil, database.TargetTally{})
	aggregate.add(core.ExecutionReport{Responded: 1}, true, false, nil, database.TargetTally{})
	aggregate.add(core.ExecutionReport{Responded: 1, FindingStoreFailed: 3}, true, false, nil, database.TargetTally{})

	assert.Equal(t, int64(3), aggregate.rep.Responded)
	assert.Equal(t, int64(5), aggregate.rep.FindingStoreFailed, "a clean later input must not erase earlier direct save failures")
	assert.False(t, aggregate.rep.Clean())
	completion := runner.DirectScanCompletion(aggregate.rep, aggregate.reached, aggregate.interrupted, aggregate.err, aggregate.tally)
	assert.Equal(t, database.CompletenessPartial, completion.Completeness)
	assert.Equal(t, database.ReasonPersistence, completion.StopReason)
	require.Len(t, completion.Phases, 1)
	phase := completion.Phases[0]
	assert.Equal(t, database.PhasePartial, phase.State)
	assert.Contains(t, phase.Reasons, database.ReasonPersistence)
	require.NotNil(t, phase.Persistence)
	assert.Equal(t, int64(5), phase.Persistence.Accepted)
	assert.Equal(t, int64(5), phase.Persistence.Failed)
	assert.Zero(t, phase.Persistence.Committed)
	assert.Zero(t, phase.Persistence.Unknown)
	assert.Zero(t, phase.Persistence.Rejected, "direct failures are accepted writes, not writer admission rejections")
}
