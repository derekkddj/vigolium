package runner

import (
	"sort"
	"sync"
)

// harvestVersionAdoptions is an explicit handoff from this invocation's harvest
// probe to native assessment. Only UUIDs, leases and acknowledgement metadata are
// retained. The generation makes late callbacks harmless even on a same-ID rescan.
type harvestVersionAdoptions struct {
	mu                    sync.Mutex
	scanUUID, projectUUID string
	generation, nextOwner uint64
	versions              map[string]string             // harvested seed UUID -> successful SaveRecordVersion result
	explicit              map[string]*harvestVersionAck // every unique successful returned UUID, including dedup
	changed               chan struct{}
}

type harvestVersionAck struct {
	owner    uint64 // source lease; zero means available for a later round
	complete bool
}

// signalLocked wakes sources waiting for acknowledgements or a released lease.
func (a *harvestVersionAdoptions) signalLocked() {
	if a.changed != nil {
		close(a.changed)
	}
	a.changed = make(chan struct{})
}

// resetHarvestProbeState runs at invocation start, even if identity setup fails
// or external-harvest is absent. Never copy the mutex or inherit completed UUIDs.
func (r *Runner) resetHarvestProbeState(scanUUID, projectUUID string) {
	r.harvestStubs = nil
	a := &r.harvestVersions
	a.mu.Lock()
	defer a.mu.Unlock()
	a.generation++
	a.scanUUID, a.projectUUID = scanUUID, projectUUID
	a.versions, a.explicit = nil, nil
	a.signalLocked()
}

func (r *Runner) rememberHarvestVersion(scanUUID, projectUUID, seedUUID, versionUUID string) {
	a := &r.harvestVersions
	a.mu.Lock()
	defer a.mu.Unlock()
	r.rememberHarvestVersionLocked(scanUUID, projectUUID, seedUUID, versionUUID)
}

// The detached harvest writer carries the generation captured before fetching,
// not just IDs: a same-ID invocation reset must not accept an old writer's return.
func (r *Runner) rememberHarvestVersionForRun(generation uint64, scanUUID, projectUUID, seedUUID, versionUUID string) {
	a := &r.harvestVersions
	a.mu.Lock()
	defer a.mu.Unlock()
	if generation == a.generation {
		r.rememberHarvestVersionLocked(scanUUID, projectUUID, seedUUID, versionUUID)
	}
}

// rememberHarvestVersionLocked requires harvestVersions.mu.
func (r *Runner) rememberHarvestVersionLocked(scanUUID, projectUUID, seedUUID, versionUUID string) {
	a := &r.harvestVersions
	if scanUUID == "" || projectUUID == "" || seedUUID == "" || versionUUID == "" ||
		a.scanUUID != scanUUID || a.projectUUID != projectUUID || r.options == nil ||
		r.options.ScanUUID != scanUUID || r.options.ProjectUUID != projectUUID {
		return
	}
	if a.versions == nil {
		a.versions = make(map[string]string)
		a.explicit = make(map[string]*harvestVersionAck)
	}
	// An exact dedup hit does not fire OnRecordSaved. Neither it nor a later
	// different successful return for the same seed may disappear from the handoff.
	if seedUUID != versionUUID {
		a.versions[seedUUID] = versionUUID
	} else {
		// No supersession when the successful return is the same record. It
		// still belongs in receive admission, but normal DA must not exclude it.
		delete(a.versions, seedUUID)
	}
	if a.explicit[versionUUID] == nil {
		a.explicit[versionUUID] = &harvestVersionAck{}
	}
	a.signalLocked()
}

func (r *Runner) harvestAdmissionSnapshot(scanUUID string) (generation uint64, seeds, versions []string) {
	a := &r.harvestVersions
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.options == nil || scanUUID == "" || a.scanUUID != scanUUID ||
		r.options.ScanUUID != scanUUID || a.projectUUID == "" || a.projectUUID != r.options.ProjectUUID {
		return 0, nil, nil
	}
	for id := range a.versions {
		seeds = append(seeds, id)
	}
	for id := range a.explicit {
		versions = append(versions, id)
	}
	sort.Strings(seeds)
	sort.Strings(versions)
	return a.generation, seeds, versions
}

func (r *Runner) supersededHarvestSeedUUIDs(scanUUID string) []string {
	_, seeds, _ := r.harvestAdmissionSnapshot(scanUUID)
	return seeds
}

func (r *Runner) harvestAssessmentExcludedUUIDs(scanUUID string) []string {
	_, seeds, versions := r.harvestAdmissionSnapshot(scanUUID)
	if r.options != nil && (r.options.ScanOnReceive || r.options.FullNativeScanOnReceive) {
		// Receive admission explicitly queues every saved version, independent of
		// the cursor. Neither a historical seed nor its version may take a shape slot.
		seeds = append(seeds, versions...)
	}
	return seeds
}

func (r *Runner) pendingHarvestVersionCount(scanUUID string) int64 {
	if r.options == nil || (!r.options.ScanOnReceive && !r.options.FullNativeScanOnReceive) {
		return 0
	}
	a := &r.harvestVersions
	a.mu.Lock()
	defer a.mu.Unlock()
	if scanUUID == "" || a.scanUUID != scanUUID || r.options.ScanUUID != scanUUID ||
		a.projectUUID == "" || a.projectUUID != r.options.ProjectUUID {
		return 0
	}
	var n int64
	for _, ack := range a.explicit {
		if !ack.complete {
			n++
		}
	}
	return n
}
