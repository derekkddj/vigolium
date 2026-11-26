package runner

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// Two native scans running at once in one process (server mode: a scan-on-
// receive runner plus a submitted scan) must each persist their own console
// output and nothing of the other's. Capture used to redirect the process-wide
// stderr to whichever scan claimed it first, so that scan stored both scans'
// lines and the other stored none of its own.
func TestConcurrentScansKeepTheirOwnConsoleLogs(t *testing.T) {
	withoutGlobalEvents(t)
	dbCfg := newCallbackScanRunner(t).settings.Database
	dbCfg.Driver = "sqlite"
	dbCfg.SQLite.Path = filepath.Join(t.TempDir(), "console.sqlite")
	db, err := database.NewDB(&dbCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	repo := database.NewRepository(db)

	names := []string{"alpha", "bravo"}
	uuids := map[string]string{
		"alpha": "11111111-1111-4111-8111-111111111111",
		"bravo": "22222222-2222-4222-8222-222222222222",
	}
	// Both scans are inside their phase, with capture set up, before either
	// prints, and neither finishes before both have printed.
	var inPhase, printed sync.WaitGroup
	inPhase.Add(len(names))
	printed.Add(len(names))
	var wg sync.WaitGroup
	for _, name := range names {
		r := newCallbackScanRunner(t)
		r.options.Silent = false
		r.options.ScanUUID = uuids[name]
		r.SetRepository(repo)
		r.phaseRunners = map[NativePhase]phaseRunner{}
		var once sync.Once
		for _, phase := range []NativePhase{PhaseDiscovery, PhaseDynamicAssessment} {
			r.phaseRunners[phase] = phaseRunner{tag: string(phase), label: string(phase), run: func(r *Runner, _ context.Context, _ *phaseInfra) error {
				once.Do(func() {
					inPhase.Done()
					inPhase.Wait()
					r.printPhaseDetail("console-marker-" + name)
					printed.Done()
					printed.Wait()
				})
				return nil
			}}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.RunNativeScan(); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}()
	}
	wg.Wait()

	for _, name := range names {
		logs, _, err := repo.ListScanLogs(context.Background(), uuids[name], "trace", "", 10000, 0)
		if err != nil {
			t.Fatal(err)
		}
		var all strings.Builder
		for _, l := range logs {
			all.WriteString(l.Message + "\n")
		}
		got := all.String()
		for _, other := range names {
			has := strings.Contains(got, "console-marker-"+other)
			if other == name && !has {
				t.Errorf("scan %s did not keep its own console output", name)
			}
			if other != name && has {
				t.Errorf("scan %s stored scan %s's console output", name, other)
			}
		}
		if strings.Contains(got, uuids[otherOf(names, name)]) {
			t.Errorf("scan %s stored the other scan's configuration banner", name)
		}
	}
}

func otherOf(names []string, name string) string {
	for _, n := range names {
		if n != name {
			return n
		}
	}
	return ""
}
