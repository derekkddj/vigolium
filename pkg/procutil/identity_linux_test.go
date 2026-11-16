//go:build linux

package procutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	testProcessIdentityPID       = 42
	testProcessIdentityBootID    = "11111111-2222-4333-8444-555555555555"
	testProcessIdentityNamespace = "pid:[4026531836]"
	testProcessIdentityTicks     = 123456
)

func testProcessIdentity() Identity {
	return Identity{
		PID:          testProcessIdentityPID,
		BootID:       testProcessIdentityBootID,
		PIDNamespace: testProcessIdentityNamespace,
		StartTicks:   testProcessIdentityTicks,
	}
}

// Only fields after comm are whitespace-delimited. Distinct preceding values
// make an off-by-one field-22 parser fail rather than accidentally pass.
func testProcessIdentityStat(pid int, comm, ticks string) []byte {
	fields := make([]string, 20)
	fields[0] = "S"
	for i := 1; i < 19; i++ {
		fields[i] = strconv.Itoa(i)
	}
	fields[19] = ticks
	return []byte(fmt.Sprintf("%d (%s) %s 23 24 25\n", pid, comm, strings.Join(fields, " ")))
}

type processIdentityFixture struct {
	t            *testing.T
	boot         []byte
	bootErr      error
	namespace    string
	namespaceErr error
	stat         []byte
	statErr      error
	calls        []string
}

func newProcessIdentityFixture(t *testing.T) *processIdentityFixture {
	t.Helper()
	return &processIdentityFixture{
		t:         t,
		boot:      []byte(testProcessIdentityBootID + "\n"),
		namespace: testProcessIdentityNamespace,
		stat:      testProcessIdentityStat(testProcessIdentityPID, "scan worker (nested)", strconv.Itoa(testProcessIdentityTicks)),
	}
}

func (fixture *processIdentityFixture) reader() processIdentityReader {
	return processIdentityReader{
		readFile: func(path string, maxBytes int) ([]byte, error) {
			fixture.calls = append(fixture.calls, path)
			switch path {
			case processIdentityBootPath:
				if maxBytes != processIdentityBootMaxBytes {
					fixture.t.Fatalf("boot read limit = %d, want %d", maxBytes, processIdentityBootMaxBytes)
				}
				return fixture.boot, fixture.bootErr
			case processIdentityStatPath(testProcessIdentityPID):
				if maxBytes != processIdentityStatMaxBytes {
					fixture.t.Fatalf("stat read limit = %d, want %d", maxBytes, processIdentityStatMaxBytes)
				}
				return fixture.stat, fixture.statErr
			default:
				fixture.t.Fatalf("unexpected file read: %s", path)
				return nil, os.ErrNotExist
			}
		},
		readlink: func(path string) (string, error) {
			fixture.calls = append(fixture.calls, path)
			if path != processIdentityNamespacePath {
				fixture.t.Fatalf("unexpected readlink: %s", path)
			}
			return fixture.namespace, fixture.namespaceErr
		},
	}
}

func (fixture *processIdentityFixture) assertNoStatRead(t *testing.T) {
	t.Helper()
	for _, path := range fixture.calls {
		if path == processIdentityStatPath(testProcessIdentityPID) {
			t.Fatal("target stat was read without a valid matched environment")
		}
	}
}

func TestParseProcessStatStartTicksComm(t *testing.T) {
	for _, comm := range []string{
		"vigolium",
		"scan worker with spaces",
		"scan (worker (nested)) done",
		"scan (((unbalanced",
		"scan ))) unbalanced",
		"scan ) 999 fake fields (still comm)",
		"scan\nworker\twith whitespace",
		"",
	} {
		t.Run(comm, func(t *testing.T) {
			data := testProcessIdentityStat(testProcessIdentityPID, comm, strconv.Itoa(testProcessIdentityTicks))
			got, err := parseProcessStatStartTicks(data, testProcessIdentityPID)
			if err != nil {
				t.Fatal(err)
			}
			if got != testProcessIdentityTicks {
				t.Fatalf("start ticks = %d, want %d", got, testProcessIdentityTicks)
			}
		})
	}
}

func TestParseProcessStatStartTicksRejectsMalformed(t *testing.T) {
	valid := testProcessIdentityStat(testProcessIdentityPID, "worker", "777")
	tests := []struct {
		name string
		data []byte
		pid  int
	}{
		{name: "blank", data: nil, pid: testProcessIdentityPID},
		{name: "missing_open", data: []byte("42 worker) S 1"), pid: testProcessIdentityPID},
		{name: "missing_close", data: []byte("42 (worker S 1"), pid: testProcessIdentityPID},
		{name: "missing_comm_separator", data: []byte("42 (worker)S 1"), pid: testProcessIdentityPID},
		{name: "missing_pid_separator", data: []byte("42(worker) S 1"), pid: testProcessIdentityPID},
		{name: "short_fields", data: []byte("42 (worker) S 1 2 3"), pid: testProcessIdentityPID},
		{name: "wrong_pid", data: valid, pid: testProcessIdentityPID + 1},
		{name: "zero_expected_pid", data: valid, pid: 0},
		{name: "negative_expected_pid", data: valid, pid: -1},
		{name: "non_numeric_pid", data: []byte(strings.Replace(string(valid), "42 (", "xx (", 1)), pid: testProcessIdentityPID},
		{name: "non_canonical_pid", data: []byte(strings.Replace(string(valid), "42 (", "+42 (", 1)), pid: testProcessIdentityPID},
		{name: "invalid_state", data: []byte(strings.Replace(string(valid), ") S ", ") ? ", 1)), pid: testProcessIdentityPID},
		{name: "zero_ticks", data: testProcessIdentityStat(testProcessIdentityPID, "worker", "0"), pid: testProcessIdentityPID},
		{name: "negative_ticks", data: testProcessIdentityStat(testProcessIdentityPID, "worker", "-1"), pid: testProcessIdentityPID},
		{name: "non_numeric_ticks", data: testProcessIdentityStat(testProcessIdentityPID, "worker", "bad"), pid: testProcessIdentityPID},
		{name: "signed_ticks", data: testProcessIdentityStat(testProcessIdentityPID, "worker", "+777"), pid: testProcessIdentityPID},
		{name: "leading_zero_ticks", data: testProcessIdentityStat(testProcessIdentityPID, "worker", "0777"), pid: testProcessIdentityPID},
		{name: "overflow_ticks", data: testProcessIdentityStat(testProcessIdentityPID, "worker", "18446744073709551616"), pid: testProcessIdentityPID},
		{name: "oversized", data: []byte(strings.Repeat("x", processIdentityStatMaxBytes+1)), pid: testProcessIdentityPID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseProcessStatStartTicks(test.data, test.pid)
			if err == nil || got != 0 {
				t.Fatalf("parse = (%d, %v), want zero ticks and error", got, err)
			}
		})
	}
}

func TestCaptureCurrentProcessIdentityComplete(t *testing.T) {
	fixture := newProcessIdentityFixture(t)
	got, err := captureCurrentProcessIdentity(testProcessIdentityPID, fixture.reader())
	if err != nil {
		t.Fatal(err)
	}
	if got != testProcessIdentity() {
		t.Fatalf("capture = %+v, want %+v", got, testProcessIdentity())
	}
	wantCalls := []string{processIdentityBootPath, processIdentityNamespacePath, processIdentityStatPath(testProcessIdentityPID)}
	if strings.Join(fixture.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("capture calls = %v, want %v", fixture.calls, wantCalls)
	}
}

func TestCaptureCurrentProcessIdentityRejectsInvalidPID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		fixture := newProcessIdentityFixture(t)
		got, err := captureCurrentProcessIdentity(pid, fixture.reader())
		if err == nil || got != (Identity{}) {
			t.Fatalf("capture(%d) = (%+v, %v), want zero identity and error", pid, got, err)
		}
		if len(fixture.calls) != 0 {
			t.Fatalf("invalid PID performed I/O: %v", fixture.calls)
		}
	}
}

func TestCaptureCurrentProcessIdentityNoPartialProof(t *testing.T) {
	t.Run("current_pid_missing", func(t *testing.T) {
		fixture := newProcessIdentityFixture(t)
		fixture.statErr = os.ErrNotExist
		got, err := captureCurrentProcessIdentity(testProcessIdentityPID, fixture.reader())
		if err == nil || got != (Identity{}) || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("capture = (%+v, %v), want zero identity and ENOENT", got, err)
		}
	})
	for _, test := range processIdentityObservationFailures() {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProcessIdentityFixture(t)
			test.modify(fixture)
			got, err := captureCurrentProcessIdentity(testProcessIdentityPID, fixture.reader())
			if err == nil || got != (Identity{}) {
				t.Fatalf("capture = (%+v, %v), want zero identity and error", got, err)
			}
		})
	}
}

func TestProbeProcessIdentityIncarnation(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*processIdentityFixture)
		want   ProcessIdentityStatus
	}{
		{name: "alive", modify: func(*processIdentityFixture) {}, want: ProcessIdentityAlive},
		{name: "missing_pid", modify: func(f *processIdentityFixture) { f.statErr = os.ErrNotExist }, want: ProcessIdentityDead},
		{
			name: "wrapped_missing_pid",
			modify: func(f *processIdentityFixture) {
				f.statErr = fmt.Errorf("stat: %w", &os.PathError{Op: "open", Path: processIdentityStatPath(testProcessIdentityPID), Err: syscall.ENOENT})
			},
			want: ProcessIdentityDead,
		},
		{
			name: "pid_reuse_later_ticks",
			modify: func(f *processIdentityFixture) {
				f.stat = testProcessIdentityStat(testProcessIdentityPID, "replacement", strconv.Itoa(testProcessIdentityTicks+1))
			},
			want: ProcessIdentityDead,
		},
		{
			name: "pid_reuse_earlier_ticks",
			modify: func(f *processIdentityFixture) {
				f.stat = testProcessIdentityStat(testProcessIdentityPID, "replacement", strconv.Itoa(testProcessIdentityTicks-1))
			},
			want: ProcessIdentityDead,
		},
		{
			name: "zombie_is_conservatively_alive",
			modify: func(f *processIdentityFixture) {
				f.stat = []byte(strings.Replace(string(f.stat), ") S ", ") Z ", 1))
			},
			want: ProcessIdentityAlive,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProcessIdentityFixture(t)
			test.modify(fixture)
			if got := probeProcessIdentity(testProcessIdentity(), fixture.reader()); got != test.want {
				t.Fatalf("probe = %v, want %v", got, test.want)
			}
			if len(fixture.calls) != 3 {
				t.Fatalf("probe did not check boot, namespace, and stat: %v", fixture.calls)
			}
		})
	}
}

func TestProbeProcessIdentityRejectsMalformedIdentity(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Identity)
	}{
		{name: "blank", modify: func(i *Identity) { *i = Identity{} }},
		{name: "zero_pid", modify: func(i *Identity) { i.PID = 0 }},
		{name: "negative_pid", modify: func(i *Identity) { i.PID = -1 }},
		{name: "zero_ticks", modify: func(i *Identity) { i.StartTicks = 0 }},
		{name: "blank_boot", modify: func(i *Identity) { i.BootID = "" }},
		{name: "malformed_boot", modify: func(i *Identity) { i.BootID = "not-a-boot-id" }},
		{name: "nil_boot_uuid", modify: func(i *Identity) { i.BootID = "00000000-0000-0000-0000-000000000000" }},
		{name: "boot_whitespace", modify: func(i *Identity) { i.BootID += "\n" }},
		{name: "blank_namespace", modify: func(i *Identity) { i.PIDNamespace = "" }},
		{name: "wrong_namespace_kind", modify: func(i *Identity) { i.PIDNamespace = "mnt:[4026531836]" }},
		{name: "malformed_namespace", modify: func(i *Identity) { i.PIDNamespace = "pid:[abc]" }},
		{name: "zero_namespace_inode", modify: func(i *Identity) { i.PIDNamespace = "pid:[0]" }},
		{name: "namespace_inode_overflow", modify: func(i *Identity) { i.PIDNamespace = "pid:[18446744073709551616]" }},
		{name: "namespace_signed_inode", modify: func(i *Identity) { i.PIDNamespace = "pid:[+4026531836]" }},
		{name: "namespace_leading_zero", modify: func(i *Identity) { i.PIDNamespace = "pid:[04026531836]" }},
		{name: "namespace_whitespace", modify: func(i *Identity) { i.PIDNamespace += " " }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			old := testProcessIdentity()
			test.modify(&old)
			fixture := newProcessIdentityFixture(t)
			fixture.statErr = os.ErrNotExist
			if got := probeProcessIdentity(old, fixture.reader()); got != ProcessIdentityUnknown {
				t.Fatalf("probe = %v, want Unknown", got)
			}
			if len(fixture.calls) != 0 {
				t.Fatalf("malformed identity performed I/O: %v", fixture.calls)
			}
		})
	}
}

func TestProbeProcessIdentityDifferentEnvironmentIsUnknown(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*processIdentityFixture)
	}{
		{
			name: "different_boot_or_host",
			modify: func(f *processIdentityFixture) {
				f.boot = []byte("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n")
			},
		},
		{
			name: "different_pid_namespace",
			modify: func(f *processIdentityFixture) {
				f.namespace = "pid:[4026531837]"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProcessIdentityFixture(t)
			test.modify(fixture)
			fixture.statErr = os.ErrNotExist
			if got := probeProcessIdentity(testProcessIdentity(), fixture.reader()); got != ProcessIdentityUnknown {
				t.Fatalf("probe = %v, want Unknown even if PID is missing", got)
			}
			fixture.assertNoStatRead(t)
		})
	}
}

func TestProbeProcessIdentityObservationErrorsAreUnknown(t *testing.T) {
	for _, test := range processIdentityObservationFailures() {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProcessIdentityFixture(t)
			test.modify(fixture)
			if got := probeProcessIdentity(testProcessIdentity(), fixture.reader()); got != ProcessIdentityUnknown {
				t.Fatalf("probe = %v, want Unknown", got)
			}
			if test.environmentFailure {
				fixture.assertNoStatRead(t)
			}
		})
	}
}

// These errors invalidate both capture and probing. A missing *target* stat is
// separately tested as Dead, while missing boot/namespace evidence is Unknown.
func processIdentityObservationFailures() []struct {
	name               string
	modify             func(*processIdentityFixture)
	environmentFailure bool
} {
	return []struct {
		name               string
		modify             func(*processIdentityFixture)
		environmentFailure bool
	}{
		{name: "boot_eacces", modify: func(f *processIdentityFixture) { f.bootErr = syscall.EACCES }, environmentFailure: true},
		{name: "boot_missing", modify: func(f *processIdentityFixture) { f.bootErr = os.ErrNotExist }, environmentFailure: true},
		{name: "boot_blank", modify: func(f *processIdentityFixture) { f.boot = []byte(" \n") }, environmentFailure: true},
		{name: "boot_malformed", modify: func(f *processIdentityFixture) { f.boot = []byte("bad\n") }, environmentFailure: true},
		{name: "boot_oversized", modify: func(f *processIdentityFixture) {
			f.boot = []byte(strings.Repeat(" ", processIdentityBootMaxBytes) + testProcessIdentityBootID)
		}, environmentFailure: true},
		{name: "namespace_eacces", modify: func(f *processIdentityFixture) { f.namespaceErr = syscall.EACCES }, environmentFailure: true},
		{name: "namespace_missing", modify: func(f *processIdentityFixture) { f.namespaceErr = os.ErrNotExist }, environmentFailure: true},
		{name: "namespace_blank", modify: func(f *processIdentityFixture) { f.namespace = "" }, environmentFailure: true},
		{name: "namespace_malformed", modify: func(f *processIdentityFixture) { f.namespace = "pid:[bad]" }, environmentFailure: true},
		{name: "stat_eacces", modify: func(f *processIdentityFixture) {
			f.statErr = &os.PathError{Op: "open", Path: processIdentityStatPath(testProcessIdentityPID), Err: syscall.EACCES}
		}},
		{name: "stat_eio", modify: func(f *processIdentityFixture) { f.statErr = syscall.EIO }},
		{name: "stat_data_with_read_error", modify: func(f *processIdentityFixture) { f.statErr = errors.New("partial read") }},
		{name: "stat_parse_failure", modify: func(f *processIdentityFixture) { f.stat = []byte("malformed stat") }},
		{name: "stat_zero_ticks", modify: func(f *processIdentityFixture) {
			f.stat = testProcessIdentityStat(testProcessIdentityPID, "worker", "0")
		}},
		{name: "stat_wrong_pid", modify: func(f *processIdentityFixture) {
			f.stat = testProcessIdentityStat(testProcessIdentityPID+1, "worker", strconv.Itoa(testProcessIdentityTicks))
		}},
		{
			name: "stat_oversized_even_with_valid_prefix",
			modify: func(f *processIdentityFixture) {
				f.stat = append(f.stat, []byte(strings.Repeat(" ", processIdentityStatMaxBytes))...)
			},
		},
	}
}

func TestReadBoundedProcessIdentityFile(t *testing.T) {
	for _, test := range []struct {
		name     string
		size     int
		wantFail bool
	}{
		{name: "below_limit", size: 3},
		{name: "at_limit", size: 4},
		{name: "above_limit", size: 5, wantFail: true},
		{name: "much_above_limit", size: processIdentityStatMaxBytes, wantFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity")
			content := []byte(strings.Repeat("x", test.size))
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			data, err := readBoundedProcessIdentityFile(path, 4)
			if test.wantFail {
				if err == nil || data != nil {
					t.Fatalf("read = (%q, %v), want nil data and error", data, err)
				}
				return
			}
			if err != nil || string(data) != string(content) {
				t.Fatalf("read = (%q, %v), want %q and no error", data, err, content)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		data, err := readBoundedProcessIdentityFile(filepath.Join(t.TempDir(), "missing"), 4)
		if data != nil || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read = (%q, %v), want nil data and ENOENT", data, err)
		}
	})
}
