//go:build linux

package procutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	processIdentityBootPath      = "/proc/sys/kernel/random/boot_id"
	processIdentityNamespacePath = "/proc/self/ns/pid"
	processIdentityBootMaxBytes  = 4 << 10
	processIdentityStatMaxBytes  = 64 << 10
	processIdentityMaxPID        = 1<<31 - 1
)

// processIdentityReader provides per-call I/O seams without mutable global test
// hooks. readFile must perform a bounded read; callers also check the returned
// length so a faulty or injected reader cannot turn oversized input into proof.
type processIdentityReader struct {
	readFile func(path string, maxBytes int) ([]byte, error)
	readlink func(path string) (string, error)
}

// processIdentityEnvironment is intentionally distinct from Identity: observing
// our boot and namespace says nothing about our own process's start ticks.
type processIdentityEnvironment struct {
	bootID       string
	pidNamespace string
}

// CaptureCurrentProcessIdentity returns a complete Linux procfs identity for the
// calling process. Any read or validation failure returns a zero Identity and an
// error wrapping ErrProcessIdentityUnavailable, never a partial proof.
func CaptureCurrentProcessIdentity() (Identity, error) {
	identity, err := captureCurrentProcessIdentity(os.Getpid(), systemProcessIdentityReader())
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrProcessIdentityUnavailable, err)
	}
	return identity, nil
}

// ProbeProcessIdentity compares old only within this boot and PID namespace.
// Different boots (including a reboot), different namespaces, invalid identities,
// and any observation error are Unknown. Only a missing PID or changed start
// ticks in a successfully matched environment establishes Dead. It sends no
// signals and never treats a PID-only existence check as incarnation evidence.
func ProbeProcessIdentity(old Identity) ProcessIdentityStatus {
	return probeProcessIdentity(old, systemProcessIdentityReader())
}

func systemProcessIdentityReader() processIdentityReader {
	return processIdentityReader{
		readFile: readBoundedProcessIdentityFile,
		readlink: os.Readlink,
	}
}

func captureCurrentProcessIdentity(pid int, reader processIdentityReader) (Identity, error) {
	if !validProcessIdentityPID(pid) {
		return Identity{}, errors.New("invalid current process PID")
	}
	environment, err := readProcessIdentityEnvironment(reader)
	if err != nil {
		return Identity{}, err
	}
	data, err := reader.readLimitedFile(processIdentityStatPath(pid), processIdentityStatMaxBytes)
	if err != nil {
		return Identity{}, fmt.Errorf("read current process stat: %w", err)
	}
	startTicks, err := parseProcessStatStartTicks(data, pid)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		PID:          pid,
		BootID:       environment.bootID,
		PIDNamespace: environment.pidNamespace,
		StartTicks:   startTicks,
	}, nil
}

func probeProcessIdentity(old Identity, reader processIdentityReader) ProcessIdentityStatus {
	if !validProcessIdentity(old) {
		return ProcessIdentityUnknown
	}
	environment, err := readProcessIdentityEnvironment(reader)
	if err != nil || environment.bootID != old.BootID || environment.pidNamespace != old.PIDNamespace {
		return ProcessIdentityUnknown
	}
	data, err := reader.readLimitedFile(processIdentityStatPath(old.PID), processIdentityStatMaxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProcessIdentityDead
		}
		return ProcessIdentityUnknown
	}
	startTicks, err := parseProcessStatStartTicks(data, old.PID)
	if err != nil {
		return ProcessIdentityUnknown
	}
	if startTicks != old.StartTicks {
		return ProcessIdentityDead
	}
	return ProcessIdentityAlive
}

func readProcessIdentityEnvironment(reader processIdentityReader) (processIdentityEnvironment, error) {
	data, err := reader.readLimitedFile(processIdentityBootPath, processIdentityBootMaxBytes)
	if err != nil {
		return processIdentityEnvironment{}, fmt.Errorf("read boot ID: %w", err)
	}
	bootID := strings.TrimSpace(string(data))
	if !validProcessIdentityBootID(bootID) {
		return processIdentityEnvironment{}, errors.New("invalid boot ID")
	}
	pidNamespace, err := reader.readlink(processIdentityNamespacePath)
	if err != nil {
		return processIdentityEnvironment{}, fmt.Errorf("read PID namespace: %w", err)
	}
	if !validProcessIdentityNamespace(pidNamespace) {
		return processIdentityEnvironment{}, errors.New("invalid PID namespace")
	}
	return processIdentityEnvironment{bootID: bootID, pidNamespace: pidNamespace}, nil
}

func validProcessIdentity(identity Identity) bool {
	return validProcessIdentityPID(identity.PID) && identity.StartTicks > 0 &&
		validProcessIdentityBootID(identity.BootID) && validProcessIdentityNamespace(identity.PIDNamespace)
}

func validProcessIdentityPID(pid int) bool {
	return pid > 0 && pid <= processIdentityMaxPID
}

func validProcessIdentityBootID(bootID string) bool {
	// Linux emits a canonical lowercase UUID. Reject whitespace, placeholders,
	// and malformed persisted values rather than normalizing ambiguous evidence.
	if len(bootID) != 36 || bootID == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i := 0; i < len(bootID); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if bootID[i] != '-' {
				return false
			}
			continue
		}
		if !((bootID[i] >= '0' && bootID[i] <= '9') || (bootID[i] >= 'a' && bootID[i] <= 'f')) {
			return false
		}
	}
	return true
}

func validProcessIdentityNamespace(namespace string) bool {
	if !strings.HasPrefix(namespace, "pid:[") || !strings.HasSuffix(namespace, "]") {
		return false
	}
	inodeText := namespace[len("pid:[") : len(namespace)-1]
	inode, err := strconv.ParseUint(inodeText, 10, 64)
	return err == nil && inode > 0 && strconv.FormatUint(inode, 10) == inodeText
}

func processIdentityStatPath(pid int) string {
	return "/proc/" + strconv.Itoa(pid) + "/stat"
}

// parseProcessStatStartTicks reads field 22. comm (field 2) can itself contain
// whitespace, newlines, and unbalanced or nested parentheses. Its closing
// delimiter is the last ')', not the first ')' or the second whitespace token.
func parseProcessStatStartTicks(data []byte, expectedPID int) (uint64, error) {
	if len(data) > processIdentityStatMaxBytes || !validProcessIdentityPID(expectedPID) {
		return 0, errors.New("invalid process stat size or expected PID")
	}
	stat := string(data)
	open := strings.IndexByte(stat, '(')
	close := strings.LastIndexByte(stat, ')')
	if open < 2 || close < open || stat[open-1] != ' ' || close+1 >= len(stat) || stat[close+1] != ' ' {
		return 0, errors.New("invalid process stat comm delimiters")
	}
	pidText := stat[:open-1]
	pid, err := strconv.Atoi(pidText)
	if err != nil || !validProcessIdentityPID(pid) || pid != expectedPID || strconv.Itoa(pid) != pidText {
		return 0, errors.New("process stat PID does not match")
	}
	// The suffix starts at field 3 (state), so field 22 is suffix index 19.
	fields := strings.Fields(stat[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.ContainsAny(fields[0], "RSDZTWtXxKIP") {
		return 0, errors.New("invalid process stat fields")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 || strconv.FormatUint(startTicks, 10) != fields[19] {
		return 0, errors.New("invalid process stat start ticks")
	}
	return startTicks, nil
}

func (reader processIdentityReader) readLimitedFile(path string, maxBytes int) ([]byte, error) {
	data, err := reader.readFile(path, maxBytes)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("process identity file %s exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}

func readBoundedProcessIdentityFile(path string, maxBytes int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close() //nolint:errcheck
	// One extra byte detects overflow without an unbounded ReadAll on procfs.
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("process identity file %s exceeds %d bytes", path, maxBytes)
	}
	return data, nil
}
