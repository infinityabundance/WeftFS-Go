package store

// Writer-lock inheritance court (subphase T2), Go side.
//
// Go cannot fork without exec, but `exec.Cmd.ExtraFiles` duplicates a
// descriptor into the child at exec time. dup(2) shares the open file
// description, so the child holds exactly what a forked-but-not-yet-exec'd
// child holds in the Rust court: the same description with the same flock and
// OFD locks. That is enough to prove both the bug and the fix.
//
// Measured Rust court figures (examples/lock_probe.rs, court tmpfs):
// flock close-only 289/2,000 spurious Busy, OFD close-only 478/2,000,
// explicit unlock 0/2,000 for both.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const lockHelperEnv = "WEFT_LOCK_HELPER_US"

// TestLockHelperProcess is the child used by the two tests below. It holds
// whatever descriptors were passed to it and exits after the requested delay.
func TestLockHelperProcess(t *testing.T) {
	value := os.Getenv(lockHelperEnv)
	if value == "" {
		t.Skip("helper process only")
	}
	micros, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("bad %s=%q", lockHelperEnv, value)
	}
	time.Sleep(time.Duration(micros) * time.Microsecond)
}

func startLockHelper(t *testing.T, file *os.File) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"=300000")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	return cmd
}

func openLockFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open LOCK: %v", err)
	}
	return file
}

// Documented bug: closing the parent's descriptor without unlocking leaves the
// lock attached to the shared open file description the child still holds.
func TestLegacyFlockCloseOnlyStaysLockedByChild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LOCK")
	held := openLockFile(t, path)
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("initial flock: %v", err)
	}
	cmd := startLockHelper(t, held)
	// Close only: this is the old ownership proof.
	if err := held.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	probe := openLockFile(t, path)
	err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
		probe.Close()
		t.Fatalf("the legacy close-only flock must remain held by the child")
	}
	probe.Close()
	if !isWouldBlock(err) {
		t.Fatalf("unexpected flock error: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
}

// The shipped path: OFD plus the compatibility flock, both released explicitly
// before close. A child that still holds the description must not block the
// next writer.
func TestLockExclusiveIsNotBlockedByChildHoldingTheDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LOCK")
	lock, mechanism, err := lockExclusive(path)
	if err != nil {
		t.Fatalf("lockExclusive: %v", err)
	}
	if runtime.GOOS == "linux" && mechanism != lockMechanismOFD {
		t.Fatalf("expected the OFD record lock on Linux, got %q", mechanism)
	}
	cmd := startLockHelper(t, lock)
	if err := releaseLock(lock); err != nil {
		t.Fatalf("release: %v", err)
	}
	again, mechanism, err := lockExclusive(path)
	if err != nil {
		t.Fatalf("reopen after the child holds the description must succeed: %v", err)
	}
	if runtime.GOOS == "linux" && mechanism != lockMechanismOFD {
		t.Fatalf("expected the OFD record lock on reopen, got %q", mechanism)
	}
	if err := releaseLock(again); err != nil {
		t.Fatalf("release reopen: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
}

// Mixed-version exclusion both ways: flock and OFD are separate namespaces, so
// the compatibility flock is what keeps an older binary from sharing the store.
func TestExclusiveLockExcludesLegacyFlockWritersBothWays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LOCK")

	legacy := openLockFile(t, path)
	if err := syscall.Flock(int(legacy.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("legacy flock: %v", err)
	}
	if _, _, err := lockExclusive(path); err == nil {
		t.Fatalf("a live legacy flock writer must block lockExclusive")
	}
	if err := syscall.Flock(int(legacy.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("legacy unlock: %v", err)
	}
	legacy.Close()

	lock, _, err := lockExclusive(path)
	if err != nil {
		t.Fatalf("lockExclusive: %v", err)
	}
	probe := openLockFile(t, path)
	err = syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
		probe.Close()
		t.Fatalf("the shipped writer must block a legacy flock writer")
	}
	probe.Close()
	if err := releaseLock(lock); err != nil {
		t.Fatalf("release: %v", err)
	}
}

// A second live handle is still refused with Busy.
func TestSecondLiveWriterIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LOCK")
	first, _, err := lockExclusive(path)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, _, err := lockExclusive(path); err == nil {
		t.Fatalf("second writer must be refused")
	}
	if err := releaseLock(first); err != nil {
		t.Fatalf("release: %v", err)
	}
	second, _, err := lockExclusive(path)
	if err != nil {
		t.Fatalf("lock is free after release: %v", err)
	}
	if err := releaseLock(second); err != nil {
		t.Fatalf("release: %v", err)
	}
}

func isWouldBlock(err error) bool {
	return err == syscall.EWOULDBLOCK || err == syscall.EAGAIN || err == syscall.EACCES
}
