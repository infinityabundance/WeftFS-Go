package store

import (
	"os"
	"syscall"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Lock mechanisms reported by lockExclusive.
const (
	lockMechanismOFD   = "ofd"
	lockMechanismFlock = "flock"
)

// lockExclusive takes the single-writer lock on path.
//
// Two locks are held on one descriptor:
//
//   - flock(2) LOCK_EX, kept for mixed-version exclusion. On Linux, flock and
//     OFD/POSIX record locks live in separate lock namespaces and do not
//     conflict, so an OFD-only writer would silently share the store with an
//     older flock-only binary.
//   - fcntl(2) F_OFD_SETLK F_WRLCK, the primary ownership lock. It belongs to
//     the open file description, so an unrelated close in this process cannot
//     drop it.
//
// releaseLock unlocks both explicitly before closing. That explicit unlock is
// what stops a forked-but-not-yet-exec'd child from keeping the store locked:
// the child inherits the open file description (the descriptor is duplicated,
// so flock and OFD locks are both still held) until it execs, and closing the
// parent's descriptor alone does not release either lock.
func lockExclusive(path string) (*os.File, string, error) {
	lock, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_CLOEXEC, 0o644)
	if err != nil {
		return nil, "", werr.Wrap(werr.Io, err, "cannot open LOCK")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, "", werr.Wrap(werr.Busy, err, "store is locked by another writer")
	}
	mechanism, err := applyOFDWriteLock(int(lock.Fd()))
	if err != nil {
		// Never leave the compatibility flock behind on a failed acquisition:
		// the descriptor is about to close, but a forked child may still
		// reference the description.
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, "", werr.Wrap(werr.Busy, err, "store is locked by another writer")
	}
	return lock, mechanism, nil
}

// releaseLock unlocks both mechanisms explicitly, then closes.
func releaseLock(lock *os.File) error {
	if lock == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	releaseOFDWriteLock(int(lock.Fd()))
	closeErr := lock.Close()
	if unlockErr != nil {
		return werr.Wrap(werr.Io, unlockErr, "cannot unlock LOCK")
	}
	return closeErr
}
