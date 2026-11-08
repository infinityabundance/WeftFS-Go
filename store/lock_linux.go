//go:build linux

package store

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// applyOFDWriteLock takes F_OFD_SETLK F_WRLCK over the whole file. It reports
// "flock" when the kernel or filesystem rejects OFD locks with EINVAL (Linux
// < 3.15 or a filesystem without OFD support); the compatibility flock taken
// by the caller is then the only lock.
func applyOFDWriteLock(fd int) (string, error) {
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lock); err != nil {
		if errors.Is(err, syscall.EINVAL) {
			return lockMechanismFlock, nil
		}
		return "", err
	}
	return lockMechanismOFD, nil
}

func releaseOFDWriteLock(fd int) {
	lock := unix.Flock_t{Type: unix.F_UNLCK, Whence: 0, Start: 0, Len: 0}
	_ = unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lock)
}
