//go:build !linux

package store

// OFD locks are Linux-specific. Every other platform uses the flock taken by
// lockExclusive, with the same explicit unlock before close.
func applyOFDWriteLock(int) (string, error) { return lockMechanismFlock, nil }

func releaseOFDWriteLock(int) {}
