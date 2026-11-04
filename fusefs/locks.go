package fusefs

import (
	"context"
	"math"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/infinityabundance/WeftFS-Go/model"
)

// v1 kernel-assisted locking.
//
// The manager is deliberately small and advisory: it tracks POSIX byte ranges
// and flock entries per object and open-file-description owner. It never
// persists anything and never blocks foreground I/O. The FUSE kernel binding
// expresses both namespaces (fuse.LK_FLOCK distinguishes flock), so no verb
// needs ENOSYS.
//
// Known limitation (documented, not hidden): FUSE only reveals a POSIX lock
// owner when a lock request arrives, so a close of a descriptor that never
// acquired a lock cannot release the process's locks on that file the way
// local POSIX close-any-fd does. Owners seen on a handle are released when that
// handle is released; explicit F_UNLCK requests are always honored.

type byteRangeLock struct {
	owner uint64
	pid   uint32
	start uint64
	end   uint64 // inclusive; math.MaxUint64 means EOF
	typ   uint32
}

type flockOwnedLock struct {
	owner uint64
	pid   uint32
	typ   uint32
}

type lockManager struct {
	mu     sync.Mutex
	ranges map[model.Hash32][]byteRangeLock
	flocks map[model.Hash32][]flockOwnedLock
	notify map[model.Hash32]chan struct{}
}

func newLockManager() *lockManager {
	return &lockManager{
		ranges: make(map[model.Hash32][]byteRangeLock),
		flocks: make(map[model.Hash32][]flockOwnedLock),
		notify: make(map[model.Hash32]chan struct{}),
	}
}

func (m *lockManager) channelLocked(id model.Hash32) chan struct{} {
	channel, ok := m.notify[id]
	if !ok {
		channel = make(chan struct{})
		m.notify[id] = channel
	}
	return channel
}

func (m *lockManager) wakeLocked(id model.Hash32) {
	if channel, ok := m.notify[id]; ok {
		close(channel)
		delete(m.notify, id)
	}
}

func normalizeRange(start, end uint64) (uint64, uint64, bool) {
	if end >= uint64(math.MaxInt64) {
		end = math.MaxUint64
	}
	if end < start {
		return 0, 0, false
	}
	return start, end, true
}

func rangesOverlap(aStart, aEnd, bStart, bEnd uint64) bool {
	return aStart <= bEnd && bStart <= aEnd
}

func typesConflict(a, b uint32) bool {
	if a == syscall.F_UNLCK || b == syscall.F_UNLCK {
		return false
	}
	return a == syscall.F_WRLCK || b == syscall.F_WRLCK
}

func validLockType(typ uint32) bool {
	return typ == syscall.F_RDLCK || typ == syscall.F_WRLCK || typ == syscall.F_UNLCK
}

// removeRangeLocked deletes or trims every lock owned by owner that intersects
// [start, end]. A partially covered lock may split into at most two ranges.
func (m *lockManager) removeRangeLocked(id model.Hash32, owner, start, end uint64) bool {
	list := m.ranges[id]
	if len(list) == 0 {
		return false
	}
	changed := false
	out := make([]byteRangeLock, 0, len(list)+1)
	for _, lock := range list {
		if lock.owner != owner || !rangesOverlap(lock.start, lock.end, start, end) {
			out = append(out, lock)
			continue
		}
		changed = true
		if lock.start < start {
			left := lock
			left.end = start - 1
			out = append(out, left)
		}
		if end < lock.end {
			right := lock
			right.start = end + 1
			out = append(out, right)
		}
	}
	if changed {
		if len(out) == 0 {
			delete(m.ranges, id)
		} else {
			m.ranges[id] = out
		}
	}
	return changed
}

// trySetLocked applies one Setlk request while m.mu is held.
func (m *lockManager) trySetLocked(id model.Hash32, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if !validLockType(lk.Typ) {
		return syscall.EINVAL
	}
	flock := flags&fuse.LK_FLOCK != 0
	if flags & ^uint32(fuse.LK_FLOCK) != 0 {
		return syscall.EINVAL
	}
	if flock {
		if lk.Typ == syscall.F_UNLCK {
			list := m.flocks[id]
			out := list[:0]
			for _, entry := range list {
				if entry.owner != owner {
					out = append(out, entry)
				}
			}
			if len(out) == 0 {
				delete(m.flocks, id)
			} else {
				m.flocks[id] = out
			}
			m.wakeLocked(id)
			return 0
		}
		for _, entry := range m.flocks[id] {
			if entry.owner != owner && typesConflict(entry.typ, lk.Typ) {
				return syscall.EAGAIN
			}
		}
		list := m.flocks[id]
		out := list[:0]
		for _, entry := range list {
			if entry.owner != owner {
				out = append(out, entry)
			}
		}
		out = append(out, flockOwnedLock{owner: owner, pid: lk.Pid, typ: lk.Typ})
		m.flocks[id] = out
		m.wakeLocked(id)
		return 0
	}

	start, end, ok := normalizeRange(lk.Start, lk.End)
	if !ok {
		return syscall.EINVAL
	}
	if lk.Typ == syscall.F_UNLCK {
		if m.removeRangeLocked(id, owner, start, end) {
			m.wakeLocked(id)
		}
		return 0
	}
	for _, lock := range m.ranges[id] {
		if lock.owner == owner {
			continue
		}
		if rangesOverlap(lock.start, lock.end, start, end) && typesConflict(lock.typ, lk.Typ) {
			return syscall.EAGAIN
		}
	}
	m.removeRangeLocked(id, owner, start, end)
	m.ranges[id] = append(m.ranges[id], byteRangeLock{
		owner: owner, pid: lk.Pid, start: start, end: end, typ: lk.Typ,
	})
	m.wakeLocked(id)
	return 0
}

// set applies Setlk when wait is false and Setlkw when wait is true. Waiting
// uses a per-object broadcast channel, so a cancellation (FUSE INTERRUPT) exits
// with EINTR without polling.
func (m *lockManager) set(ctx context.Context, id model.Hash32, owner uint64, lk *fuse.FileLock, flags uint32, wait bool) syscall.Errno {
	for {
		m.mu.Lock()
		errno := m.trySetLocked(id, owner, lk, flags)
		if errno != syscall.EAGAIN || !wait {
			m.mu.Unlock()
			return errno
		}
		channel := m.channelLocked(id)
		m.mu.Unlock()
		if ctx == nil {
			<-channel
			continue
		}
		select {
		case <-ctx.Done():
			return syscall.EINTR
		case <-channel:
		}
	}
}

// get returns a conflicting lock from a different owner, or F_UNLCK.
func (m *lockManager) get(id model.Hash32, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if !validLockType(lk.Typ) || lk.Typ == syscall.F_UNLCK {
		return syscall.EINVAL
	}
	flock := flags&fuse.LK_FLOCK != 0
	if flags & ^uint32(fuse.LK_FLOCK) != 0 {
		return syscall.EINVAL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if flock {
		for _, entry := range m.flocks[id] {
			if entry.owner != owner && typesConflict(entry.typ, lk.Typ) {
				out.Start = 0
				out.End = uint64(math.MaxInt64)
				out.Typ = entry.typ
				out.Pid = entry.pid
				return 0
			}
		}
	} else {
		start, end, ok := normalizeRange(lk.Start, lk.End)
		if !ok {
			return syscall.EINVAL
		}
		for _, lock := range m.ranges[id] {
			if lock.owner == owner {
				continue
			}
			if !rangesOverlap(lock.start, lock.end, start, end) || !typesConflict(lock.typ, lk.Typ) {
				continue
			}
			out.Start = lock.start
			if lock.end == math.MaxUint64 {
				out.End = uint64(math.MaxInt64)
			} else {
				out.End = lock.end
			}
			out.Typ = lock.typ
			out.Pid = lock.pid
			return 0
		}
	}
	out.Start = 0
	out.End = 0
	out.Typ = syscall.F_UNLCK
	out.Pid = 0
	return 0
}

// releaseOwner drops every lock held by one owner. Called from handle Release.
func (m *lockManager) releaseOwner(owner uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, list := range m.ranges {
		out := list[:0]
		for _, lock := range list {
			if lock.owner != owner {
				out = append(out, lock)
			}
		}
		if len(out) == 0 {
			delete(m.ranges, id)
		} else {
			m.ranges[id] = out
		}
		m.wakeLocked(id)
	}
	for id, list := range m.flocks {
		out := list[:0]
		for _, entry := range list {
			if entry.owner != owner {
				out = append(out, entry)
			}
		}
		if len(out) == 0 {
			delete(m.flocks, id)
		} else {
			m.flocks[id] = out
		}
		m.wakeLocked(id)
	}
}

func (m *lockManager) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ranges = make(map[model.Hash32][]byteRangeLock)
	m.flocks = make(map[model.Hash32][]flockOwnedLock)
	for id := range m.notify {
		m.wakeLocked(id)
	}
}
