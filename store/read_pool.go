// Bounded read-handle pool for immutable blobs (subphase R14).
//
// Every chunk read on the local and object planes used to open, read, and close
// one file descriptor. A restore touches thousands of chunks, so that cost is
// paid thousands of times per file and is pure syscall overhead: the bytes are
// content-addressed and immutable, and the hash is still computed after the
// handle is released, so verify-then-trust is unchanged.
//
// This is the Go counterpart of `src/read_pool.rs`. The invariants are the Rust
// court's, plus one the Go fail-closed tests demand:
//
//   - a pooled handle is only used for an immutable blob path;
//   - before an idle handle is reused, the path is re-checked with one `stat`.
//     A vanished file is **not** served from the still-open descriptor: the
//     handle is closed and the read returns `NotFound`, so deleting a chunk
//     behind the store's back is still detected. A path whose size or
//     modification time changed is reopened instead of reused;
//   - the pool holds at most a bounded number of idle handles (default 64) and
//     closes the oldest first;
//   - any mutation of the plane (Put, Delete, DeleteEntry) invalidates every
//     idle handle;
//   - reads never serialise on a global lock: the mutex protects the idle map
//     only, never the I/O;
//   - a missing file is `NotFound`, a short read is `Io`, and pooling never
//     changes an error class.
//
// Remote planes (s3, gcs, azure) have no descriptors and are never pooled.
package store

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

// DefaultReadPoolIdle is the default bound on idle handles, matching the Rust
// `MAX_IDLE_HANDLES`.
const DefaultReadPoolIdle = 64

// ReadPoolStats is diagnostic evidence about the pool, never a correctness
// input.
type ReadPoolStats struct {
	// Backend is the plane the pool belongs to (`local` or `object`).
	Backend string `json:"backend"`
	// MaxIdle is the configured bound.
	MaxIdle int `json:"max_idle"`
	// Idle is the number of handles currently held.
	Idle int `json:"idle"`
	// Opens counts descriptors opened.
	Opens uint64 `json:"opens"`
	// Reuses counts reads served from a validated idle handle.
	Reuses uint64 `json:"reuses"`
	// Refreshes counts idle handles discarded because the path changed or
	// vanished.
	Refreshes uint64 `json:"refreshes"`
	// Evictions counts handles closed because the bound was reached.
	Evictions uint64 `json:"evictions"`
	// Invalidations counts mutation-triggered drops of the idle set.
	Invalidations uint64 `json:"invalidations"`
	// Reads is the number of pooled reads.
	Reads uint64 `json:"reads"`
	// BytesRead is the number of bytes those reads returned.
	BytesRead uint64 `json:"bytes_read"`
}

// pooledHandle is one open descriptor plus the identity of the file it was
// opened on. The identity is what makes reuse safe.
type pooledHandle struct {
	file  *os.File
	size  int64
	mtime time.Time
}

func (h *pooledHandle) matches(info os.FileInfo) bool {
	return info.Size() == h.size && info.ModTime().Equal(h.mtime)
}

type readHandlePool struct {
	kind    PlaneKind
	maxIdle int

	mu            sync.Mutex
	idle          map[string]*pooledHandle
	order         []string
	opens         uint64
	reuses        uint64
	refreshes     uint64
	evictions     uint64
	invalidations uint64
	reads         uint64
	bytesRead     uint64
}

// newReadHandlePool returns a pool, or nil when pooling is disabled. A
// non-positive bound disables it; a disabled pool is never a silent fallback —
// the caller then reads with a plain open, exactly as before.
func newReadHandlePool(kind PlaneKind, maxIdle int) *readHandlePool {
	if maxIdle <= 0 {
		return nil
	}
	if kind != PlaneLocal && kind != PlaneObject {
		return nil
	}
	return &readHandlePool{kind: kind, maxIdle: maxIdle, idle: make(map[string]*pooledHandle, maxIdle)}
}

// acquire returns a handle for `path` whose recorded size is current. A path
// that vanished or changed is never served from an older descriptor.
func (p *readHandlePool) acquire(path string) (*pooledHandle, error) {
	p.mu.Lock()
	existing, cached := p.idle[path]
	if cached {
		delete(p.idle, path)
	}
	p.mu.Unlock()

	if cached {
		info, err := os.Stat(path)
		if err == nil && existing.matches(info) {
			p.mu.Lock()
			p.reuses++
			p.mu.Unlock()
			return existing, nil
		}
		// Vanished or replaced: close the descriptor so the read fails closed
		// (or reopens the new file) instead of returning stale bytes.
		_ = existing.file.Close()
		p.mu.Lock()
		p.refreshes++
		p.mu.Unlock()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
			}
			return nil, werr.Wrap(werr.Io, err, "cannot stat %s", path)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, werr.Wrap(werr.NotFound, err, "blob %s does not exist", path)
		}
		return nil, werr.Wrap(werr.Io, err, "cannot open %s", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, werr.Wrap(werr.Io, err, "cannot stat %s", path)
	}
	p.mu.Lock()
	p.opens++
	p.mu.Unlock()
	return &pooledHandle{file: file, size: info.Size(), mtime: info.ModTime()}, nil
}

// release returns a handle to the idle set, or closes it when the set is full.
// The bound is hard: the oldest idle handle is closed to make room.
func (p *readHandlePool) release(path string, handle *pooledHandle) {
	var closeNow []*pooledHandle
	p.mu.Lock()
	if _, exists := p.idle[path]; !exists && len(p.idle) < p.maxIdle {
		p.idle[path] = handle
		p.order = append(p.order, path)
		handle = nil
	} else {
		for len(p.order) > 0 && len(p.idle) >= p.maxIdle {
			oldest := p.order[0]
			p.order = p.order[1:]
			candidate, ok := p.idle[oldest]
			if !ok {
				continue
			}
			delete(p.idle, oldest)
			closeNow = append(closeNow, candidate)
		}
		if _, exists := p.idle[path]; !exists && len(p.idle) < p.maxIdle {
			p.idle[path] = handle
			p.order = append(p.order, path)
			handle = nil
		}
	}
	if handle != nil {
		// Either the path was already idle (a duplicate handle) or the set is
		// still full: this handle is closed instead of kept.
		closeNow = append(closeNow, handle)
	}
	p.evictions += uint64(len(closeNow))
	p.mu.Unlock()
	for _, discarded := range closeNow {
		_ = discarded.file.Close()
	}
}

// invalidate drops every idle handle. Called on any plane mutation.
func (p *readHandlePool) invalidate() {
	p.mu.Lock()
	handles := make([]*pooledHandle, 0, len(p.idle))
	for path, handle := range p.idle {
		handles = append(handles, handle)
		delete(p.idle, path)
	}
	p.order = p.order[:0]
	p.invalidations++
	p.mu.Unlock()
	for _, handle := range handles {
		_ = handle.file.Close()
	}
}

// closeAll releases every idle handle (store close).
func (p *readHandlePool) closeAll() {
	p.mu.Lock()
	handles := make([]*pooledHandle, 0, len(p.idle))
	for path, handle := range p.idle {
		handles = append(handles, handle)
		delete(p.idle, path)
	}
	p.order = p.order[:0]
	p.mu.Unlock()
	for _, handle := range handles {
		_ = handle.file.Close()
	}
}

// readAll reads a whole blob through the pool. The bytes are copied out of the
// file, so the handle can be released (and reused) before the caller hashes.
func (p *readHandlePool) readAll(path string) ([]byte, error) {
	handle, err := p.acquire(path)
	if err != nil {
		return nil, err
	}
	size := handle.size
	if size < 0 {
		_ = handle.file.Close()
		return nil, werr.Newf(werr.Io, "cannot read %s: negative size", path)
	}
	buf := make([]byte, size)
	if size > 0 {
		n, readErr := handle.file.ReadAt(buf, 0)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			_ = handle.file.Close()
			return nil, werr.Wrap(werr.Io, readErr, "cannot read %s", path)
		}
		if int64(n) != size {
			_ = handle.file.Close()
			return nil, werr.Newf(werr.Io, "short read of %s: %d of %d bytes", path, n, size)
		}
	}
	p.release(path, handle)
	p.mu.Lock()
	p.reads++
	p.bytesRead += uint64(size)
	p.mu.Unlock()
	return buf, nil
}

// readRange reads `length` bytes at `offset` through the pool, clamping to EOF
// exactly like the unpooled plane.
func (p *readHandlePool) readRange(path string, offset, length uint64) ([]byte, error) {
	handle, err := p.acquire(path)
	if err != nil {
		return nil, err
	}
	size := uint64(handle.size)
	if offset > size {
		_ = handle.file.Close()
		return nil, werr.Newf(werr.InvalidArgument,
			"read offset %d is beyond %s (%d bytes)", offset, path, size)
	}
	want := size - offset
	if length < want {
		want = length
	}
	if want == 0 {
		p.release(path, handle)
		p.mu.Lock()
		p.reads++
		p.mu.Unlock()
		return []byte{}, nil
	}
	buf := make([]byte, want)
	n, readErr := handle.file.ReadAt(buf, int64(offset))
	if readErr != nil && uint64(n) < want {
		_ = handle.file.Close()
		return nil, werr.Wrap(werr.Io, readErr, "short ranged read of %s", path)
	}
	p.release(path, handle)
	p.mu.Lock()
	p.reads++
	p.bytesRead += uint64(n)
	p.mu.Unlock()
	return buf[:n], nil
}

func (p *readHandlePool) snapshot() ReadPoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ReadPoolStats{
		Backend:       string(p.kind),
		MaxIdle:       p.maxIdle,
		Idle:          len(p.idle),
		Opens:         p.opens,
		Reuses:        p.reuses,
		Refreshes:     p.refreshes,
		Evictions:     p.evictions,
		Invalidations: p.invalidations,
		Reads:         p.reads,
		BytesRead:     p.bytesRead,
	}
}
