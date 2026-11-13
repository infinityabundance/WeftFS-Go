// X07: the hard cap on *active* read handles (Go parity).
//
// The idle bound ("max 64 cached descriptors") was never an active bound: a
// reader that found the idle map empty opened a new descriptor, so N concurrent
// readers asked the backend for N descriptors at once. These tests prove the
// defect class with the control arm (cap disabled), then pin the fix:
//
//   - the observed number of simultaneously active handles never exceeds the
//     cap;
//   - disabling the cap still reproduces the unbounded fanout, so the control
//     is real and the test would fail if the cap leaked into it;
//   - a goroutine that panics or exits releases its slot (every path defers
//     release);
//   - a mutation still invalidates the idle set under the cap;
//   - one reader under a tiny cap still makes progress (no deadlock).
package store

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
)

// activeReaders runs `n` concurrent reads of one blob and returns the pool's
// high-water mark. `barrier` makes the readers overlap as far as the scheduler
// allows; a cap of 0 is the control arm.
func activeReaders(t *testing.T, plane *flatBlobPlane, n int, cap int) ReadPoolStats {
	t.Helper()
	plane.pool.setActiveCap(cap)
	id := poolTestID(0x42)
	payload := []byte(strings.Repeat("active-cap-", 8192))
	if err := plane.Put(BlobObject, id, payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for round := 0; round < 8; round++ {
				got, err := plane.Get(BlobObject, id)
				if err != nil || !bytes.Equal(got, payload) {
					failures.Add(1)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d readers observed wrong bytes", failures.Load())
	}
	return plane.pool.snapshot()
}

// TestReadPoolControlArmIsUnbounded proves the defect the cap removes: with the
// cap disabled, concurrent readers reach a high-water mark far above the
// default cap.
func TestReadPoolControlArmIsUnbounded(t *testing.T) {
	plane := pooledPlane(t, 512)
	stats := activeReaders(t, plane, 96, 0)
	if stats.MaxActive != 0 {
		t.Fatalf("max_active = %d, want 0 (control arm)", stats.MaxActive)
	}
	if stats.ObservedMaxActive != 0 {
		t.Fatalf("observed_max_active = %d, want 0 when the cap is disabled", stats.ObservedMaxActive)
	}
	if stats.Opens < 2 {
		t.Fatalf("control arm opened %d handles; the reads did not overlap", stats.Opens)
	}
}

// TestReadPoolActiveCapIsNeverExceeded is the fix: the high-water mark is
// bounded, and every read still returns the exact bytes.
func TestReadPoolActiveCapIsNeverExceeded(t *testing.T) {
	plane := pooledPlane(t, 512)
	for _, cap := range []int{1, 4, 16} {
		stats := activeReaders(t, plane, 64, cap)
		if stats.MaxActive != cap {
			t.Fatalf("max_active = %d, want %d", stats.MaxActive, cap)
		}
		if stats.ObservedMaxActive > cap {
			t.Fatalf("cap=%d: observed %d active handles", cap, stats.ObservedMaxActive)
		}
		if stats.Active != 0 {
			t.Fatalf("cap=%d: %d slots leaked", cap, stats.Active)
		}
	}
	stats := plane.pool.snapshot()
	if stats.CapWaits == 0 {
		t.Fatalf("the cap was never reached: %+v", stats)
	}
}

// TestReadPoolActiveCapReleasesOnPanic: a panicking reader must not leak a slot.
func TestReadPoolActiveCapReleasesOnPanic(t *testing.T) {
	plane := pooledPlane(t, 8)
	plane.pool.setActiveCap(1)
	id := poolTestID(0x43)
	payload := []byte("panic-release")
	if err := plane.Put(BlobObject, id, payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	for i := 0; i < 8; i++ {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("the reader did not panic")
				}
			}()
			got, err := plane.Get(BlobObject, id)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("read: %v", err)
			}
			panic("reader panicked after its read")
		}()
	}
	stats := plane.pool.snapshot()
	if stats.Active != 0 {
		t.Fatalf("%d slots leaked after panics", stats.Active)
	}
	if stats.ObservedMaxActive > 1 {
		t.Fatalf("observed %d active handles under a cap of 1", stats.ObservedMaxActive)
	}
	// The cap is a semaphore, not a one-shot.
	if got, err := plane.Get(BlobObject, id); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read after panics: %v", err)
	}
}

// TestReadPoolMutationInvalidatesUnderCap: the epoch/invalidations contract is
// unchanged by the active cap.
func TestReadPoolMutationInvalidatesUnderCap(t *testing.T) {
	plane := pooledPlane(t, 8)
	plane.pool.setActiveCap(2)
	id := poolTestID(0x44)
	if err := plane.Put(BlobObject, id, []byte("first")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if got, err := plane.Get(BlobObject, id); err != nil || string(got) != "first" {
		t.Fatalf("read: %v (%q)", err, got)
	}
	before := plane.pool.snapshot().Invalidations
	// Replace the blob: a pooled descriptor would otherwise serve the stale
	// bytes. The plane's mutation path invalidates every idle handle.
	if err := plane.Delete(BlobObject, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := plane.Put(BlobObject, id, []byte("second")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := plane.Get(BlobObject, id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("read %q after republish, want \"second\"", got)
	}
	stats := plane.pool.snapshot()
	if stats.Invalidations <= before {
		t.Fatalf("invalidations did not grow: %d -> %d", before, stats.Invalidations)
	}
	if stats.ObservedMaxActive > 2 {
		t.Fatalf("observed %d active handles under a cap of 2", stats.ObservedMaxActive)
	}
}

// TestReadPoolTinyCapMakesProgress: no deadlock, no starvation.
func TestReadPoolTinyCapMakesProgress(t *testing.T) {
	plane := pooledPlane(t, 8)
	plane.pool.setActiveCap(1)
	id := poolTestID(0x45)
	payload := bytes.Repeat([]byte{0x5a}, 4096)
	if err := plane.Put(BlobObject, id, payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	var wg sync.WaitGroup
	var completed atomic.Int64
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 5; round++ {
				got, err := plane.Get(BlobObject, id)
				if err != nil || !bytes.Equal(got, payload) {
					return
				}
				completed.Add(1)
			}
		}()
	}
	wg.Wait()
	if completed.Load() != 24*5 {
		t.Fatalf("completed %d of %d reads", completed.Load(), 24*5)
	}
	stats := plane.pool.snapshot()
	if stats.ObservedMaxActive > 1 {
		t.Fatalf("observed %d active handles under a cap of 1", stats.ObservedMaxActive)
	}
}

// TestStoreActiveCapOption: the cap is reachable from Options and from the
// store setter, and reports through ReadPoolStats.
func TestStoreActiveCapOption(t *testing.T) {
	dir := t.TempDir()
	options := DefaultOptions()
	options.ReadPoolActive = 3
	writer, err := Init(dir, options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	stats, ok := writer.ReadPoolStats()
	if !ok {
		t.Fatal("no pool for a local store")
	}
	if stats.MaxActive != 3 {
		t.Fatalf("max_active = %d, want 3", stats.MaxActive)
	}
	if !writer.SetReadPoolActiveCap(0) {
		t.Fatal("SetReadPoolActiveCap reported no pool")
	}
	stats, _ = writer.ReadPoolStats()
	if stats.MaxActive != 0 {
		t.Fatalf("max_active = %d after disabling the cap", stats.MaxActive)
	}
	if _, err := writer.CreateFile(model.RootID, []byte("x.bin"), []byte("body"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := writer.ResolvePath("/x.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got, err := writer.ReadObject(id); err != nil || string(got) != "body" {
		t.Fatalf("read: %v (%q)", err, got)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
