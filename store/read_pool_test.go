// Read-handle pool tests (subphase R14).
//
// The invariants are the Rust `tests/read_pool.rs` ones, restated for Go:
// handles are reused, the bound is hard, a mutation invalidates the idle set so
// a republished path is never served stale bytes, concurrent readers never mix
// bytes, and pooling never changes an error class. The pool only serves local
// and object planes; remote planes have no descriptors.
package store

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func pooledPlane(t *testing.T, maxIdle int) *flatBlobPlane {
	t.Helper()
	plane, err := newFlatBlobPlaneWithPool(t.TempDir(), PlaneLocal, maxIdle)
	if err != nil {
		t.Fatalf("plane: %v", err)
	}
	if plane.pool == nil {
		t.Fatalf("pool was not created for maxIdle=%d", maxIdle)
	}
	return plane
}

func poolTestID(seed byte) model.Hash32 {
	var id model.Hash32
	id[0] = seed
	return id
}

// TestReadPoolReusesHandles: repeated reads of one blob open the file once.
func TestReadPoolReusesHandles(t *testing.T) {
	plane := pooledPlane(t, 8)
	id := poolTestID(1)
	payload := []byte(strings.Repeat("pooled-", 1024))
	if err := plane.Put(BlobObject, id, payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := plane.Get(BlobObject, id)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("read %d returned %d bytes, want %d", i, len(got), len(payload))
		}
	}
	stats := plane.pool.snapshot()
	if stats.Opens != 1 {
		t.Fatalf("opens = %d, want 1 (reads must reuse the handle)", stats.Opens)
	}
	if stats.Reuses < 49 {
		t.Fatalf("reuses = %d, want >= 49", stats.Reuses)
	}
	if stats.BytesRead != uint64(50*len(payload)) {
		t.Fatalf("bytes_read = %d, want %d", stats.BytesRead, 50*len(payload))
	}
}

// TestReadPoolBoundIsHard: the idle set never exceeds the configured bound.
func TestReadPoolBoundIsHard(t *testing.T) {
	plane := pooledPlane(t, 2)
	for i := byte(1); i <= 6; i++ {
		if err := plane.Put(BlobObject, poolTestID(i), []byte{0x10 + i}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	for i := byte(1); i <= 6; i++ {
		if _, err := plane.Get(BlobObject, poolTestID(i)); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if stats := plane.pool.snapshot(); stats.Idle > 2 {
			t.Fatalf("idle = %d after %d reads, want <= 2", stats.Idle, i)
		}
	}
	stats := plane.pool.snapshot()
	if stats.Evictions == 0 {
		t.Fatalf("evictions = 0, want the bound to have closed handles: %+v", stats)
	}
}

// TestReadPoolMutationInvalidates: a deleted and republished path is never
// served from a handle opened before the change.
func TestReadPoolMutationInvalidates(t *testing.T) {
	plane := pooledPlane(t, 8)
	id := poolTestID(7)
	first := []byte("first-generation")
	if err := plane.Put(BlobObject, id, first); err != nil {
		t.Fatalf("put first: %v", err)
	}
	if got, err := plane.Get(BlobObject, id); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("read first: %v %q", err, got)
	}
	// The handle for `id` is now idle.
	if err := plane.Delete(BlobObject, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	second := []byte("second-generation-with-different-length")
	if err := plane.Put(BlobObject, id, second); err != nil {
		t.Fatalf("put second: %v", err)
	}
	got, err := plane.Get(BlobObject, id)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("read returned %q, want %q (a stale pooled handle was served)", got, second)
	}
	if stats := plane.pool.snapshot(); stats.Invalidations == 0 {
		t.Fatalf("invalidations = 0 after a delete and a put: %+v", stats)
	}
}

// TestReadPoolHandlesDoNotMix: pooled descriptors are per path; interleaved
// reads of two blobs return their own bytes.
func TestReadPoolHandlesDoNotMix(t *testing.T) {
	plane := pooledPlane(t, 4)
	left := bytes.Repeat([]byte("L"), 4096)
	right := bytes.Repeat([]byte("R"), 3000)
	if err := plane.Put(BlobObject, poolTestID(11), left); err != nil {
		t.Fatalf("put left: %v", err)
	}
	if err := plane.Put(BlobObject, poolTestID(12), right); err != nil {
		t.Fatalf("put right: %v", err)
	}
	for i := 0; i < 20; i++ {
		gotLeft, err := plane.Get(BlobObject, poolTestID(11))
		if err != nil || !bytes.Equal(gotLeft, left) {
			t.Fatalf("left read %d: %v (%d bytes)", i, err, len(gotLeft))
		}
		gotRight, err := plane.Get(BlobObject, poolTestID(12))
		if err != nil || !bytes.Equal(gotRight, right) {
			t.Fatalf("right read %d: %v (%d bytes)", i, err, len(gotRight))
		}
	}
}

// TestReadPoolConcurrentReaders exercises the pool under the race detector.
func TestReadPoolConcurrentReaders(t *testing.T) {
	plane := pooledPlane(t, 4)
	payload := bytes.Repeat([]byte("concurrent"), 512)
	if err := plane.Put(BlobObject, poolTestID(21), payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				got, err := plane.Get(BlobObject, poolTestID(21))
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, payload) {
					errs <- werr.Newf(werr.Corrupt, "reader saw %d bytes, want %d", len(got), len(payload))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent read: %v", err)
	}
	if stats := plane.pool.snapshot(); stats.Idle > 4 {
		t.Fatalf("idle = %d, want <= 4", stats.Idle)
	}
}

// TestReadPoolRangeReads: pooled ranged reads are exact and keep the plane's
// error classes.
func TestReadPoolRangeReads(t *testing.T) {
	plane := pooledPlane(t, 4)
	payload := []byte("0123456789abcdefghij")
	if err := plane.Put(BlobObject, poolTestID(31), payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := plane.GetRange(BlobObject, poolTestID(31), 4, 6)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if string(got) != "456789" {
		t.Fatalf("range = %q, want %q", got, "456789")
	}
	// A range past EOF clamps, exactly like the unpooled plane.
	got, err = plane.GetRange(BlobObject, poolTestID(31), 15, 100)
	if err != nil || string(got) != "fghij" {
		t.Fatalf("clamped range = %q err=%v", got, err)
	}
	if _, err := plane.GetRange(BlobObject, poolTestID(31), 99, 1); err == nil {
		t.Fatal("range past EOF was accepted")
	} else if typed, ok := err.(*werr.Error); !ok || typed.Kind != werr.InvalidArgument {
		t.Fatalf("range past EOF class = %v, want InvalidArgument", err)
	}
	// A missing blob keeps NotFound, not Io.
	if _, err := plane.Get(BlobObject, poolTestID(32)); err == nil {
		t.Fatal("missing blob was read")
	} else if typed, ok := err.(*werr.Error); !ok || typed.Kind != werr.NotFound {
		t.Fatalf("missing blob class = %v, want NotFound", err)
	}
	// A zero-length range returns empty bytes without touching the handle twice.
	empty, err := plane.GetRange(BlobObject, poolTestID(31), 20, 5)
	if err != nil || len(empty) != 0 {
		t.Fatalf("range at EOF = %q err=%v", empty, err)
	}
}

// TestReadPoolDisabledByOption: a negative bound is the plain path, and the
// store reports that no pool exists rather than pretending.
func TestReadPoolDisabledByOption(t *testing.T) {
	dir := t.TempDir()
	options := DefaultOptions()
	options.ReadPoolIdle = -1
	writer, err := Init(dir, options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, ok := writer.ReadPoolStats(); ok {
		t.Fatal("ReadPoolStats reported a pool for a disabled configuration")
	}
	if _, err := writer.CreateFile(model.RootID, []byte("plain.txt"), []byte("plain"), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := writer.ResolvePath("/plain.txt")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got, err := writer.ReadObject(id); err != nil || string(got) != "plain" {
		t.Fatalf("read: %v %q", err, got)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestReadPoolReportsThroughTheStore: a default store pools, and the counters
// prove reuse on a repeated read of the same object.
func TestReadPoolReportsThroughTheStore(t *testing.T) {
	dir := t.TempDir()
	writer, err := Init(dir, DefaultOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	payload := bytes.Repeat([]byte("store-pool-"), 2048)
	if _, err := writer.CreateFile(model.RootID, []byte("pooled.bin"), payload, 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := writer.ResolvePath("/pooled.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for i := 0; i < 5; i++ {
		if got, err := writer.ReadObject(id); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("read %d: %v (%d bytes)", i, err, len(got))
		}
	}
	stats, ok := writer.ReadPoolStats()
	if !ok {
		t.Fatal("ReadPoolStats reported no pool for a default store")
	}
	if stats.Backend != string(PlaneLocal) {
		t.Fatalf("backend = %q", stats.Backend)
	}
	if stats.Reuses == 0 {
		t.Fatalf("reuses = 0 after five reads of one object: %+v", stats)
	}
	if stats.MaxIdle != DefaultReadPoolIdle {
		t.Fatalf("max_idle = %d, want %d", stats.MaxIdle, DefaultReadPoolIdle)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Benchmarks compare the pooled and unpooled read paths on the same file, so
// the difference is the descriptor cost the pool removes. They are host-local
// observations (tmpfs, warm page cache), not a performance claim; run them with
// `go test -bench 'ReadBlob' ./store`.
func benchPlane(b *testing.B, maxIdle int) (*flatBlobPlane, model.Hash32) {
	b.Helper()
	plane, err := newFlatBlobPlaneWithPool(b.TempDir(), PlaneLocal, maxIdle)
	if err != nil {
		b.Fatalf("plane: %v", err)
	}
	id := poolTestID(99)
	payload := bytes.Repeat([]byte("benchmark-payload-"), 4096)
	if err := plane.Put(BlobObject, id, payload); err != nil {
		b.Fatalf("put: %v", err)
	}
	b.SetBytes(int64(len(payload)))
	return plane, id
}

func BenchmarkReadBlobUnpooled(b *testing.B) {
	plane, id := benchPlane(b, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := plane.Get(BlobObject, id); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

func BenchmarkReadBlobPooled(b *testing.B) {
	plane, id := benchPlane(b, DefaultReadPoolIdle)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := plane.Get(BlobObject, id); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// TestReadPoolVanishedBlobFailsClosed: a blob deleted behind the store's back
// must not be served from a still-open descriptor. The path is re-checked
// before reuse, so the read fails closed exactly as it did before pooling.
func TestReadPoolVanishedBlobFailsClosed(t *testing.T) {
	plane := pooledPlane(t, 8)
	id := poolTestID(41)
	if err := plane.Put(BlobObject, id, []byte("will-vanish")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := plane.Get(BlobObject, id); err != nil {
		t.Fatalf("first read: %v", err)
	}
	path := plane.path(BlobObject, id)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove behind the plane's back: %v", err)
	}
	if _, err := plane.Get(BlobObject, id); err == nil {
		t.Fatal("a deleted blob was served from a pooled descriptor")
	} else if typed, ok := err.(*werr.Error); !ok || typed.Kind != werr.NotFound {
		t.Fatalf("vanished blob class = %v, want NotFound", err)
	}
	if stats := plane.pool.snapshot(); stats.Refreshes == 0 {
		t.Fatalf("refreshes = 0 after the blob vanished: %+v", stats)
	}
}
