package store_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func packTestOptions() store.PackOptions {
	opts := store.DefaultPackOptions()
	opts.TargetBytes = 64 * 1024
	opts.MemberThresholdBytes = 2048
	opts.CatalogSegments = 4
	opts.MaxCatalogBytes = 4 * (16 + 32 + 113)
	opts.MaxMembersPerPack = 256
	return opts
}

func packedStoreOptions(chunk uint64) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = chunk
	opts.Packing = true
	opts.PackOptions = packTestOptions()
	opts.GCGraceSecs = 0
	return opts
}

type countingBlob struct {
	store.BlobAccess
	gets   atomic.Uint64
	ranges atomic.Uint64
}

func (c *countingBlob) Get(kind store.BlobKind, id model.Hash32) ([]byte, error) {
	c.gets.Add(1)
	return c.BlobAccess.Get(kind, id)
}

func (c *countingBlob) GetRange(kind store.BlobKind, id model.Hash32, offset, length uint64) ([]byte, error) {
	c.ranges.Add(1)
	return c.BlobAccess.GetRange(kind, id, offset, length)
}

func memberID(data []byte) model.Hash32 {
	return hash.Domain("weft/test/member/v1", data)
}

func TestPackedPlaneStoresMembersAndReadsNarrowRanges(t *testing.T) {
	blobDir := t.TempDir()
	commitDir := t.TempDir()
	flat, err := store.OpenFlatBlobPlane(blobDir, store.PlaneLocal)
	if err != nil {
		t.Fatalf("flat plane: %v", err)
	}
	counted := &countingBlob{BlobAccess: flat}
	control, err := store.OpenControlPlane(commitDir, store.PlaneLocal)
	if err != nil {
		t.Fatalf("control plane: %v", err)
	}
	options := packTestOptions()
	options.TargetBytes = 1 << 20
	options.CatalogSegments = 4
	options.MaxCatalogBytes = 1 << 20
	packed, err := store.NewPackedBlobPlane(counted, control, options)
	if err != nil {
		t.Fatalf("packed plane: %v", err)
	}
	members := make(map[model.Hash32][]byte)
	for i := 0; i < 64; i++ {
		data := overlayPattern(1000, byte(i))
		id := memberID(data)
		members[id] = data
		if err := packed.Put(store.BlobObject, id, data); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	// A blob above the member threshold stays flat.
	large := overlayPattern(4096, 200)
	largeID := memberID(large)
	if err := packed.Put(store.BlobObject, largeID, large); err != nil {
		t.Fatalf("put large: %v", err)
	}
	if err := packed.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	for id, want := range members {
		got, err := packed.Get(store.BlobObject, id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("member %s: %v", id.Hex(), err)
		}
	}
	got, err := packed.Get(store.BlobObject, largeID)
	if err != nil || !bytes.Equal(got, large) {
		t.Fatalf("flat member: %v", err)
	}
	// One ranged read of exactly the requested member slice, after the catalog
	// is warm. No whole-pack read is issued.
	var target model.Hash32
	for id := range members {
		target = id
		break
	}
	if _, err := packed.Get(store.BlobObject, target); err != nil {
		t.Fatalf("warm: %v", err)
	}
	counted.gets.Store(0)
	counted.ranges.Store(0)
	part, err := packed.GetRange(store.BlobObject, target, 100, 64)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if !bytes.Equal(part, members[target][100:164]) {
		t.Fatalf("range bytes differ")
	}
	if counted.ranges.Load() != 1 || counted.gets.Load() != 0 {
		t.Fatalf("range read used %d gets and %d range requests, want 0/1",
			counted.gets.Load(), counted.ranges.Load())
	}
	stats, err := packed.PackCatalogStats()
	if err != nil {
		t.Fatalf("catalog stats: %v", err)
	}
	if stats.PackedMembers != uint64(len(members)) || stats.SealedPacks == 0 {
		t.Fatalf("catalog stats = %+v", stats)
	}
	if problems, err := packed.VerifyPacks(); err != nil || len(problems) != 0 {
		t.Fatalf("verify packs: %v %v", problems, err)
	}
}

func TestPackedPlaneFailsClosedOnDigestAndTruncation(t *testing.T) {
	newPlane := func(t *testing.T, dir string) *store.PackedBlobPlane {
		t.Helper()
		options := packTestOptions()
		options.TargetBytes = 1 << 20
		options.MaxCatalogBytes = 1 << 20
		packed, err := store.OpenPackedBlobPlane(dir, dir, options)
		if err != nil {
			t.Fatalf("packed plane: %v", err)
		}
		return packed
	}
	t.Run("digest", func(t *testing.T) {
		dir := t.TempDir()
		packed := newPlane(t, dir)
		data := overlayPattern(700, 3)
		id := memberID(data)
		if err := packed.Put(store.BlobObject, id, data); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := packed.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		packs, err := os.ReadDir(filepath.Join(dir, "packs"))
		if err != nil || len(packs) != 1 {
			t.Fatalf("packs: %v %v", packs, err)
		}
		shard := filepath.Join(dir, "packs", packs[0].Name())
		files, err := os.ReadDir(shard)
		if err != nil || len(files) != 1 {
			t.Fatalf("pack files: %v %v", files, err)
		}
		path := filepath.Join(shard, files[0].Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read pack: %v", err)
		}
		raw[10] ^= 0xFF
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatalf("corrupt pack: %v", err)
		}
		reopened := newPlane(t, dir)
		if _, err := reopened.Get(store.BlobObject, id); err == nil {
			t.Fatal("a corrupted pack member was returned")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		dir := t.TempDir()
		packed := newPlane(t, dir)
		data := overlayPattern(700, 4)
		id := memberID(data)
		if err := packed.Put(store.BlobObject, id, data); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := packed.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		var packPath string
		filepath.WalkDir(filepath.Join(dir, "packs"), func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() {
				packPath = path
			}
			return nil
		})
		if packPath == "" {
			t.Fatal("no pack object found")
		}
		if err := os.Truncate(packPath, 3); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		reopened := newPlane(t, dir)
		if _, err := reopened.Get(store.BlobObject, id); err == nil {
			t.Fatal("a truncated pack member was returned")
		}
	})
}

func TestPackedPlaneMissingCatalogMetadataFailsClosed(t *testing.T) {
	newPlane := func(t *testing.T, dir string, options store.PackOptions) *store.PackedBlobPlane {
		t.Helper()
		packed, err := store.OpenPackedBlobPlane(dir, dir, options)
		if err != nil {
			t.Fatalf("packed plane: %v", err)
		}
		return packed
	}
	t.Run("catalog root", func(t *testing.T) {
		dir := t.TempDir()
		options := packTestOptions()
		options.TargetBytes = 1 << 20
		options.MaxCatalogBytes = 1 << 20
		packed := newPlane(t, dir, options)
		data := overlayPattern(600, 5)
		id := memberID(data)
		if err := packed.Put(store.BlobObject, id, data); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := packed.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if err := os.Remove(filepath.Join(dir, "pack-catalog.root")); err != nil {
			t.Fatalf("remove root: %v", err)
		}
		reopened := newPlane(t, dir, options)
		if _, err := reopened.Get(store.BlobObject, id); err == nil {
			t.Fatal("a member was served without a catalog root")
		}
	})
	t.Run("catalog segment", func(t *testing.T) {
		dir := t.TempDir()
		options := packTestOptions()
		options.TargetBytes = 1 << 20
		options.MaxCatalogBytes = 1 << 20
		packed := newPlane(t, dir, options)
		data := overlayPattern(600, 6)
		id := memberID(data)
		if err := packed.Put(store.BlobObject, id, data); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := packed.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		segments, err := os.ReadDir(filepath.Join(dir, "pack-catalog"))
		if err != nil || len(segments) == 0 {
			t.Fatalf("catalog segments: %v %v", segments, err)
		}
		shard := filepath.Join(dir, "pack-catalog", segments[0].Name())
		files, err := os.ReadDir(shard)
		if err != nil || len(files) == 0 {
			t.Fatalf("catalog files: %v %v", files, err)
		}
		if err := os.Remove(filepath.Join(shard, files[0].Name())); err != nil {
			t.Fatalf("remove segment: %v", err)
		}
		reopened := newPlane(t, dir, options)
		if _, err := reopened.Get(store.BlobObject, id); err == nil {
			t.Fatal("a member was served with a missing catalog segment")
		}
	})
}

func TestPackedStoreRoundTripVerifyReopenAndGC(t *testing.T) {
	dir := t.TempDir()
	opts := packedStoreOptions(4096)
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	payloads := make(map[model.Hash32][]byte)
	for i := 0; i < 8; i++ {
		data := overlayPattern(2500+i*37, byte(10+i))
		id, err := s.CreateFileSeeded(model.RootID, []byte("packed-"+itoaU64(uint64(i))), data, 0o644, 0, 0, nil, []byte("pack-seed-"+itoaU64(uint64(i))))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		payloads[id] = data
	}
	stats, ok := s.PackStats()
	if !ok || stats.SealedPacks == 0 {
		t.Fatalf("no packs were sealed: %+v", stats)
	}
	t.Logf("packs: sealed=%d members=%d bytes=%d catalog_segments=%d",
		stats.SealedPacks, stats.PackedMembers, stats.PackedBytes, stats.CatalogSegmentPublishes)
	for id, want := range payloads {
		got, err := s.ReadObject(id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read %s: %v", id.Hex(), err)
		}
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reader, err := store.OpenWithOptions(dir, store.ReadOnly, opts)
	if err != nil {
		t.Fatalf("reopen packed store: %v", err)
	}
	for id, want := range payloads {
		got, err := reader.ReadObject(id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("reopened read %s: %v", id.Hex(), err)
		}
	}
	if report, err := reader.Verify(true); err != nil || !report.OK {
		t.Fatalf("reopened verify: %v %+v", err, report)
	}
	reader.Close()

	// GC reclaims the packs of a deleted file once every member is gone.
	writer, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("writer open: %v", err)
	}
	defer writer.Close()
	var victimID model.Hash32
	var victimName string
	for i := 0; i < 8; i++ {
		name := "packed-" + itoaU64(uint64(i))
		id, err := writer.ResolvePath("/" + name)
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		victimID, victimName = id, name
		break
	}
	if err := writer.Unlink(model.RootID, []byte(victimName)); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	gc, err := writer.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if gc.ReclaimedPacks.DeletedPacks == 0 && gc.ReclaimedPacks.DeletedCatalogSegments == 0 {
		t.Fatalf("gc reclaimed nothing: %+v", gc.ReclaimedPacks)
	}
	if _, err := writer.ReadObject(victimID); err == nil {
		t.Fatal("the deleted object is still readable")
	}
	// Surviving objects still read exactly.
	for id, want := range payloads {
		if id == victimID {
			continue
		}
		got, err := writer.ReadObject(id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("post-gc read %s: %v", id.Hex(), err)
		}
	}
	if report, err := writer.Verify(true); err != nil || !report.OK {
		t.Fatalf("post-gc verify: %v %+v", err, report)
	}
}

func TestPackedCatalogBoundFallsBackToFlat(t *testing.T) {
	dir := t.TempDir()
	opts := packedStoreOptions(1024)
	opts.PackOptions.MemberThresholdBytes = 512
	opts.PackOptions.TargetBytes = 4096
	opts.PackOptions.MaxCatalogBytes = 4 * (16 + 32 + 113) // five entries
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	payloads := make(map[model.Hash32][]byte)
	for i := 0; i < 12; i++ {
		data := overlayPattern(300+i, byte(40+i))
		id, err := s.CreateFileSeeded(model.RootID, []byte("flat-"+itoaU64(uint64(i))), data, 0o644, 0, 0, nil, []byte("flat-seed-"+itoaU64(uint64(i))))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		payloads[id] = data
	}
	stats, ok := s.PackStats()
	if !ok || stats.FlatMembers == 0 || !stats.PackingDisabled {
		t.Fatalf("catalog bound did not fall back to flat: %+v", stats)
	}
	for id, want := range payloads {
		got, err := s.ReadObject(id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read %s: %v", id.Hex(), err)
		}
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify: %v %+v", err, report)
	}
}

func TestPackedLayoutIsDeterministic(t *testing.T) {
	var layouts [2][]string
	var roots [2][]byte
	for round := 0; round < 2; round++ {
		dir := t.TempDir()
		opts := packedStoreOptions(1024)
		opts.PackOptions.TargetBytes = 8192
		opts.PackOptions.MemberThresholdBytes = 512
		s, err := store.Init(dir, opts)
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		for i := 0; i < 10; i++ {
			data := overlayPattern(400+i*13, byte(60+i))
			if _, err := s.CreateFileSeeded(model.RootID, []byte("det-"+itoaU64(uint64(i))), data, 0o644, 0, 0, nil, []byte("det-seed-"+itoaU64(uint64(i)))); err != nil {
				t.Fatalf("create: %v", err)
			}
		}
		s.Close()
		names := make([]string, 0)
		filepath.WalkDir(filepath.Join(dir, "packs"), func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() {
				rel, _ := filepath.Rel(dir, path)
				names = append(names, filepath.ToSlash(rel))
			}
			return nil
		})
		sort.Strings(names)
		layouts[round] = names
		root, err := os.ReadFile(filepath.Join(dir, "pack-catalog.root"))
		if err != nil {
			t.Fatalf("read catalog root: %v", err)
		}
		roots[round] = root
	}
	if len(layouts[0]) == 0 || len(layouts[0]) != len(layouts[1]) {
		t.Fatalf("pack layouts differ in size: %v vs %v", layouts[0], layouts[1])
	}
	for i := range layouts[0] {
		if layouts[0][i] != layouts[1][i] {
			t.Fatalf("pack layout differs at %d: %s vs %s", i, layouts[0][i], layouts[1][i])
		}
	}
	if !bytes.Equal(roots[0], roots[1]) {
		t.Fatalf("catalog root bytes differ between deterministic rounds")
	}
}

func TestPackedPlaneRejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	inner, err := store.OpenFlatBlobPlane(dir, store.PlaneLocal)
	if err != nil {
		t.Fatalf("flat plane: %v", err)
	}
	control, err := store.OpenControlPlane(dir, store.PlaneLocal)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	options := packTestOptions()
	options.MemberThresholdBytes = 8192
	options.TargetBytes = 4096
	if _, err := store.NewPackedBlobPlane(inner, control, options); err == nil {
		t.Fatal("a member larger than the pack target was accepted")
	}
}

func TestPackedStoreRejectsInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	opts := packedStoreOptions(1024)
	opts.PackOptions.CatalogSegments = 3
	if _, err := store.Init(dir, opts); err == nil {
		t.Fatal("a non-power-of-two catalog segment count was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "FORMAT")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused Init left a FORMAT marker")
	}
}

// TestPackCrashChildProcess is the re-executed child used by the pack crash
// proxy. It is not a test of its own.
func TestPackCrashChildProcess(t *testing.T) {
	dir := os.Getenv("WEFT_PACK_CRASH_STORE")
	if dir == "" {
		t.Skip("pack crash helper process; not run directly")
	}
	opts := packedStoreOptions(4096)
	s, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("child open: %v", err)
	}
	defer s.Close()
	data := overlayPattern(6000, 99)
	if _, err := s.CreateFile(model.RootID, []byte("crash2.bin"), data, 0o644, 0, 0, nil); err != nil {
		t.Fatalf("child create: %v", err)
	}
	t.Fatalf("child survived crash phase %q; the crash hook did not fire", os.Getenv("WEFT_CRASH_PHASE"))
}

func TestPackCrashProxyYieldsOldOrNew(t *testing.T) {
	for _, phase := range []string{"pack_after_pack_object", "pack_after_catalog_segments"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			opts := packedStoreOptions(4096)
			s, err := store.Init(dir, opts)
			if err != nil {
				t.Fatalf("init: %v", err)
			}
			first := overlayPattern(9000, 98)
			firstID, err := s.CreateFileSeeded(model.RootID, []byte("first.bin"), first, 0o644, 0, 0, nil, []byte("pack-crash-first"))
			if err != nil {
				t.Fatalf("first create: %v", err)
			}
			head := s.Head()
			generation := s.Generation()
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestPackCrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_PACK_CRASH_STORE="+dir,
				"WEFT_CRASH_PHASE="+phase,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("child exited cleanly after %s: %s", phase, output)
			}
			reader, err := store.OpenWithOptions(dir, store.ReadOnly, opts)
			if err != nil {
				t.Fatalf("reopen after crash at %s: %v", phase, err)
			}
			defer reader.Close()
			got, err := reader.ReadObject(firstID)
			if err != nil || !bytes.Equal(got, first) {
				t.Fatalf("first object after crash at %s: %v", phase, err)
			}
			if reader.Head() != head || reader.Generation() != generation {
				t.Fatalf("head changed after crash at %s", phase)
			}
			if report, err := reader.Verify(true); err != nil || !report.OK {
				t.Fatalf("verify after crash at %s: %v %+v", phase, err, report)
			}
		})
	}
}
