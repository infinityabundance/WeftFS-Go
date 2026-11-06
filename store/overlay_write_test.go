package store_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func overlayOptions(chunk uint64) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = chunk
	opts.Representation = store.RepresentationModeOverlay
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	// GC tests need immediate collection; the production default is an hour.
	opts.GCGraceSecs = 0
	return opts
}

func canonicalOptions(chunk uint64) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = chunk
	opts.Representation = store.RepresentationModeRaw
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	return opts
}

func initOverlayStore(t *testing.T, dir string, opts store.Options) *store.Store {
	t.Helper()
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init overlay store: %v", err)
	}
	return s
}

func overlayPattern(length int, seed byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte((i*31 + int(seed)*17) % 251)
	}
	return out
}

func requireWerr(t *testing.T, err error, kind werr.Kind, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected %s, got nil", what, kind)
	}
	typed, ok := err.(*werr.Error)
	if !ok || typed.Kind != kind {
		t.Fatalf("%s: expected %s, got %v", what, kind, err)
	}
}

// manifestOf returns the manifest of the object's current content.
func manifestOf(t *testing.T, s *store.Store, id model.Hash32) model.Manifest {
	t.Helper()
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("object meta: %v", err)
	}
	manifest, err := store.ReadManifest(s.Root(), record.Content)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	return manifest
}

// assertExactRoot compares the overlay object's bytes and Merkle root against a
// freshly written canonical v3 file with the same logical bytes.
func assertExactRoot(t *testing.T, s *store.Store, id model.Hash32, expected []byte) {
	t.Helper()
	got, err := s.ReadObject(id)
	if err != nil {
		t.Fatalf("read overlay object: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("overlay bytes differ: got %d bytes, want %d", len(got), len(expected))
	}
	manifest := manifestOf(t, s, id)
	canonicalRoot := model.MerkleRootChunks(chunkRefs(t, expected, manifest.ChunkSize))
	if manifest.ContentHash != canonicalRoot {
		t.Fatalf("overlay content root %s != canonical v3 root %s",
			manifest.ContentHash.Hex(), canonicalRoot.Hex())
	}
	if manifest.Size != uint64(len(expected)) {
		t.Fatalf("manifest size = %d, want %d", manifest.Size, len(expected))
	}
}

func chunkRefs(t *testing.T, data []byte, chunkSize uint64) []model.ChunkRef {
	t.Helper()
	refs := make([]model.ChunkRef, 0)
	for start := uint64(0); start < uint64(len(data)); start += chunkSize {
		end := start + chunkSize
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		refs = append(refs, model.ChunkRef{Hash: model.ContentHash(data[start:end]), Len: end - start})
	}
	return refs
}

func TestOverlayAlignedAndMisalignedWritesAreExact(t *testing.T) {
	const chunk = 4096
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(int(chunk*8), 1)
	id, err := s.CreateFile(model.RootID, []byte("overlay.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The base is an ordinary v3 table, not an overlay layer.
	if manifest := manifestOf(t, s, id); manifest.Representation != nil {
		t.Fatalf("create with overlay policy produced a representation: %+v", manifest.Representation)
	}
	expected := append([]byte(nil), base...)

	// Aligned write inside the first chunk.
	if _, err := s.WriteFile(id, 0, []byte("AAAA")); err != nil {
		t.Fatalf("aligned write: %v", err)
	}
	copy(expected[0:4], []byte("AAAA"))
	assertExactRoot(t, s, id, expected)

	// Misaligned write straddling a chunk boundary.
	if _, err := s.WriteFile(id, chunk-3, []byte("0123456789")); err != nil {
		t.Fatalf("misaligned write: %v", err)
	}
	copy(expected[chunk-3:chunk+7], []byte("0123456789"))
	assertExactRoot(t, s, id, expected)

	// A write that starts past EOF zero-fills the gap.
	if _, err := s.WriteFile(id, uint64(len(expected))+chunk/2, []byte("tail")); err != nil {
		t.Fatalf("sparse write: %v", err)
	}
	expected = append(expected, make([]byte, chunk/2)...)
	expected = append(expected, []byte("tail")...)
	assertExactRoot(t, s, id, expected)

	manifest := manifestOf(t, s, id)
	if manifest.Representation == nil || manifest.Representation.Kind != model.RepresentationOverlay {
		t.Fatalf("expected an overlay representation, got %+v", manifest.Representation)
	}
	if manifest.Representation.Overlay.Depth != 1 {
		t.Fatalf("adjacent writes should fold into one layer, depth = %d", manifest.Representation.Overlay.Depth)
	}
}

func TestOverlayOverlappingRangesAreLastWriterWins(t *testing.T) {
	const chunk = 4096
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 2)
	id, err := s.CreateFile(model.RootID, []byte("overlap.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expected := append([]byte(nil), base...)
	ranges := []store.RangeWrite{
		{Offset: 100, Data: []byte("first")},
		{Offset: 102, Data: []byte("SECOND")},
		{Offset: 200, Data: []byte("third")},
	}
	for _, r := range ranges {
		copy(expected[r.Offset:], r.Data)
	}
	if _, err := s.WriteFileRanges(id, ranges); err != nil {
		t.Fatalf("range write: %v", err)
	}
	assertExactRoot(t, s, id, expected)
}

func TestOverlayAdjacentWritesCoalesce(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(8*chunk, 3)
	id, err := s.CreateFile(model.RootID, []byte("coalesce.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expected := append([]byte(nil), base...)
	for i := 0; i < 8; i++ {
		offset := uint64(i * 64)
		payload := []byte{byte('a' + i)}
		if _, err := s.WriteFile(id, offset, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		copy(expected[offset:], payload)
	}
	assertExactRoot(t, s, id, expected)
	overlay := manifestOf(t, s, id).Representation.Overlay
	if overlay.Depth != 1 {
		t.Fatalf("adjacent writes grew the chain to depth %d", overlay.Depth)
	}
	if len(overlay.Extents) != 1 {
		t.Fatalf("adjacent writes produced %d extents, want 1", len(overlay.Extents))
	}
}

func TestOverlayAppendAndTruncateGrowExactLayers(t *testing.T) {
	const chunk = 4096
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(3*chunk+17, 4)
	id, err := s.CreateFile(model.RootID, []byte("append.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expected := append([]byte(nil), base...)
	appended := []byte("appended-bytes")
	if _, err := s.WriteFile(id, uint64(len(expected)), appended); err != nil {
		t.Fatalf("append: %v", err)
	}
	expected = append(expected, appended...)
	assertExactRoot(t, s, id, expected)

	grown := uint64(len(expected)) + 2*chunk + 3
	if _, err := s.Truncate(id, grown); err != nil {
		t.Fatalf("grow truncate: %v", err)
	}
	expected = append(expected, make([]byte, grown-uint64(len(expected)))...)
	assertExactRoot(t, s, id, expected)

	if _, err := s.Truncate(id, grown); err != nil {
		t.Fatalf("same-size truncate: %v", err)
	}
	if _, err := s.Truncate(id, grown-1); err == nil {
		t.Fatal("shrinking truncate was accepted on an overlay object")
	}
}

func TestOverlayZeroRangePublishesALayer(t *testing.T) {
	const chunk = 2048
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 5)
	id, err := s.CreateFile(model.RootID, []byte("zero.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.ZeroRange(id, 100, 300, false); err != nil {
		t.Fatalf("zero range: %v", err)
	}
	expected := append([]byte(nil), base...)
	clear(expected[100:400])
	assertExactRoot(t, s, id, expected)

	// Extending zero range grows the file.
	grown := uint64(len(expected)) + chunk
	if _, err := s.ZeroRange(id, uint64(len(expected)), chunk, true); err != nil {
		t.Fatalf("extending zero range: %v", err)
	}
	expected = append(expected, make([]byte, chunk)...)
	assertExactRoot(t, s, id, expected)
	if got := uint64(len(expected)); got != grown {
		t.Fatalf("grown size = %d, want %d", got, grown)
	}
}

func TestOverlayRefusesCollapseInsertAndShrink(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 6)
	id, err := s.CreateFile(model.RootID, []byte("refuse.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 0, []byte("x")); err != nil {
		t.Fatalf("seed overlay: %v", err)
	}
	if _, err := s.CollapseRange(id, 0, 10); err == nil {
		t.Fatal("collapse_range on an overlay was accepted")
	}
	if _, err := s.InsertRange(id, 0, 10); err == nil {
		t.Fatal("insert_range on an overlay was accepted")
	}
	if _, err := s.Truncate(id, 10); err == nil {
		t.Fatal("shrinking truncate on an overlay was accepted")
	}
}

func TestOverlayExtentLimitPublishesANewLayer(t *testing.T) {
	const chunk = 512
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	// One chunk used, one skipped, so writes stay disjoint; 65 disjoint writes
	// force the 64-extent per-manifest bound.
	const writes = model.MaxOverlayExtentsPerManifest + 1
	size := uint64(writes) * 2 * chunk
	base := make([]byte, size)
	id, err := s.CreateFile(model.RootID, []byte("extents.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expected := append([]byte(nil), base...)
	for i := uint64(0); i < writes; i++ {
		offset := i * 2 * chunk
		payload := []byte{byte(i%251) + 1}
		if _, err := s.WriteFile(id, offset, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		copy(expected[offset:], payload)
	}
	assertExactRoot(t, s, id, expected)
	overlay := manifestOf(t, s, id).Representation.Overlay
	if overlay.Depth != 2 {
		t.Fatalf("65 disjoint writes should publish depth 2, got %d", overlay.Depth)
	}
	if len(overlay.Extents) > model.MaxOverlayExtentsPerManifest {
		t.Fatalf("manifest lists %d extents", len(overlay.Extents))
	}
}

func TestOverlayWriterBoundsRefuseAndNameCompaction(t *testing.T) {
	const chunk = 512
	t.Run("depth", func(t *testing.T) {
		dir := t.TempDir()
		opts := overlayOptions(chunk)
		opts.MaxOverlayDepth = 1
		s, err := store.Init(dir, opts)
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		defer s.Close()
		const writes = model.MaxOverlayExtentsPerManifest + 1
		base := make([]byte, uint64(writes)*2*chunk)
		id, err := s.CreateFile(model.RootID, []byte("depth.bin"), base, 0o644, 0, 0, nil)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		for i := uint64(0); i < writes-1; i++ {
			if _, err := s.WriteFile(id, i*2*chunk, []byte{byte(i%251) + 1}); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		// The next disjoint write cannot fold into the layer and would need
		// depth 2, above the configured bound.
		_, err = s.WriteFile(id, (writes-1)*2*chunk, []byte{7})
		requireWerr(t, err, werr.LimitExceeded, "depth bound")
	})
	t.Run("bytes", func(t *testing.T) {
		dir := t.TempDir()
		opts := overlayOptions(chunk)
		opts.MaxOverlayBytes = chunk
		s, err := store.Init(dir, opts)
		if err != nil {
			t.Fatalf("init: %v", err)
		}
		defer s.Close()
		base := make([]byte, 8*chunk)
		id, err := s.CreateFile(model.RootID, []byte("bytes.bin"), base, 0o644, 0, 0, nil)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		payload := bytes.Repeat([]byte{0x5A}, int(2*chunk))
		_, err = s.WriteFile(id, 0, payload)
		requireWerr(t, err, werr.LimitExceeded, "byte bound")
	})
}

func TestOverlayIdenticalRewritePublishesNothing(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 7)
	id, err := s.CreateFile(model.RootID, []byte("same.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	version, err := s.WriteFile(id, 0, base[:16])
	if err != nil {
		t.Fatalf("write identical bytes: %v", err)
	}
	after, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if version != before.Version || after.Version != before.Version || after.Content != before.Content {
		t.Fatalf("identical rewrite published a new version: %s -> %s", before.Version.Hex(), version.Hex())
	}
	if after.Size != before.Size {
		t.Fatalf("identical rewrite changed the size")
	}
}

func TestOverlaySnapshotRetainsEveryLayer(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 8)
	id, err := s.CreateFile(model.RootID, []byte("snap.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	first, err := s.WriteFile(id, 0, []byte("layer-one"))
	if err != nil {
		t.Fatalf("first layer: %v", err)
	}
	if _, err := s.SnapshotCreate("before-second"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	expected := append([]byte(nil), base...)
	copy(expected, []byte("layer-one"))
	second, err := s.WriteFile(id, 2*chunk, []byte("layer-two"))
	if err != nil {
		t.Fatalf("second layer: %v", err)
	}
	copy(expected[2*chunk:], []byte("layer-two"))

	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc: %v", err)
	}
	// The live version reads exactly.
	got, err := s.ReadObject(id)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("live overlay read after gc: %v", err)
	}
	// The snapshot pinned between the layers reads its own version.
	snapshotCommit, err := s.LookupSnapshot("before-second")
	if err != nil {
		t.Fatalf("lookup snapshot: %v", err)
	}
	snapshotState, err := s.StateAt(snapshotCommit)
	if err != nil {
		t.Fatalf("state at snapshot: %v", err)
	}
	snapshotRecord, ok := snapshotState.Objects[id]
	if !ok {
		t.Fatalf("snapshot has no object record")
	}
	if snapshotRecord.Version == second && snapshotRecord.Version != first {
		t.Fatalf("snapshot version is not the first layer's version")
	}
	snapshotBytes, err := s.ReadObjectAt(&snapshotCommit, id)
	if err != nil {
		t.Fatalf("snapshot read: %v", err)
	}
	want := append([]byte(nil), base...)
	copy(want, []byte("layer-one"))
	if !bytes.Equal(snapshotBytes, want) {
		t.Fatalf("snapshot bytes changed after later overlay + gc")
	}
	// The current manifest still resolves.
	if _, err := store.ReadManifest(dir, manifestOf(t, s, id).Representation.Overlay.Base); err != nil {
		t.Fatalf("base chain missing after gc: %v", err)
	}
}

func TestOverlayGCCollectsAnUnreferencedLayer(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 9)
	id, err := s.CreateFile(model.RootID, []byte("gc.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 0, []byte("doomed")); err != nil {
		t.Fatalf("layer: %v", err)
	}
	doomedManifest := manifestOf(t, s, id)
	doomedID := doomedManifest.Representation.Overlay.Base
	if _, err := s.WriteFile(id, chunk, []byte("newer")); err != nil {
		t.Fatalf("second layer: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc: %v", err)
	}
	// The first overlay manifest is no longer named by any live head and its
	// own base is still referenced; but the *base* manifest stays because the
	// second layer names the first layer's base... actually the second layer
	// folds and names `doomedID`? It names the same base, so only the first
	// layer's manifest itself becomes unreferenced.
	path := store.ManifestPath(dir, mustManifestID(t, doomedManifest))
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("unreferenced overlay manifest %s survived gc", path)
	}
	if _, err := store.ReadManifest(dir, doomedID); err != nil {
		t.Fatalf("base manifest was collected: %v", err)
	}
}

func mustManifestID(t *testing.T, manifest model.Manifest) model.Hash32 {
	t.Helper()
	id, err := manifest.ID()
	if err != nil {
		t.Fatalf("manifest id: %v", err)
	}
	return id
}

// TestOverlayCrashChildProcess is the re-executed child used by the compaction
// crash proxy. It is not a test of its own.
func TestOverlayCrashChildProcess(t *testing.T) {
	dir := os.Getenv("WEFT_OVERLAY_CRASH_STORE")
	if dir == "" {
		t.Skip("overlay crash helper process; not run directly")
	}
	phase := os.Getenv("WEFT_CRASH_PHASE")
	if phase == "" {
		t.Fatal("WEFT_OVERLAY_CRASH_STORE set without WEFT_CRASH_PHASE")
	}
	opts := overlayOptions(1024)
	s, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("child open: %v", err)
	}
	defer s.Close()
	id, err := s.ResolvePath("/crash.bin")
	if err != nil {
		t.Fatalf("child resolve: %v", err)
	}
	if _, err := s.Compact(id); err != nil {
		t.Fatalf("child compact: %v", err)
	}
	t.Fatalf("child survived crash phase %q; the crash hook did not fire", phase)
}

func TestOverlayCompactionCrashProxyYieldsOldOrNew(t *testing.T) {
	const chunk = 1024
	for _, phase := range []string{"after_objects", "after_commit_file", "after_superblock_write"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			s := initOverlayStore(t, dir, overlayOptions(chunk))
			base := overlayPattern(4*chunk, 10)
			id, err := s.CreateFile(model.RootID, []byte("crash.bin"), base, 0o644, 0, 0, nil)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			expected := append([]byte(nil), base...)
			copy(expected, []byte("edited"))
			if _, err := s.WriteFile(id, 0, []byte("edited")); err != nil {
				t.Fatalf("layer: %v", err)
			}
			generation := s.Generation()
			head := s.Head()
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=TestOverlayCrashChildProcess")
			cmd.Env = append(os.Environ(),
				"WEFT_OVERLAY_CRASH_STORE="+dir,
				"WEFT_CRASH_PHASE="+phase,
			)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("child exited cleanly after %s: %s", phase, output)
			}

			reader, err := store.Open(dir, store.ReadOnly)
			if err != nil {
				t.Fatalf("reopen after crash at %s: %v", phase, err)
			}
			defer reader.Close()
			got, err := reader.ReadObject(id)
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatalf("bytes after crash at %s: %v", phase, err)
			}
			manifest := manifestOf(t, reader, id)
			compacted := manifest.Representation == nil
			if phase == "after_superblock_write" && !compacted {
				t.Fatalf("compaction was published before the superblock slot")
			}
			if phase != "after_superblock_write" {
				if compacted {
					t.Fatalf("compaction became visible after a crash at %s", phase)
				}
				if reader.Generation() != generation || reader.Head() != head {
					t.Fatalf("head changed after crash at %s", phase)
				}
			}
		})
	}
}

func TestCompactRefusesNonOverlayObject(t *testing.T) {
	dir := t.TempDir()
	opts := canonicalOptions(1024)
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	id, err := s.CreateFile(model.RootID, []byte("plain.bin"), overlayPattern(2048, 11), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Compact(id); err == nil {
		t.Fatal("compact accepted a non-overlay object")
	}
}

func TestCompactPreservesTheRootAndSnapshot(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(6*chunk, 12)
	id, err := s.CreateFile(model.RootID, []byte("compact.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expected := append([]byte(nil), base...)
	for i, payload := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		offset := uint64(i * 100)
		if _, err := s.WriteFile(id, offset, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		copy(expected[offset:], payload)
	}
	if _, err := s.SnapshotCreate("before-compact"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	before := manifestOf(t, s, id)
	report, err := s.Compact(id)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if report.ContentRoot != before.ContentHash {
		t.Fatalf("compaction changed the content root")
	}
	after := manifestOf(t, s, id)
	if after.Representation != nil {
		t.Fatalf("compacted manifest still has a representation: %+v", after.Representation)
	}
	if after.ContentHash != before.ContentHash || after.Size != before.Size {
		t.Fatalf("compacted manifest changed the logical content")
	}
	got, err := s.ReadObject(id)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("read after compaction: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc: %v", err)
	}
	snapshot, err := s.LookupSnapshot("before-compact")
	if err != nil {
		t.Fatalf("lookup snapshot: %v", err)
	}
	snapshotBytes, err := s.ReadObjectAt(&snapshot, id)
	if err != nil || !bytes.Equal(snapshotBytes, expected) {
		t.Fatalf("snapshot after compaction + gc: %v", err)
	}
	// Compaction clears the writer bounds.
	afterCompact := manifestOf(t, s, id)
	_ = afterCompact
	if _, err := s.WriteFile(id, chunk*2, []byte("post-compact")); err != nil {
		t.Fatalf("write after compaction: %v", err)
	}
	if manifestOf(t, s, id).Representation == nil {
		t.Fatalf("write after compaction did not publish an overlay layer")
	}
}

func TestCompactDetectsChunkCorruptionBeforePublication(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()

	base := overlayPattern(4*chunk, 13)
	id, err := s.CreateFile(model.RootID, []byte("corrupt.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 0, []byte("layer")); err != nil {
		t.Fatalf("layer: %v", err)
	}
	manifest := manifestOf(t, s, id)
	table := manifest.Representation.Overlay.Extents[0].Chunks
	// Corrupt one chunk blob this manifest names.
	path := store.ObjectPath(dir, table[0].Hash)
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xEE}, int(table[0].Len)), 0o644); err != nil {
		t.Fatalf("corrupt chunk: %v", err)
	}
	headBefore := s.Head()
	if _, err := s.Compact(id); err == nil {
		t.Fatal("compact accepted a corrupted chunk")
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	if reader.Head() != headBefore {
		t.Fatalf("a failed compaction published a commit")
	}
}

func TestOverlayDirectoryHasNoStrayTemporaryFiles(t *testing.T) {
	const chunk = 1024
	dir := t.TempDir()
	s := initOverlayStore(t, dir, overlayOptions(chunk))
	defer s.Close()
	id, err := s.CreateFile(model.RootID, []byte("clean.bin"), overlayPattern(4*chunk, 14), 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 0, []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "tmp"))
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("tmp contains %d stale entries", len(entries))
	}
}
