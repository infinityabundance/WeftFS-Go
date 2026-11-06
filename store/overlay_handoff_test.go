package store_test

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// The committed fixture is produced by the Rust example
// examples/gen_overlay_fixture.rs (there is no v4 write path yet). Go reads the
// same store bytes and must reproduce every object exactly and fail closed on
// broken chains.

type overlayFixtureObject struct {
	Path        string `json:"path"`
	Size        uint64 `json:"size"`
	ContentRoot string `json:"content_root"`
	ExpectedHex string `json:"expected_hex"`
}

type overlayFixture struct {
	Format          string                 `json:"format"`
	ChunkSize       uint64                 `json:"chunk_size"`
	BaseManifest    string                 `json:"base_manifest"`
	OverlayManifest string                 `json:"overlay_manifest"`
	NestedManifest  string                 `json:"nested_manifest"`
	Objects         []overlayFixtureObject `json:"objects"`
	BaseChunks      []string               `json:"base_chunks"`
	OverlayChunks   []string               `json:"overlay_chunks"`
	NestedChunks    []string               `json:"nested_chunks"`
}

func overlayFixtureDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("conformance", "overlay", "v1"),
		filepath.Join("..", "conformance", "overlay", "v1"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(filepath.Join(candidate, "EXPECTED.json")); err == nil && !info.IsDir() {
			return candidate
		}
	}
	t.Skip("committed overlay fixture not found; generate it with " +
		"cargo run --release --example gen_overlay_fixture -- <dir>")
	return ""
}

func copyOverlayTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
}

func loadOverlayFixture(t *testing.T, dir string) (overlayFixture, []byte) {
	t.Helper()
	var fixture overlayFixture
	raw, err := os.ReadFile(filepath.Join(dir, "EXPECTED.json"))
	if err != nil {
		t.Fatalf("read EXPECTED.json: %v", err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse EXPECTED.json: %v", err)
	}
	if fixture.Format != "weftfs-overlay-fixture-v1" {
		t.Fatalf("fixture format = %q", fixture.Format)
	}
	return fixture, raw
}

func mustOverlayHash(t *testing.T, text string) model.Hash32 {
	t.Helper()
	id, err := hash.FromHex(text)
	if err != nil {
		t.Fatalf("bad hash %q: %v", text, err)
	}
	return id
}

func overlayExpectedByPath(t *testing.T, fixture overlayFixture, path string) []byte {
	t.Helper()
	for _, object := range fixture.Objects {
		if object.Path == path {
			bytesValue, err := hex.DecodeString(object.ExpectedHex)
			if err != nil {
				t.Fatalf("decode expected %s: %v", path, err)
			}
			return bytesValue
		}
	}
	t.Fatalf("fixture has no object %s", path)
	return nil
}

func TestOverlayHandoffRustFixtureGoReads(t *testing.T) {
	src := overlayFixtureDir(t)
	fixture, _ := loadOverlayFixture(t, src)
	dir := t.TempDir()
	copyOverlayTree(t, src, dir)

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open rust overlay fixture: %v", err)
	}
	defer s.Close()

	objects := map[string]model.Hash32{}
	for _, object := range fixture.Objects {
		id, err := s.ResolvePath(object.Path)
		if err != nil {
			t.Fatalf("resolve %s: %v", object.Path, err)
		}
		objects[object.Path] = id
		record, err := s.ObjectMeta(id)
		if err != nil {
			t.Fatalf("meta %s: %v", object.Path, err)
		}
		if got := record.Content.Hex(); got != object.ContentRoot {
			t.Fatalf("%s content root = %s, want %s", object.Path, got, object.ContentRoot)
		}
		if record.Size != object.Size {
			t.Fatalf("%s size = %d, want %d", object.Path, record.Size, object.Size)
		}
		got, err := s.ReadObject(id)
		if err != nil {
			t.Fatalf("read %s: %v", object.Path, err)
		}
		want, err := hex.DecodeString(object.ExpectedHex)
		if err != nil {
			t.Fatalf("decode expected %s: %v", object.Path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s bytes = %x, want %x", object.Path, got, want)
		}
	}

	baseID := mustOverlayHash(t, fixture.BaseManifest)
	overlayID := mustOverlayHash(t, fixture.OverlayManifest)
	nestedID := mustOverlayHash(t, fixture.NestedManifest)
	base, err := store.ReadManifest(dir, baseID)
	if err != nil {
		t.Fatalf("read base manifest: %v", err)
	}
	overlay, err := store.ReadManifest(dir, overlayID)
	if err != nil {
		t.Fatalf("read overlay manifest: %v", err)
	}
	nested, err := store.ReadManifest(dir, nestedID)
	if err != nil {
		t.Fatalf("read nested manifest: %v", err)
	}
	if base.Representation != nil {
		t.Fatalf("base is not raw v3: %+v", base.Representation)
	}
	for _, tc := range []struct {
		manifest model.Manifest
		depth    uint64
	}{
		{overlay, 1},
		{nested, 2},
	} {
		if tc.manifest.Representation == nil || tc.manifest.Representation.Kind != model.RepresentationOverlay {
			t.Fatalf("manifest representation = %+v", tc.manifest.Representation)
		}
		if tc.manifest.Representation.Overlay == nil ||
			tc.manifest.Representation.Overlay.Depth != tc.depth {
			t.Fatalf("overlay depth = %+v, want %d", tc.manifest.Representation.Overlay, tc.depth)
		}
	}
	if got := overlay.Representation.Overlay.Base; got != baseID {
		t.Fatalf("overlay base = %s, want %s", got.Hex(), baseID.Hex())
	}
	if got := nested.Representation.Overlay.Base; got != overlayID {
		t.Fatalf("nested base = %s, want %s", got.Hex(), overlayID.Hex())
	}

	report, err := s.Verify(false)
	if err != nil {
		t.Fatalf("verify shallow: %v", err)
	}
	if !report.OK {
		t.Fatalf("shallow verify problems: %+v", report.Problems)
	}
	report, err = s.Verify(true)
	if err != nil {
		t.Fatalf("verify full: %v", err)
	}
	if !report.OK {
		t.Fatalf("full verify problems: %+v", report.Problems)
	}
	if report.CheckedRepresentations < 2 {
		t.Fatalf("checked representations = %d, want at least 2", report.CheckedRepresentations)
	}

	nestedObject := objects["/nested"]
	var wantNested []byte
	for _, object := range fixture.Objects {
		if object.Path == "/nested" {
			wantNested, err = hex.DecodeString(object.ExpectedHex)
			if err != nil {
				t.Fatalf("decode nested: %v", err)
			}
		}
	}
	if len(wantNested) != 32 {
		t.Fatalf("nested expected bytes = %d", len(wantNested))
	}
	got, err := s.ReadRange(nestedObject, 24, 8)
	if err != nil {
		t.Fatalf("nested range: %v", err)
	}
	if string(got) != string(wantNested[24:32]) {
		t.Fatalf("nested range = %x, want %x", got, wantNested[24:32])
	}
}

// A range read must not require chunks outside the requested range. Removing a
// non-intersecting chunk keeps the range readable; removing the intersecting
// chunk makes it fail closed.
func TestOverlayRangeReadsOnlyIntersectingChunks(t *testing.T) {
	src := overlayFixtureDir(t)
	fixture, _ := loadOverlayFixture(t, src)
	dir := t.TempDir()
	copyOverlayTree(t, src, dir)

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open fixture copy: %v", err)
	}
	defer s.Close()
	nested, err := s.ResolvePath("/nested")
	if err != nil {
		t.Fatalf("resolve /nested: %v", err)
	}

	// Chunk 0 covers [0,8); it is not needed for [24,32).
	removeBlob := func(hexText string) {
		id := mustOverlayHash(t, hexText)
		if err := os.Remove(store.BlobPath(dir, store.BlobObject, id)); err != nil {
			t.Fatalf("remove chunk %s: %v", hexText, err)
		}
	}
	removeBlob(fixture.NestedChunks[0])
	if _, err := s.ReadRange(nested, 24, 8); err != nil {
		t.Fatalf("range [24,32) needed a non-intersecting chunk: %v", err)
	}
	removeBlob(fixture.NestedChunks[3])
	if _, err := s.ReadRange(nested, 24, 8); err == nil {
		t.Fatalf("range [24,32) succeeded with its chunk missing")
	}
}

func TestOverlayGCRetainsBaseChainAndCollectsUnreferencedChunks(t *testing.T) {
	src := overlayFixtureDir(t)
	fixture, _ := loadOverlayFixture(t, src)
	dir := t.TempDir()
	copyOverlayTree(t, src, dir)

	opts := store.DefaultOptions()
	opts.GCGraceSecs = 0
	s, err := store.OpenWithOptions(dir, store.ReadWrite, opts)
	if err != nil {
		t.Fatalf("open writable fixture: %v", err)
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}

	baseID := mustOverlayHash(t, fixture.BaseManifest)
	overlayID := mustOverlayHash(t, fixture.OverlayManifest)
	nestedID := mustOverlayHash(t, fixture.NestedManifest)
	exists := func(kind store.BlobKind, hexText string) bool {
		info, err := os.Stat(store.BlobPath(dir, kind, mustOverlayHash(t, hexText)))
		return err == nil && !info.IsDir()
	}
	manifestExists := func(id model.Hash32) bool {
		info, err := os.Stat(store.BlobPath(dir, store.BlobManifest, id))
		return err == nil && !info.IsDir()
	}

	// An unreferenced chunk must be collected.
	dead := hash.Domain(model.DomainChunk, []byte("unreferenced overlay chunk"))
	deadPath := store.BlobPath(dir, store.BlobObject, dead)
	if err := os.MkdirAll(filepath.Dir(deadPath), 0o755); err != nil {
		t.Fatalf("mkdir dead chunk: %v", err)
	}
	if err := os.WriteFile(deadPath, []byte("unreferenced overlay chunk"), 0o644); err != nil {
		t.Fatalf("write dead chunk: %v", err)
	}

	// /base is not needed as an object once /overlay exists, but its manifest
	// and chunks are still referenced through the overlay base chain.
	if err := s.Unlink(root, []byte("base")); err != nil {
		t.Fatalf("unlink /base: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc 1: %v", err)
	}
	if !manifestExists(baseID) || !manifestExists(overlayID) || !manifestExists(nestedID) {
		t.Fatalf("GC deleted a live overlay/base manifest")
	}
	for _, chunk := range append(append([]string{}, fixture.BaseChunks...), fixture.NestedChunks...) {
		if !exists(store.BlobObject, chunk) {
			t.Fatalf("GC deleted live chunk %s", chunk)
		}
	}
	if _, err := os.Stat(deadPath); err == nil {
		t.Fatalf("GC retained an unreferenced chunk")
	}
	overlayObject, err := s.ResolvePath("/nested")
	if err != nil {
		t.Fatalf("resolve /nested after gc: %v", err)
	}
	got, err := s.ReadObject(overlayObject)
	if err != nil {
		t.Fatalf("read /nested after gc: %v", err)
	}
	want := overlayExpectedByPath(t, fixture, "/nested")
	if string(got) != string(want) {
		t.Fatalf("/nested after gc = %x, want %x", got, want)
	}

	// Drop the outer object: /overlay is now reachable only as /nested's base.
	if err := s.Unlink(root, []byte("overlay")); err != nil {
		t.Fatalf("unlink /overlay: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc 2: %v", err)
	}
	if !manifestExists(baseID) || !manifestExists(overlayID) || !manifestExists(nestedID) {
		t.Fatalf("GC deleted a base-only manifest")
	}

	// Drop the last root: the whole chain is collectable.
	if err := s.Unlink(root, []byte("nested")); err != nil {
		t.Fatalf("unlink /nested: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc 3: %v", err)
	}
	if manifestExists(baseID) || manifestExists(overlayID) || manifestExists(nestedID) {
		t.Fatalf("GC retained an unreachable overlay manifest")
	}
	for _, chunk := range append(append([]string{}, fixture.BaseChunks...), fixture.NestedChunks...) {
		if exists(store.BlobObject, chunk) {
			t.Fatalf("GC retained unreachable chunk %s", chunk)
		}
	}
}

func TestOverlayFailsClosedOnBrokenBaseChain(t *testing.T) {
	src := overlayFixtureDir(t)
	fixture, _ := loadOverlayFixture(t, src)
	dir := t.TempDir()
	copyOverlayTree(t, src, dir)

	// Delete the base manifest but keep the overlay object.
	baseID := mustOverlayHash(t, fixture.BaseManifest)
	if err := os.Remove(store.BlobPath(dir, store.BlobManifest, baseID)); err != nil {
		t.Fatalf("remove base manifest: %v", err)
	}
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open with missing base: %v", err)
	}
	defer s.Close()
	overlayID := mustOverlayHash(t, fixture.OverlayManifest)
	if _, err := s.ReadContent(overlayID, 0, 8); err == nil {
		t.Fatalf("read succeeded with a missing base manifest")
	} else if got := err.Error(); !strings.Contains(strings.ToLower(got), "missing") &&
		!strings.Contains(strings.ToLower(got), "corrupt") {
		t.Fatalf("unexpected missing-base error: %v", err)
	}
	report, err := s.Verify(false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatalf("verify reported ok with a missing base manifest")
	}
	found := false
	for _, problem := range report.Problems {
		if strings.Contains(problem.Detail, "overlay") {
			found = true
		}
	}
	if !found {
		t.Fatalf("verify did not name the broken overlay: %+v", report.Problems)
	}
}
