package store_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func v2Compressible(size int) []byte {
	pattern := []byte("WeftFS v2 representation manifest cross-language parity. ")
	out := make([]byte, 0, size+len(pattern))
	for len(out) < size {
		out = append(out, pattern...)
	}
	return out[:size]
}

func v2Incompressible(size int) []byte {
	out := make([]byte, size)
	state := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < size; i += 8 {
		state += 0x9e3779b97f4a7c15
		z := state
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z ^= z >> 31
		end := i + 8
		if end > size {
			end = size
		}
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], z)
		copy(out[i:end], word[:end-i])
	}
	return out
}

func v2NearDuplicate(base []byte) []byte {
	derived := append([]byte(nil), base...)
	replacement := []byte("REPLACED-REGION-0123456789-abcdefghijklmnopqrstuvwxyz-REPLACED-REGION")
	copy(derived[len(derived)/2:], replacement)
	return derived
}

func v2Options() store.Options {
	opts := store.DefaultOptions()
	opts.Representation = store.RepresentationModeCodecAuto
	opts.CodecMinBytes = store.DefaultCodecMinBytes
	opts.CheckpointInterval = 0
	opts.GCGraceSecs = 0
	return opts
}

func v2ManifestFor(t *testing.T, s *store.Store, path string) (model.Hash32, model.Manifest) {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("object meta %s: %v", path, err)
	}
	manifest, err := store.ReadManifest(s.Root(), record.Content)
	if err != nil {
		t.Fatalf("manifest %s: %v", path, err)
	}
	return id, manifest
}

func TestCodecAutoWritesAndReadsRepresentations(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	base := v2Compressible(128 * 1024)
	derived := v2NearDuplicate(base)
	incompressible := v2Incompressible(64 * 1024)

	baseID, err := s.CreateFileSeeded(model.RootID, []byte("base.txt"), base, 0o644, 0, 0, nil, []byte("v2-base"))
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		t.Fatalf("base meta: %v", err)
	}
	if _, err := s.CreateFileSeededCausal(model.RootID, []byte("derived.txt"), derived, 0o644, 0, 0, nil,
		[]byte("v2-derived"), []model.Hash32{baseRecord.Version}); err != nil {
		t.Fatalf("create derived: %v", err)
	}
	if _, err := s.CreateFileSeeded(model.RootID, []byte("random.bin"), incompressible, 0o644, 0, 0, nil, []byte("v2-random")); err != nil {
		t.Fatalf("create random: %v", err)
	}

	_, baseManifest := v2ManifestFor(t, s, "/base.txt")
	_, derivedManifest := v2ManifestFor(t, s, "/derived.txt")
	_, randomManifest := v2ManifestFor(t, s, "/random.bin")

	if baseManifest.Representation == nil || baseManifest.Representation.Kind != model.RepresentationCodec ||
		baseManifest.Representation.Strategy != model.StrategyZstd {
		t.Fatalf("base representation = %+v, want codec/zstd", baseManifest.Representation)
	}
	if derivedManifest.Representation == nil || derivedManifest.Representation.Kind != model.RepresentationCodec ||
		derivedManifest.Representation.Strategy != model.StrategyDelta {
		t.Fatalf("derived representation = %+v, want codec/delta", derivedManifest.Representation)
	}
	if len(derivedManifest.Representation.Dependencies) != 1 ||
		derivedManifest.Representation.Dependencies[0] != baseRecord.Content {
		t.Fatalf("derived dependencies = %v, want the base content root", derivedManifest.Representation.Dependencies)
	}
	if randomManifest.Representation == nil || randomManifest.Representation.Kind != model.RepresentationRaw {
		t.Fatalf("random representation = %+v, want v2 raw fallback", randomManifest.Representation)
	}

	for path, want := range map[string][]byte{
		"/base.txt": base, "/derived.txt": derived, "/random.bin": incompressible,
	} {
		id, err := s.ResolvePath(path)
		if err != nil {
			t.Fatalf("resolve %s: %v", path, err)
		}
		got, err := s.ReadObject(id)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("read %s returned %d bytes, want %d", path, len(got), len(want))
		}
	}

	// A middle range read must decode without materialising the whole file and
	// must match the same slice of the logical content.
	derivedID, _ := s.ResolvePath("/derived.txt")
	offset := uint64(len(derived) / 3)
	length := uint64(4096)
	gotRange, err := s.ReadRange(derivedID, offset, length)
	if err != nil {
		t.Fatalf("range read: %v", err)
	}
	if !bytes.Equal(gotRange, derived[offset:offset+length]) {
		t.Fatal("range read bytes disagree with the logical content")
	}

	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("verify problems: %+v", report.Problems)
	}
	if report.CheckedRepresentations < 2 {
		t.Fatalf("checked_representations = %d, want at least 2", report.CheckedRepresentations)
	}

	// Reopen read-only and read/verify again, proving nothing depends on the
	// writer's in-memory state.
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	reopened, err := reader.Verify(true)
	if err != nil || !reopened.OK {
		t.Fatalf("reopened verify: %v, problems=%+v", err, reopened.Problems)
	}
	if reopened.CheckedRepresentations < 2 {
		t.Fatalf("reopened checked_representations = %d", reopened.CheckedRepresentations)
	}
	baseID, _ = reader.ResolvePath("/base.txt")
	got, err := reader.ReadObject(baseID)
	if err != nil || !bytes.Equal(got, base) {
		t.Fatalf("reopened read base: %v", err)
	}
}

func TestRawPolicyStillWritesV1Manifests(t *testing.T) {
	dir := t.TempDir()
	opts := store.DefaultOptions()
	opts.CheckpointInterval = 0
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	if _, err := s.CreateFile(model.RootID, []byte("plain.txt"), v2Compressible(16*1024), 0o644, 0, 0, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, manifest := v2ManifestFor(t, s, "/plain.txt")
	if manifest.Representation != nil {
		t.Fatalf("raw policy wrote a representation: %+v", manifest.Representation)
	}
}

func TestCodecDependencyRetention(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	base := v2Compressible(128 * 1024)
	derived := v2NearDuplicate(base)
	baseID, err := s.CreateFileSeeded(model.RootID, []byte("base.txt"), base, 0o644, 0, 0, nil, []byte("ret-base"))
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	baseRecord, _ := s.ObjectMeta(baseID)
	derivedID, err := s.CreateFileSeededCausal(model.RootID, []byte("derived.txt"), derived, 0o644, 0, 0, nil,
		[]byte("ret-derived"), []model.Hash32{baseRecord.Version})
	if err != nil {
		t.Fatalf("create derived: %v", err)
	}
	_, derivedManifest := v2ManifestFor(t, s, "/derived.txt")
	if derivedManifest.Representation == nil || len(derivedManifest.Representation.Dependencies) != 1 {
		t.Fatalf("derived is not a delta representation: %+v", derivedManifest.Representation)
	}
	baseRoot := derivedManifest.Representation.Dependencies[0]

	root, _ := s.ResolvePath("/")
	if err := s.Unlink(root, []byte("base.txt")); err != nil {
		t.Fatalf("unlink base: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc after base unlink: %v", err)
	}
	if _, err := os.Stat(store.ManifestPath(dir, baseRoot)); err != nil {
		t.Fatalf("GC reclaimed a dependency still needed by a delta dependent: %v", err)
	}
	got, err := s.ReadObject(derivedID)
	if err != nil || !bytes.Equal(got, derived) {
		t.Fatalf("dependent read after GC: %v", err)
	}

	if err := s.Unlink(root, []byte("derived.txt")); err != nil {
		t.Fatalf("unlink derived: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc after derived unlink: %v", err)
	}
	if _, err := os.Stat(store.ManifestPath(dir, baseRoot)); !os.IsNotExist(err) {
		t.Fatalf("dependency manifest still present after both objects were removed: %v", err)
	}
}

func TestCodecMissingDependencyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	base := v2Compressible(128 * 1024)
	derived := v2NearDuplicate(base)
	baseID, err := s.CreateFileSeeded(model.RootID, []byte("base.txt"), base, 0o644, 0, 0, nil, []byte("missing-base"))
	if err != nil {
		t.Fatalf("create base: %v", err)
	}
	baseRecord, _ := s.ObjectMeta(baseID)
	derivedID, err := s.CreateFileSeededCausal(model.RootID, []byte("derived.txt"), derived, 0o644, 0, 0, nil,
		[]byte("missing-derived"), []model.Hash32{baseRecord.Version})
	if err != nil {
		t.Fatalf("create derived: %v", err)
	}
	_, derivedManifest := v2ManifestFor(t, s, "/derived.txt")
	if derivedManifest.Representation == nil || derivedManifest.Representation.Strategy != model.StrategyDelta {
		t.Fatalf("derived is not a delta representation: %+v", derivedManifest.Representation)
	}
	dependency := derivedManifest.Representation.Dependencies[0]

	// Remove the base manifest behind the dependent's back, leaving the frame
	// and chunks in place to prove the dependency itself is required.
	if err := os.Remove(store.ManifestPath(dir, dependency)); err != nil {
		t.Fatalf("remove dependency manifest: %v", err)
	}
	if _, err := s.ReadObject(derivedID); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("read with missing dependency = %v, want Corrupt", err)
	}
	if _, err := s.ReadRange(derivedID, 0, 1024); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("range read with missing dependency = %v, want Corrupt", err)
	}
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("verify reported ok with a missing representation dependency")
	}
	named := false
	for _, problem := range report.Problems {
		if problem.Class == string(werr.Corrupt) && bytes.Contains([]byte(problem.Detail), []byte(derivedID.Hex())) {
			named = true
		}
	}
	if !named {
		t.Fatalf("verify did not name the affected object %s: %+v", derivedID.Hex(), report.Problems)
	}
}
