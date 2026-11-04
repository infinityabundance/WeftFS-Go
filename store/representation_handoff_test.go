package store_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// runRustBytes runs the Rust oracle and returns raw stdout, so binary file
// contents are compared byte for byte rather than through a string round trip.
func runRustBytes(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("rust %s failed: %v\nstderr:\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

func writePayload(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write payload %s: %v", name, err)
	}
	return path
}

// buildRustCodecStore writes the required codec-auto shape with the Rust
// binary: compressible ZSTD, a near-duplicate DELTA pair with a causal parent,
// and an incompressible raw fallback.
func buildRustCodecStore(t *testing.T, bin, dir, payloadDir string, base, derived, incompressible []byte) {
	t.Helper()
	basePath := writePayload(t, payloadDir, "base.bin", base)
	derivedPath := writePayload(t, payloadDir, "derived.bin", derived)
	randomPath := writePayload(t, payloadDir, "random.bin", incompressible)
	policy := []string{"--store", dir, "--representation", "codec-auto", "--codec-min-bytes", "4096"}
	runRust(t, bin, append(policy, "init")...)
	runRust(t, bin, append(policy, "create", "/base.txt", "--file", basePath, "--seed", "rust-v2-base")...)
	stat := rustJSON(t, bin, dir, "stat", "/base.txt")
	versionID, ok := stat["version_id"].(string)
	if !ok || len(versionID) != 64 {
		t.Fatalf("rust stat /base.txt returned no version_id: %+v", stat)
	}
	runRust(t, bin, append(policy,
		"create", "/derived.txt", "--file", derivedPath, "--causal", versionID, "--seed", "rust-v2-derived")...)
	runRust(t, bin, append(policy,
		"create", "/random.bin", "--file", randomPath, "--seed", "rust-v2-random")...)
}

func assertRepresentationStrategies(t *testing.T, root string, s *store.Store) {
	t.Helper()
	cases := []struct {
		path     string
		kind     model.RepresentationKind
		strategy string
	}{
		{"/base.txt", model.RepresentationCodec, model.StrategyZstd},
		{"/derived.txt", model.RepresentationCodec, model.StrategyDelta},
		{"/random.bin", model.RepresentationRaw, model.StrategyRaw},
	}
	for _, tc := range cases {
		id, err := s.ResolvePath(tc.path)
		if err != nil {
			t.Fatalf("resolve %s: %v", tc.path, err)
		}
		record, err := s.ObjectMeta(id)
		if err != nil {
			t.Fatalf("object meta %s: %v", tc.path, err)
		}
		manifest, err := store.ReadManifest(root, record.Content)
		if err != nil {
			t.Fatalf("manifest %s: %v", tc.path, err)
		}
		if manifest.Representation == nil {
			t.Fatalf("%s has no v2 representation", tc.path)
		}
		if manifest.Representation.Kind != tc.kind || manifest.Representation.Strategy != tc.strategy {
			t.Fatalf("%s representation = %s/%s, want %s/%s", tc.path,
				manifest.Representation.Kind, manifest.Representation.Strategy, tc.kind, tc.strategy)
		}
	}
}

func TestRepresentationHandoffRustThenGo(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	payloadDir := t.TempDir()
	base := v2Compressible(128 * 1024)
	derived := v2NearDuplicate(base)
	incompressible := v2Incompressible(64 * 1024)
	buildRustCodecStore(t, bin, dir, payloadDir, base, derived, incompressible)

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open rust store: %v", err)
	}
	defer s.Close()

	assertRepresentationStrategies(t, dir, s)

	for path, want := range map[string][]byte{
		"/base.txt": base, "/derived.txt": derived, "/random.bin": incompressible,
	} {
		id, err := s.ResolvePath(path)
		if err != nil {
			t.Fatalf("resolve %s: %v", path, err)
		}
		got, err := s.ReadObject(id)
		if err != nil {
			t.Fatalf("go read %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("go read %s returned %d bytes, want %d", path, len(got), len(want))
		}
	}

	derivedID, _ := s.ResolvePath("/derived.txt")
	offset := uint64(len(derived) / 4)
	length := uint64(8192)
	gotRange, err := s.ReadRange(derivedID, offset, length)
	if err != nil {
		t.Fatalf("go range read of a Rust delta: %v", err)
	}
	if !bytes.Equal(gotRange, derived[offset:offset+length]) {
		t.Fatal("go range read of a Rust delta returned the wrong bytes")
	}

	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("go verify rust store: %v", err)
	}
	if !report.OK {
		t.Fatalf("go verify rust store problems: %+v", report.Problems)
	}
	if report.CheckedRepresentations < 2 {
		t.Fatalf("go checked_representations = %d, want at least 2", report.CheckedRepresentations)
	}
}

func TestRepresentationHandoffGoThenRust(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	base := v2Compressible(128 * 1024)
	derived := v2NearDuplicate(base)
	incompressible := v2Incompressible(64 * 1024)

	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	baseID, err := s.CreateFileSeeded(model.RootID, []byte("base.txt"), base, 0o644, 0, 0, nil, []byte("go-v2-base"))
	if err != nil {
		t.Fatalf("go create base: %v", err)
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		t.Fatalf("go base meta: %v", err)
	}
	if _, err := s.CreateFileSeededCausal(model.RootID, []byte("derived.txt"), derived, 0o644, 0, 0, nil,
		[]byte("go-v2-derived"), []model.Hash32{baseRecord.Version}); err != nil {
		t.Fatalf("go create derived: %v", err)
	}
	if _, err := s.CreateFileSeeded(model.RootID, []byte("random.bin"), incompressible, 0o644, 0, 0, nil, []byte("go-v2-random")); err != nil {
		t.Fatalf("go create random: %v", err)
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify: %v, problems=%+v", err, report.Problems)
	}
	if report.CheckedRepresentations < 2 {
		t.Fatalf("go checked_representations = %d, want at least 2", report.CheckedRepresentations)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("go close: %v", err)
	}

	rustReport := rustJSON(t, bin, dir, "verify", "--full")
	if ok, _ := rustReport["ok"].(bool); !ok {
		t.Fatalf("rust verify --full failed on a Go store: %+v", rustReport)
	}
	checked, _ := rustReport["checked_representations"].(float64)
	if checked < 2 {
		t.Fatalf("rust checked_representations = %v, want at least 2", rustReport["checked_representations"])
	}
	if problems, ok := rustReport["problems"].([]any); ok && len(problems) != 0 {
		t.Fatalf("rust verify reported problems on a Go store: %+v", problems)
	}

	for path, want := range map[string][]byte{
		"/base.txt": base, "/derived.txt": derived, "/random.bin": incompressible,
	} {
		got := runRustBytes(t, bin, "--store", dir, "cat", path)
		if !bytes.Equal(got, want) {
			t.Fatalf("rust cat %s returned %d bytes, want %d", path, len(got), len(want))
		}
	}

	derivedOffset := uint64(len(derived) / 4)
	gotRange := runRustBytes(t, bin, "--store", dir, "cat", "/derived.txt",
		"--offset", itoaU64(derivedOffset), "--len", "8192")
	if !bytes.Equal(gotRange, derived[derivedOffset:derivedOffset+8192]) {
		t.Fatal("rust range read of a Go delta returned the wrong bytes")
	}
}

func TestRepresentationRetentionRustWrittenGoGC(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	payloadDir := t.TempDir()
	base := v2Compressible(128 * 1024)
	derived := v2NearDuplicate(base)
	incompressible := v2Incompressible(64 * 1024)
	buildRustCodecStore(t, bin, dir, payloadDir, base, derived, incompressible)

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, v2Options())
	if err != nil {
		t.Fatalf("go open rust store for GC: %v", err)
	}
	defer writer.Close()
	_, derivedManifest := v2ManifestFor(t, writer, "/derived.txt")
	if derivedManifest.Representation == nil || len(derivedManifest.Representation.Dependencies) != 1 {
		t.Fatalf("rust derived is not a delta representation: %+v", derivedManifest.Representation)
	}
	dependency := derivedManifest.Representation.Dependencies[0]
	root, _ := writer.ResolvePath("/")
	if err := writer.Unlink(root, []byte("base.txt")); err != nil {
		t.Fatalf("go unlink base in rust store: %v", err)
	}
	if _, err := writer.GC(true); err != nil {
		t.Fatalf("go gc: %v", err)
	}
	if _, err := os.Stat(store.ManifestPath(dir, dependency)); err != nil {
		t.Fatalf("go GC reclaimed a Rust delta dependency: %v", err)
	}
	derivedID, _ := writer.ResolvePath("/derived.txt")
	got, err := writer.ReadObject(derivedID)
	if err != nil || !bytes.Equal(got, derived) {
		t.Fatalf("go read of a Rust delta after GC: %v", err)
	}

	// Rust must still verify the store after Go's GC, including the retained
	// dependency.
	rustReport := rustJSON(t, bin, dir, "verify", "--full")
	if ok, _ := rustReport["ok"].(bool); !ok {
		t.Fatalf("rust verify after go GC failed: %+v", rustReport)
	}
	rustDerived := runRustBytes(t, bin, "--store", dir, "cat", "/derived.txt")
	if !bytes.Equal(rustDerived, derived) {
		t.Fatal("rust read of its own delta after go GC returned the wrong bytes")
	}
}

func itoaU64(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for value > 0 {
		pos--
		buf[pos] = digits[value%10]
		value /= 10
	}
	return string(buf[pos:])
}
