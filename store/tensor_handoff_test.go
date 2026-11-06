package store_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

var tensorShape = []uint64{256, 512}

// writeRustTensorStore builds the required Rust-written shape:
//   - an independent bf16 tensor (planner-chosen raw/zstd),
//   - a near-duplicate pair whose second member is a mode-16 sparse delta
//     (the planner's choice for a 1,000-word change),
//   - the same pair forced to mode-11 weight delta,
//   - an incompressible bf16 tensor (raw).
func writeRustTensorStore(t *testing.T, bin, dir, payloadDir string) map[string][]byte {
	t.Helper()
	independent := smoothBf16Tensor(256*512, 0x41)
	base := smoothBf16Tensor(256*512, 0x52)
	derived := nudgeBf16LowMantissa(base, 1000)
	incompressible := v2Incompressible(256 * 512 * 2)

	policy := []string{"--store", dir, "--representation", "codec-auto", "--codec-min-bytes", "4096"}
	runRust(t, bin, append(policy, "init")...)

	writeTensor := func(path string, data []byte, extra ...string) {
		payload := writePayload(t, payloadDir, strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "-"), data)
		args := append([]string{"write", path, "--tensor", "--dtype", "bf16", "--shape", "256,512",
			"--file", payload}, extra...)
		runRust(t, bin, append(policy, args...)...)
	}

	writeTensor("/independent.bin", independent)
	writeTensor("/pair-base.bin", base)
	stat := rustJSON(t, bin, dir, "stat", "/pair-base.bin")
	versionID, ok := stat["version_id"].(string)
	if !ok || len(versionID) != 64 {
		t.Fatalf("rust stat /pair-base.bin returned no version_id: %+v", stat)
	}
	writeTensor("/pair-derived.bin", derived, "--causal", versionID)
	writeTensor("/pair-derived-weight.bin", derived, "--causal", versionID,
		"--strategy", "weight-delta")
	writeTensor("/incompressible.bin", incompressible)

	return map[string][]byte{
		"/independent.bin":         independent,
		"/pair-base.bin":           base,
		"/pair-derived.bin":        derived,
		"/pair-derived-weight.bin": derived,
		"/incompressible.bin":      incompressible,
	}
}

// writeGoTensorStore builds the same logical shape with the Go writer, plus a
// q8_0 mode-10 tensor so Rust validates the Go scale plane.
func writeGoTensorStore(t *testing.T, dir string) (map[string][]byte, *store.Store, model.Hash32) {
	t.Helper()
	independent := smoothBf16Tensor(256*512, 0x41)
	base := smoothBf16Tensor(256*512, 0x52)
	derived := nudgeBf16LowMantissa(base, 1000)
	incompressible := v2Incompressible(256 * 512 * 2)
	quantized := v2Incompressible(256 * 512)

	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("go init: %v", err)
	}
	if _, err := s.WriteTensorFile(model.RootID, []byte("independent.bin"), "bf16", tensorShape,
		independent, store.RowMajorTensorLayout(), nil); err != nil {
		t.Fatalf("go write independent: %v", err)
	}
	baseID, err := s.WriteTensorFile(model.RootID, []byte("pair-base.bin"), "bf16", tensorShape,
		base, store.RowMajorTensorLayout(), nil)
	if err != nil {
		t.Fatalf("go write pair base: %v", err)
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		t.Fatalf("go pair base meta: %v", err)
	}
	derivedID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("pair-derived.bin"), "bf16",
		tensorShape, derived, store.RowMajorTensorLayout(),
		store.TensorWriteSpec{Causal: []model.Hash32{baseRecord.Version}})
	if err != nil {
		t.Fatalf("go write pair derived: %v", err)
	}
	if _, err := s.WriteTensorFileWithSpec(model.RootID, []byte("pair-derived-weight.bin"), "bf16",
		tensorShape, derived, store.RowMajorTensorLayout(),
		store.TensorWriteSpec{
			Causal:       []model.Hash32{baseRecord.Version},
			StrategyHint: strategyPtr(store.TensorStrategyWeightDelta),
		}); err != nil {
		t.Fatalf("go write mode-11 pair derived: %v", err)
	}
	if _, err := s.WriteTensorFile(model.RootID, []byte("incompressible.bin"), "bf16", tensorShape,
		incompressible, store.RowMajorTensorLayout(), nil); err != nil {
		t.Fatalf("go write incompressible: %v", err)
	}
	if _, err := s.WriteTensorFile(model.RootID, []byte("quantized.bin"), "q8_0", tensorShape,
		quantized, store.RowMajorTensorLayout(), nil); err != nil {
		t.Fatalf("go write q8_0: %v", err)
	}
	rep := tensorRepresentation(t, dir, s, "/pair-derived.bin")
	if rep == nil || rep.Kind != model.RepresentationTensor || rep.Tensor == nil ||
		rep.Tensor.Mode != 16 || rep.Strategy != model.StrategySparseDelta {
		t.Fatalf("go derived representation = %+v, want mode 16 sparse-delta", rep)
	}
	weightRep := tensorRepresentation(t, dir, s, "/pair-derived-weight.bin")
	if weightRep == nil || weightRep.Tensor == nil || weightRep.Tensor.Mode != 11 ||
		weightRep.Strategy != model.StrategyWeightDelta {
		t.Fatalf("go forced representation = %+v, want mode 11 weight-delta", weightRep)
	}
	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify: %v, problems=%+v", err, report.Problems)
	}
	return map[string][]byte{
		"/independent.bin":         independent,
		"/pair-base.bin":           base,
		"/pair-derived.bin":        derived,
		"/pair-derived-weight.bin": derived,
		"/incompressible.bin":      incompressible,
		"/quantized.bin":           quantized,
	}, s, derivedID
}

func runRustExpectFailure(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("rust %s unexpectedly succeeded:\n%s", strings.Join(args, " "), output)
	}
	return string(output)
}

func TestTensorHandoffRustThenGo(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	payloadDir := t.TempDir()
	expected := writeRustTensorStore(t, bin, dir, payloadDir)

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open rust tensor store: %v", err)
	}
	defer s.Close()

	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("go verify rust tensor store: %v", err)
	}
	if !report.OK {
		t.Fatalf("go verify problems: %+v", report.Problems)
	}
	if report.CheckedRepresentations < 1 {
		t.Fatalf("checked_representations = %d, want at least 1", report.CheckedRepresentations)
	}

	for path, want := range expected {
		id, err := s.ResolvePath(path)
		if err != nil {
			t.Fatalf("resolve %s: %v", path, err)
		}
		meta, err := s.TensorMetadata(id)
		if err != nil {
			t.Fatalf("tensor metadata %s: %v", path, err)
		}
		if meta.Dtype != "bf16" || len(meta.Shape) != 2 || meta.Shape[0] != 256 || meta.Shape[1] != 512 {
			t.Fatalf("%s metadata = %+v", path, meta)
		}
		root, err := s.TensorLogicalRoot(id)
		if err != nil {
			t.Fatalf("logical root %s: %v", path, err)
		}
		if root != meta.LogicalRoot {
			t.Fatalf("%s logical root %s != recorded %s", path, root.Hex(), meta.LogicalRoot.Hex())
		}
		got, err := s.ReadTensor(id)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("read %s returned %d bytes, want %d", path, len(got), len(want))
		}
	}

	// The planner-chosen member is an exact mode-16 sparse delta with one
	// dependency; the forced member is mode 11.
	rep := tensorRepresentation(t, dir, s, "/pair-derived.bin")
	if rep == nil || rep.Tensor == nil || rep.Tensor.Mode != 16 ||
		rep.Strategy != model.StrategySparseDelta || len(rep.Dependencies) != 1 {
		t.Fatalf("rust pair-derived representation = %+v", rep)
	}
	weightRep := tensorRepresentation(t, dir, s, "/pair-derived-weight.bin")
	if weightRep == nil || weightRep.Tensor == nil || weightRep.Tensor.Mode != 11 ||
		weightRep.Strategy != model.StrategyWeightDelta || len(weightRep.Dependencies) != 1 {
		t.Fatalf("rust forced representation = %+v", weightRep)
	}

	// Region reads are exact (rows 10..12 of 256x512 bf16).
	derivedID, _ := s.ResolvePath("/pair-derived.bin")
	read, err := s.ReadTensorRegion(derivedID, tensor.NewRegion([]uint64{10, 0}, []uint64{12, 512}))
	if err != nil {
		t.Fatalf("go region read: %v", err)
	}
	if want := expected["/pair-derived.bin"][10*512*2 : 12*512*2]; !bytes.Equal(read.Bytes, want) {
		t.Fatal("go region read of a Rust tensor returned the wrong bytes")
	}
}

func TestTensorHandoffGoThenRust(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	expected, s, _ := writeGoTensorStore(t, dir)
	if err := s.Close(); err != nil {
		t.Fatalf("go close: %v", err)
	}

	report := rustJSON(t, bin, dir, "verify", "--full")
	if ok, _ := report["ok"].(bool); !ok {
		t.Fatalf("rust verify --full failed on a Go tensor store: %+v", report)
	}
	checked, _ := report["checked_representations"].(float64)
	if checked < 1 {
		t.Fatalf("rust checked_representations = %v, want at least 1", report["checked_representations"])
	}
	if problems, ok := report["problems"].([]any); ok && len(problems) != 0 {
		t.Fatalf("rust verify reported problems on a Go tensor store: %+v", problems)
	}

	for path, want := range expected {
		got := runRustBytes(t, bin, "--store", dir, "cat", path)
		if !bytes.Equal(got, want) {
			t.Fatalf("rust cat %s returned %d bytes, want %d", path, len(got), len(want))
		}
	}
	gotRegion := runRustBytes(t, bin, "--store", dir, "cat", "/pair-derived.bin",
		"--region", "10,0:12,512")
	if want := expected["/pair-derived.bin"][10*512*2 : 12*512*2]; !bytes.Equal(gotRegion, want) {
		t.Fatal("rust region read of a Go tensor returned the wrong bytes")
	}
}

func TestTensorRetentionRustWrittenGoGC(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	payloadDir := t.TempDir()
	expected := writeRustTensorStore(t, bin, dir, payloadDir)

	writer, err := store.OpenWithOptions(dir, store.ReadWrite, v2Options())
	if err != nil {
		t.Fatalf("go open rust tensor store: %v", err)
	}
	defer writer.Close()
	rep := tensorRepresentation(t, dir, writer, "/pair-derived.bin")
	if rep == nil || rep.Tensor == nil || rep.Tensor.Mode != 16 || len(rep.Dependencies) != 1 {
		t.Fatalf("rust pair-derived is not a mode-16 delta: %+v", rep)
	}
	dependency := rep.Dependencies[0]
	root, _ := writer.ResolvePath("/")
	if err := writer.Unlink(root, []byte("pair-base.bin")); err != nil {
		t.Fatalf("go unlink base: %v", err)
	}
	if _, err := writer.GC(true); err != nil {
		t.Fatalf("go gc: %v", err)
	}
	if _, err := os.Stat(store.ManifestPath(dir, dependency)); err != nil {
		t.Fatalf("go GC reclaimed a Rust tensor delta base: %v", err)
	}
	derivedID, _ := writer.ResolvePath("/pair-derived.bin")
	got, err := writer.ReadTensor(derivedID)
	if err != nil || !bytes.Equal(got, expected["/pair-derived.bin"]) {
		t.Fatalf("go read of a Rust tensor delta after GC: %v", err)
	}

	report := rustJSON(t, bin, dir, "verify", "--full")
	if ok, _ := report["ok"].(bool); !ok {
		t.Fatalf("rust verify after go GC failed: %+v", report)
	}
}

func TestTensorMissingBaseFailsClosedBothSides(t *testing.T) {
	bin := rustBinary(t)

	// Rust-written store. The base object is unlinked first so the store's own
	// open-time validation does not reject the tail; the dependent stays live and
	// the missing base is reached only through the dependency closure.
	rustDir := t.TempDir()
	rustPayloads := t.TempDir()
	writeRustTensorStore(t, bin, rustDir, rustPayloads)
	rustStore, err := store.OpenWithOptions(rustDir, store.ReadWrite, v2Options())
	if err != nil {
		t.Fatalf("go open rust store: %v", err)
	}
	rep := tensorRepresentation(t, rustDir, rustStore, "/pair-derived.bin")
	if rep == nil || len(rep.Dependencies) != 1 {
		t.Fatalf("rust pair-derived has no dependency: %+v", rep)
	}
	dependency := rep.Dependencies[0]
	derivedID, _ := rustStore.ResolvePath("/pair-derived.bin")
	rootID, err := rustStore.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	if err := rustStore.Unlink(rootID, []byte("pair-base.bin")); err != nil {
		t.Fatalf("go unlink rust base: %v", err)
	}
	if err := rustStore.Close(); err != nil {
		t.Fatalf("close rust store: %v", err)
	}
	if err := os.Remove(store.ManifestPath(rustDir, dependency)); err != nil {
		t.Fatalf("remove rust dependency: %v", err)
	}

	reader, err := store.Open(rustDir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen rust store: %v", err)
	}
	if _, err := reader.ReadTensor(derivedID); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("go read with a missing Rust base = %v, want Corrupt", err)
	}
	if _, err := reader.ReadRange(derivedID, 0, 32); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("go range read with a missing Rust base = %v, want Corrupt", err)
	}
	verifyReport, err := reader.Verify(true)
	if err != nil {
		t.Fatalf("go verify: %v", err)
	}
	if verifyReport.OK {
		t.Fatal("go verify reported ok with a missing Rust base")
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	// Rust validates the catalog at open, so a CLI read refuses the tail before
	// decoding. `verify --full` names the missing dependency with class Corrupt
	// (the same class its in-process read path returns).
	rustVerify := rustJSON(t, bin, rustDir, "verify", "--full")
	if ok, _ := rustVerify["ok"].(bool); ok {
		t.Fatal("rust verify reported ok with a missing tensor base")
	}
	if !verifyNamesCorruptDependency(rustVerify, dependency) {
		t.Fatalf("rust verify did not name %s as Corrupt: %+v", dependency.Hex(), rustVerify)
	}
	runRustExpectFailure(t, bin, "--store", rustDir, "cat", "/pair-derived.bin")

	// Go-written store: Rust fails closed as Corrupt.
	goDir := t.TempDir()
	_, goStore, goDerived := writeGoTensorStore(t, goDir)
	rep = tensorRepresentation(t, goDir, goStore, "/pair-derived.bin")
	if rep == nil || len(rep.Dependencies) != 1 {
		t.Fatalf("go pair-derived has no dependency: %+v", rep)
	}
	goDependency := rep.Dependencies[0]
	goRoot, err := goStore.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve go root: %v", err)
	}
	if err := goStore.Unlink(goRoot, []byte("pair-base.bin")); err != nil {
		t.Fatalf("go unlink go base: %v", err)
	}
	if err := goStore.Close(); err != nil {
		t.Fatalf("close go store: %v", err)
	}
	if err := os.Remove(store.ManifestPath(goDir, goDependency)); err != nil {
		t.Fatalf("remove go dependency: %v", err)
	}
	goReader, err := store.Open(goDir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen go store: %v", err)
	}
	if _, err := goReader.ReadTensor(goDerived); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("go read with a missing Go base = %v, want Corrupt", err)
	}
	if err := goReader.Close(); err != nil {
		t.Fatalf("close go reader: %v", err)
	}
	goVerify := rustJSON(t, bin, goDir, "verify", "--full")
	if ok, _ := goVerify["ok"].(bool); ok {
		t.Fatal("rust verify reported ok with a missing Go tensor base")
	}
	if !verifyNamesCorruptDependency(goVerify, goDependency) {
		t.Fatalf("rust verify did not name %s as Corrupt: %+v", goDependency.Hex(), goVerify)
	}
	runRustExpectFailure(t, bin, "--store", goDir, "cat", "/pair-derived.bin")
}

// verifyNamesCorruptDependency reports whether a Rust verify JSON report has a
// Corrupt problem naming the hash.
func verifyNamesCorruptDependency(report map[string]any, dependency model.Hash32) bool {
	problems, ok := report["problems"].([]any)
	if !ok {
		return false
	}
	for _, item := range problems {
		problem, ok := item.(map[string]any)
		if !ok || problem["class"] != string(werr.Corrupt) {
			continue
		}
		detail, _ := problem["detail"].(string)
		if strings.Contains(detail, dependency.Hex()) {
			return true
		}
	}
	return false
}

func TestTensorDependencyDepthBound(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	// A cycle cannot exist in a hash-verified store (a manifest that depends on
	// itself is a BLAKE3 fixed point), so the reachable failure is a chain that
	// exceeds the depth bound. Manifests are written directly with correct
	// content addresses; the frame is a valid mode-11 frame so every level below
	// the bound parses, and the depth check fires before the deepest decode.
	//
	// M0 -> M1 -> ... -> M9 -> missing, so M9 is read at depth 9 > 8.
	lim := limits.Default()
	shape := []uint64{4, 4}
	baseFrame, err := modes.EncodeTensor(make([]byte, 32), "bf16", shape, lim)
	if err != nil {
		t.Fatalf("base frame: %v", err)
	}
	weight, err := modes.ParseWeightDtype("bf16")
	if err != nil {
		t.Fatalf("weight dtype: %v", err)
	}
	deltaFrame, err := modes.EncodeWeightDelta(context.Background(), make([]byte, 32), weight, shape, baseFrame, lim)
	if err != nil {
		t.Fatalf("delta frame: %v", err)
	}
	frameID := hash.Domain(model.DomainManifest, deltaFrame)
	framePath := store.ManifestPath(dir, frameID)
	if err := os.MkdirAll(filepath.Dir(framePath), 0o755); err != nil {
		t.Fatalf("mkdir frame: %v", err)
	}
	if err := os.WriteFile(framePath, deltaFrame, 0o644); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	dependency := v2Incompressible(32)
	var dependencyRoot model.Hash32
	copy(dependencyRoot[:], dependency)
	for level := 9; level >= 0; level-- {
		dependencyForThis := dependencyRoot
		manifest := model.Manifest{
			Size: 32, ChunkSize: model.DefaultChunkSize,
			ContentHash: model.ContentHash(nil),
			Representation: &model.Representation{
				Kind:         model.RepresentationTensor,
				Frame:        &frameID,
				Dependencies: []model.Hash32{dependencyForThis},
				Strategy:     model.StrategyWeightDelta,
				DecodedSize:  32,
				Tensor: &model.TensorRepresentation{
					Mode: 11, Dtype: "bf16", Shape: shape,
					LogicalRoot: dependencyRoot,
					Layout: wcb.MapValue(map[string]wcb.Value{
						"schema": wcb.TextValue(tensor.LayoutSchema),
						"dtype":  wcb.TextValue("bf16"),
						"shape":  wcb.ArrayValue([]wcb.Value{wcb.U64Value(4), wcb.U64Value(4)}),
						"layout": wcb.TextValue("row-major"),
					}),
				},
			},
		}
		encoded, err := manifest.Encode()
		if err != nil {
			t.Fatalf("encode manifest: %v", err)
		}
		id, err := manifest.ID()
		if err != nil {
			t.Fatalf("manifest id: %v", err)
		}
		path := store.ManifestPath(dir, id)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		dependencyRoot = id
	}

	if _, err := s.ReadContent(dependencyRoot, 0, 32); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "depth") {
		t.Fatalf("oversized tensor dependency chain = %v, want Corrupt depth", err)
	}
}
