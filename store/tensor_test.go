package store_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// smoothBf16Tensor builds a compressible bf16 tensor with structured 16-bit
// words, matching the Rust reference fixture generator.
func smoothBf16Tensor(elements int, seed uint64) []byte {
	out := make([]byte, 0, elements*2)
	state := seed | 1
	for index := 0; index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		low := (uint16(index) * 37) & 0x3ff
		word := uint16(0x3f00|low) ^ (uint16(state) & 0x3f)
		var buffer [2]byte
		binary.LittleEndian.PutUint16(buffer[:], word)
		out = append(out, buffer[:]...)
	}
	return out
}

// nudgeBf16LowMantissa flips bit 0 of `count` elements, which keeps values in
// the same semantic class but changes exact bytes.
func nudgeBf16LowMantissa(data []byte, count int) []byte {
	out := append([]byte(nil), data...)
	elements := len(out) / 2
	if count <= 0 || elements == 0 {
		return out
	}
	stride := elements / count
	if stride < 1 {
		stride = 1
	}
	done := 0
	for index := 0; index < elements && done < count; index += stride {
		out[index*2] ^= 0x01
		done++
	}
	return out
}

func blockedBf16Payload(t *testing.T, dtype string, shape, block []uint64, rowMajor []byte) []byte {
	t.Helper()
	physical, ok := model.TensorPhysicalDtype(dtype)
	if !ok {
		t.Fatalf("no physical dtype for %s", dtype)
	}
	blocks, err := tensor.BlockedBytes(physical, shape, block, rowMajor, limits.Default())
	if err != nil {
		t.Fatalf("blocked bytes: %v", err)
	}
	var out []byte
	for _, part := range blocks {
		out = append(out, part...)
	}
	return out
}

func tensorRepresentation(t *testing.T, dir string, s *store.Store, path string) *model.Representation {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("object meta %s: %v", path, err)
	}
	manifest, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		t.Fatalf("manifest %s: %v", path, err)
	}
	return manifest.Representation
}

func tensorFrameSize(t *testing.T, dir string, s *store.Store, path string) uint64 {
	t.Helper()
	rep := tensorRepresentation(t, dir, s, path)
	if rep == nil || rep.Frame == nil {
		t.Fatalf("%s has no frame blob", path)
	}
	info, err := os.Stat(store.ManifestPath(dir, *rep.Frame))
	if err != nil {
		t.Fatalf("frame size %s: %v", path, err)
	}
	return uint64(info.Size())
}

func TestTensorMode10RoundTripsAcrossLayouts(t *testing.T) {
	shape := []uint64{256, 512}
	rowMajor := v2Incompressible(256 * 512)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	rowID, err := s.WriteTensorFile(model.RootID, []byte("q8-row"), "q8_0", shape, rowMajor,
		store.RowMajorTensorLayout(), nil)
	if err != nil {
		t.Fatalf("write q8 row-major: %v", err)
	}
	rowMeta, err := s.TensorMetadata(rowID)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if rowMeta.Strategy != model.StrategyTensorSharded {
		t.Fatalf("strategy = %s, want tensor-sharded", rowMeta.Strategy)
	}
	rowRoot, err := s.TensorLogicalRoot(rowID)
	if err != nil {
		t.Fatalf("logical root: %v", err)
	}
	got, err := s.ReadTensor(rowID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, rowMajor) {
		t.Fatal("mode-10 row-major read returned the wrong bytes")
	}

	// Blocked physical input, canonicalised by the store.
	block := []uint64{64, 64}
	blocked := blockedBf16Payload(t, "q8_0", shape, block, rowMajor)
	blockedID, err := s.WriteTensorFile(model.RootID, []byte("q8-blocked"), "q8_0", shape, blocked,
		store.BlockedTensorLayout(block), nil)
	if err != nil {
		t.Fatalf("write q8 blocked: %v", err)
	}
	got, err = s.ReadTensor(blockedID)
	if err != nil || !bytes.Equal(got, rowMajor) {
		t.Fatalf("blocked read: %v", err)
	}
	blockedRoot, err := s.TensorLogicalRoot(blockedID)
	if err != nil || blockedRoot != rowRoot {
		t.Fatalf("blocked logical root = %v (%v), want %v", blockedRoot, err, rowRoot)
	}

	// Single-shard declaration.
	shardedID, err := s.WriteTensorFile(model.RootID, []byte("q8-sharded"), "q8_0", shape, rowMajor,
		store.ShardedTensorLayout(0, 1, 0), nil)
	if err != nil {
		t.Fatalf("write q8 sharded: %v", err)
	}
	got, err = s.ReadTensor(shardedID)
	if err != nil || !bytes.Equal(got, rowMajor) {
		t.Fatalf("sharded read: %v", err)
	}
	shardedRoot, err := s.TensorLogicalRoot(shardedID)
	if err != nil || shardedRoot != rowRoot {
		t.Fatalf("sharded logical root = %v (%v), want %v", shardedRoot, err, rowRoot)
	}

	// A multi-shard write is rejected, never silently truncated.
	if _, err := s.WriteTensorFile(model.RootID, []byte("q8-multi"), "q8_0", shape, rowMajor,
		store.ShardedTensorLayout(0, 2, 0), nil); werr.ClassOf(err) != werr.InvalidArgument {
		t.Fatalf("multi-shard write = %v, want InvalidArgument", err)
	}

	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v, problems=%+v", err, report.Problems)
	}
	if report.CheckedRepresentations != 3 {
		t.Fatalf("checked_representations = %d, want 3", report.CheckedRepresentations)
	}
}

func TestTensorPlannerChoosesWeightDeltaAndRaw(t *testing.T) {
	shape := []uint64{256, 512}
	base := smoothBf16Tensor(256*512, 0x33)
	derived := nudgeBf16LowMantissa(base, 1000)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	baseID, err := s.WriteTensorFile(model.RootID, []byte("base"), "bf16", shape, base,
		store.RowMajorTensorLayout(), nil)
	if err != nil {
		t.Fatalf("write base: %v", err)
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		t.Fatalf("base meta: %v", err)
	}
	plan, err := s.PlanTensor("bf16", shape, derived, store.RowMajorTensorLayout(),
		[]model.Hash32{baseRecord.Version}, store.TensorPlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Chosen != store.TensorStrategyWeightDelta {
		t.Fatalf("chosen = %s, want weight-delta (plan %+v)", plan.Chosen, plan)
	}
	derivedID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("derived"), "bf16", shape, derived,
		store.RowMajorTensorLayout(), store.TensorWriteSpec{Causal: []model.Hash32{baseRecord.Version}})
	if err != nil {
		t.Fatalf("write derived: %v", err)
	}
	if got := tensorFrameSize(t, dir, s, "/derived"); got != plan.ChosenPhysicalBytes {
		t.Fatalf("written frame %d bytes, plan chose %d", got, plan.ChosenPhysicalBytes)
	}
	rep := tensorRepresentation(t, dir, s, "/derived")
	if rep == nil || rep.Kind != model.RepresentationTensor || rep.Tensor == nil ||
		rep.Tensor.Mode != 11 || rep.Strategy != model.StrategyWeightDelta {
		t.Fatalf("derived representation = %+v", rep)
	}
	if len(rep.Dependencies) != 1 || rep.Dependencies[0] != baseRecord.Content {
		t.Fatalf("derived dependencies = %v, want the base content root", rep.Dependencies)
	}
	got, err := s.ReadTensor(derivedID)
	if err != nil || !bytes.Equal(got, derived) {
		t.Fatalf("derived read: %v", err)
	}
	if _, err := s.TensorLogicalRoot(derivedID); err != nil {
		t.Fatalf("derived logical root: %v", err)
	}

	// An incompressible tensor with no causal base stays on the raw path.
	random := v2Incompressible(256 * 512 * 2)
	randomPlan, err := s.PlanTensor("bf16", shape, random, store.RowMajorTensorLayout(),
		nil, store.TensorPlanOptions{})
	if err != nil {
		t.Fatalf("plan random: %v", err)
	}
	if randomPlan.Chosen != store.TensorStrategyRaw {
		t.Fatalf("incompressible chosen = %s, want raw (plan %+v)", randomPlan.Chosen, randomPlan)
	}
	randomID, err := s.WriteTensorFile(model.RootID, []byte("random"), "bf16", shape, random,
		store.RowMajorTensorLayout(), nil)
	if err != nil {
		t.Fatalf("write random: %v", err)
	}
	if rep := tensorRepresentation(t, dir, s, "/random"); rep == nil || rep.Kind != model.RepresentationRaw {
		t.Fatalf("random representation = %+v, want raw", rep)
	}
	if got, err := s.ReadTensor(randomID); err != nil || !bytes.Equal(got, random) {
		t.Fatalf("random read: %v", err)
	}

	// The logical root is layout-independent for a weight-delta target.
	block := []uint64{64, 64}
	blockedDerived := blockedBf16Payload(t, "bf16", shape, block, derived)
	blockedID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("derived-blocked"), "bf16", shape,
		blockedDerived, store.BlockedTensorLayout(block),
		store.TensorWriteSpec{Causal: []model.Hash32{baseRecord.Version}})
	if err != nil {
		t.Fatalf("write blocked derived: %v", err)
	}
	derivedMeta, _ := s.TensorMetadata(derivedID)
	blockedMeta, err := s.TensorMetadata(blockedID)
	if err != nil || blockedMeta.LogicalRoot != derivedMeta.LogicalRoot {
		t.Fatalf("blocked logical root = %v (%v), want %v", blockedMeta.LogicalRoot, err, derivedMeta.LogicalRoot)
	}

	// A middle region read is exact.
	region := tensor.NewRegion([]uint64{10, 0}, []uint64{12, 512})
	read, err := s.ReadTensorRegion(derivedID, region)
	if err != nil {
		t.Fatalf("region read: %v", err)
	}
	expected := derived[10*512*2 : 12*512*2]
	if !bytes.Equal(read.Bytes, expected) {
		t.Fatal("region read returned the wrong bytes")
	}
	if read.UnitsTouched != 1 {
		t.Fatalf("units_touched = %d, want 1", read.UnitsTouched)
	}

	report, err := s.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("verify: %v, problems=%+v", err, report.Problems)
	}
}

func TestTensorReservedAttributesAndByteRewrite(t *testing.T) {
	shape := []uint64{8, 8}
	data := smoothBf16Tensor(64, 0x99)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	id, err := s.WriteTensorFile(model.RootID, []byte("t"), "bf16", shape, data,
		store.RowMajorTensorLayout(), nil)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	for _, key := range []string{
		model.AttrTensorDtype, model.AttrTensorShape, model.AttrTensorLogicalRoot,
		model.AttrTensorLayout, model.AttrTensorStrategy,
	} {
		if _, ok := record.Attrs[key]; !ok {
			t.Fatalf("reserved attribute %s is missing", key)
		}
	}
	meta, err := s.TensorMetadata(id)
	if err != nil {
		t.Fatalf("tensor metadata: %v", err)
	}
	if meta.Dtype != "bf16" || meta.Layout.Name() != "row-major" {
		t.Fatalf("metadata = %+v", meta)
	}
	root, err := s.TensorLogicalRoot(id)
	if err != nil || root != meta.LogicalRoot {
		t.Fatalf("logical root = %v (%v), want %v", root, err, meta.LogicalRoot)
	}

	modified := append([]byte(nil), data...)
	modified[0] ^= 0xff
	if _, err := s.WriteFile(id, 0, modified[:1]); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if got, err := s.ReadObject(id); err != nil || !bytes.Equal(got, modified) {
		t.Fatalf("rewrite read: %v", err)
	}
	if _, err := s.TensorMetadata(id); werr.ClassOf(err) != werr.NotFound {
		t.Fatalf("tensor metadata after a byte rewrite = %v, want NotFound", err)
	}
	if report, err := s.Verify(true); err != nil || !report.OK {
		t.Fatalf("verify after rewrite: %v, problems=%+v", err, report.Problems)
	}
}

func TestTensorMissingDependencyFailsClosedAndGC(t *testing.T) {
	shape := []uint64{128, 512}
	base := smoothBf16Tensor(128*512, 0x77)
	derived := nudgeBf16LowMantissa(base, 500)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	baseID, err := s.WriteTensorFile(model.RootID, []byte("base"), "bf16", shape, base,
		store.RowMajorTensorLayout(), nil)
	if err != nil {
		t.Fatalf("write base: %v", err)
	}
	baseRecord, _ := s.ObjectMeta(baseID)
	derivedID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("derived"), "bf16", shape, derived,
		store.RowMajorTensorLayout(), store.TensorWriteSpec{StrategyHint: strategyPtr(store.TensorStrategyWeightDelta),
			Causal: []model.Hash32{baseRecord.Version}})
	if err != nil {
		t.Fatalf("write derived: %v", err)
	}
	rep := tensorRepresentation(t, dir, s, "/derived")
	if rep == nil || len(rep.Dependencies) != 1 || rep.Dependencies[0] != baseRecord.Content {
		t.Fatalf("derived representation = %+v", rep)
	}
	dependency := rep.Dependencies[0]

	root, _ := s.ResolvePath("/")
	if err := s.Unlink(root, []byte("base")); err != nil {
		t.Fatalf("unlink base: %v", err)
	}
	if _, err := s.GC(true); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := os.Stat(store.ManifestPath(dir, dependency)); err != nil {
		t.Fatalf("GC reclaimed a live tensor dependency: %v", err)
	}
	if got, err := s.ReadTensor(derivedID); err != nil || !bytes.Equal(got, derived) {
		t.Fatalf("read after GC: %v", err)
	}

	// Remove the base manifest: full and range reads fail closed as Corrupt.
	if err := os.Remove(store.ManifestPath(dir, dependency)); err != nil {
		t.Fatalf("remove dependency: %v", err)
	}
	if _, err := s.ReadTensor(derivedID); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("full read with missing dependency = %v, want Corrupt", err)
	}
	if _, err := s.ReadRange(derivedID, 0, 32); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("range read with missing dependency = %v, want Corrupt", err)
	}
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.OK {
		t.Fatal("verify reported ok with a missing tensor dependency")
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

func strategyPtr(strategy store.TensorStrategy) *store.TensorStrategy { return &strategy }
