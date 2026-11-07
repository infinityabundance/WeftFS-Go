package store_test

import (
	"bytes"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// TestFloatTiledWriteAndRead covers the mode-17 planner candidate and the
// store's generic decode path.
func TestFloatTiledWriteAndRead(t *testing.T) {
	shape := []uint64{64, 64}
	payload := smoothBf16Tensor(64*64, 0x51)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	hint := store.TensorStrategyFloatTiled
	id, err := s.WriteTensorFileWithSpec(
		model.RootID,
		[]byte("float-tiled"),
		"bf16",
		shape,
		payload,
		store.RowMajorTensorLayout(),
		store.TensorWriteSpec{
			StrategyHint: &hint,
			Plan:         store.TensorPlanOptions{TileShape: []uint64{16, 32}},
		},
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	meta, err := s.TensorMetadata(id)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.Strategy != store.TensorStrategyFloatTiled.String() {
		t.Fatalf("strategy = %s", meta.Strategy)
	}
	got, err := s.ReadTensor(id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("mode-17 read returned the wrong bytes")
	}
	row := tensor.Region{Start: []uint64{17, 0}, End: []uint64{18, 64}}
	read, err := s.ReadTensorRegion(id, row)
	if err != nil {
		t.Fatalf("region: %v", err)
	}
	if !bytes.Equal(read.Bytes, payload[17*64*2:18*64*2]) {
		t.Fatal("mode-17 region read returned the wrong bytes")
	}
	root, err := s.TensorLogicalRoot(id)
	if err != nil {
		t.Fatalf("logical root: %v", err)
	}
	if root != meta.LogicalRoot {
		t.Fatal("logical root mismatch")
	}
}

// weightLikeBf16 mirrors the Rust test fixture byte for byte: a clustered
// exponent byte and a random mantissa byte.
func weightLikeBf16(elements int, seed uint64) []byte {
	state := seed | 1
	out := make([]byte, 0, elements*2)
	for index := 0; index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		high := byte(0x3f)
		if state%16 == 0 {
			high = 0x40
		}
		out = append(out, byte(state>>8), high)
	}
	return out
}

// TestAccessPatternMatchesRustChoices runs the same fixture definition as the
// Rust access-pattern test and asserts the same selected strategies.
func TestAccessPatternMatchesRustChoices(t *testing.T) {
	shape := []uint64{512, 512}
	payload := weightLikeBf16(512*512, 0x1234)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	whole, err := s.PlanTensor("bf16", shape, payload, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{TileShape: []uint64{16, 32}})
	if err != nil {
		t.Fatalf("whole plan: %v", err)
	}
	if whole.Chosen != store.TensorStrategyFloatTensor {
		t.Fatalf("whole chosen = %s (candidates: %+v)", whole.Chosen, whole.Candidates)
	}

	region, err := s.PlanTensor("bf16", shape, payload, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{
			TileShape: []uint64{16, 32},
			LambdaNS:  1,
			AccessPattern: store.AccessPattern{
				Kind: store.AccessPatternRegion, RegionBytes: 2 * 32, ReadsPerWrite: 1000,
			},
		})
	if err != nil {
		t.Fatalf("region plan: %v", err)
	}
	if region.Chosen != store.TensorStrategyFloatTiled &&
		region.Chosen != store.TensorStrategyFloatTiledStreams {
		t.Fatalf("region chosen = %s (candidates: %+v)", region.Chosen, region.Candidates)
	}
	// Mode 18's fitted fixed term is 0, so at 64 fetched bytes it is the
	// cheapest modelled read. That is a model choice, not a latency claim.
}
func TestFloatTiledPlannerOffersTheCandidate(t *testing.T) {
	shape := []uint64{64, 64}
	payload := smoothBf16Tensor(64*64, 0x77)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	plan, err := s.PlanTensor("bf16", shape, payload, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{TileShape: []uint64{16, 32}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	found := false
	for _, candidate := range plan.Candidates {
		if candidate.Strategy == store.TensorStrategyFloatTiled && candidate.Applicable {
			found = true
		}
	}
	if !found {
		t.Fatal("float-tiled candidate missing")
	}
	if plan.Chosen == store.TensorStrategyFloatTiled {
		t.Fatal("bytes-only planner should not choose the per-tile form here")
	}
}
