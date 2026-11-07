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

// TestFloatTiledPlannerOffersTheCandidate checks the explicit opt-in rule.
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
