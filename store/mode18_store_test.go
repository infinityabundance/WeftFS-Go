package store_test

import (
	"bytes"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

// TestFloatTiledStreamsWriteAndRead covers the mode-18 planner candidate and
// the store's generic decode path.
func TestFloatTiledStreamsWriteAndRead(t *testing.T) {
	shape := []uint64{64, 64}
	payload := smoothBf16Tensor(64*64, 0x51)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	hint := store.TensorStrategyFloatTiledStreams
	id, err := s.WriteTensorFileWithSpec(
		model.RootID,
		[]byte("float-tiled-streams"),
		"bf16",
		shape,
		payload,
		store.RowMajorTensorLayout(),
		store.TensorWriteSpec{
			StrategyHint: &hint,
			Plan: store.TensorPlanOptions{
				TileShape: []uint64{16, 32},
				NStreams:  4,
			},
		},
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	meta, err := s.TensorMetadata(id)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if meta.Strategy != store.TensorStrategyFloatTiledStreams.String() {
		t.Fatalf("strategy = %s", meta.Strategy)
	}
	got, err := s.ReadTensor(id)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("mode-18 read returned the wrong bytes")
	}
	row := tensor.Region{Start: []uint64{17, 0}, End: []uint64{18, 64}}
	read, err := s.ReadTensorRegion(id, row)
	if err != nil {
		t.Fatalf("region: %v", err)
	}
	if !bytes.Equal(read.Bytes, payload[17*64*2:18*64*2]) {
		t.Fatal("mode-18 region read returned the wrong bytes")
	}
	if _, err := s.Verify(true); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFloatTiledStreamsPlannerCandidateAndDefault(t *testing.T) {
	shape := []uint64{64, 64}
	payload := smoothBf16Tensor(64*64, 0x77)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	plan, err := s.PlanTensor("bf16", shape, payload, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{TileShape: []uint64{16, 32}, AllowExperimentalModes: true})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	found := false
	for _, candidate := range plan.Candidates {
		if candidate.Strategy == store.TensorStrategyFloatTiledStreams && candidate.Applicable {
			found = true
		}
	}
	if !found {
		t.Fatal("mode-18 candidate missing")
	}
	// Bytes-only default must keep the strictly smaller representation.
	if plan.Chosen == store.TensorStrategyFloatTiledStreams {
		t.Fatalf("bytes-only plan chose mode 18: %+v", plan.Candidates)
	}
}

func TestFloatTiledStreamsCostRowIsMeasuredAndLoses(t *testing.T) {
	shape := []uint64{1024, 1024}
	payload := smoothBf16Tensor(1024*1024, 0x99)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	pattern, err := store.ParseAccessPattern("region:102400:2")
	if err != nil {
		t.Fatalf("pattern: %v", err)
	}
	plan, err := s.PlanTensor("bf16", shape, payload, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{
			TileShape:              []uint64{256, 1024},
			NStreams:               4,
			LambdaNS:               1000,
			AllowExperimentalModes: true,
			AccessPattern:          pattern,
		})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var mode18, mode17 *uint64
	for index := range plan.Candidates {
		switch plan.Candidates[index].Strategy {
		case store.TensorStrategyFloatTiledStreams:
			mode18 = plan.Candidates[index].EstimatedDecodeNS
		case store.TensorStrategyFloatTiled:
			mode17 = plan.Candidates[index].EstimatedDecodeNS
		}
	}
	if mode18 == nil {
		t.Fatal("mode-18 candidate missing")
	}
	// The measured row is separate from mode 17's; on this host it is slightly
	// more expensive, so the planner does not choose it.
	if mode17 != nil && *mode18 == *mode17 {
		t.Fatal("mode 18 reused mode 17's cost row")
	}
	if plan.Chosen == store.TensorStrategyFloatTiledStreams {
		t.Fatalf("planner chose mode 18 despite the measured row: %+v", plan.Candidates)
	}
}
