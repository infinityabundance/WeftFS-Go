package store_test

import (
	"strconv"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/store"
)

// TestEncodeCostModelMatchesRust pins the encode table to the Rust constants in
// src/cost_model.rs. Any drift fails here before it can reach a receipt.
func TestEncodeCostModelMatchesRust(t *testing.T) {
	want := map[store.EncodeClass]uint64{
		store.EncodeClassRaw:               2620000,
		store.EncodeClassZstd:              3090000,
		store.EncodeClassZstd19:            35087719,
		store.EncodeClassFloatTensor:       8806000,
		store.EncodeClassTensorSharded:     8806000,
		store.EncodeClassTensorTiled:       28633000,
		store.EncodeClassFloatTiled:        28633000,
		store.EncodeClassFloatTiledStreams: 37360000,
		store.EncodeClassWeightDelta:       17612000,
		store.EncodeClassSparseDelta:       17612000,
		store.EncodeClassSemanticDelta:     17612000,
	}
	if len(want) != len(store.EncodeClassAll) {
		t.Fatalf("expected %d encode classes, table has %d", len(store.EncodeClassAll), len(want))
	}
	for _, class := range store.EncodeClassAll {
		row, ok := store.EncodeCoefficientsTable[class]
		if !ok {
			t.Fatalf("missing encode row for %s", class)
		}
		if row.NSperMiB != want[class] {
			t.Fatalf("%s ns_per_mib = %d, want %d", class, row.NSperMiB, want[class])
		}
		if row.FixedNS != 0 {
			t.Fatalf("%s: encode rows have no fixed term", class)
		}
	}
	// The measured 3.25x mode-17/mode-9 write ratio.
	if store.EstimateEncodeNS(store.TensorStrategyFloatTiled, 1048576) <=
		store.EstimateEncodeNS(store.TensorStrategyFloatTensor, 1048576)*3 {
		t.Fatal("mode 17 encode must be more than 3x mode 9")
	}
}

// TestMode18FixedTermIsPositive pins the measured lower bound.
func TestMode18FixedTermIsPositive(t *testing.T) {
	// One tile of 114,688 canonical bytes is never cheaper than the measured
	// small-region floor plus its variable term.
	estimate := store.EstimateMode18NS(114688)
	if estimate <= 159477 {
		t.Fatalf("mode-18 one-tile estimate %d is not above the measured variable term", estimate)
	}
	// And the fixed term is not zero: a zero-byte estimate still costs the
	// floor.
	if store.EstimateMode18NS(0) != 96601 {
		t.Fatalf("mode-18 fixed term = %d, want 96601", store.EstimateMode18NS(0))
	}
}

// TestWriteTermGatesSingleReadTileSelection is the Go half of the Rust
// `write_term_prevents_a_single_read_selecting_the_tiled_form` test.
func TestWriteTermGatesSingleReadTileSelection(t *testing.T) {
	shape := []uint64{512, 512}
	payload := smoothBf16Tensor(512*512, 0x1234)
	dir := t.TempDir()
	s, err := store.Init(dir, v2Options())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	plan := func(reads uint64) store.TensorPlan {
		pattern, err := store.ParseAccessPattern("region:64:" + strconv.FormatUint(reads, 10))
		if err != nil {
			t.Fatalf("pattern: %v", err)
		}
		p, err := s.PlanTensor("bf16", shape, payload, store.RowMajorTensorLayout(), nil,
			store.TensorPlanOptions{
				TileShape:     []uint64{16, 32},
				LambdaNS:      1,
				AccessPattern: pattern,
			})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		return p
	}

	once := plan(1)
	if once.Chosen != store.TensorStrategyRaw {
		t.Fatalf("a single read chose %s, want raw: %+v", once.Chosen, once.Candidates)
	}
	if once.ChosenEstimatedEncodeNS == 0 {
		t.Fatal("the write term was not charged")
	}
	many := plan(1000)
	if many.Chosen != store.TensorStrategyFloatTiled {
		t.Fatalf("1,000 reads chose %s, want float-tiled: %+v", many.Chosen, many.Candidates)
	}
}
