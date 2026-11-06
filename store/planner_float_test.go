package store_test

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func plannerPayload(elements int, seed uint64) []byte {
	out := make([]byte, 0, elements*2)
	state := seed | 1
	for index := 0; index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		// Bounded f32 in [-0.5, 0.5), truncated to BF16.
		unit := float32(state>>40) / float32(uint64(1)<<24)
		value := (unit*2 - 1) * 0.5
		f := math.Float32bits(value)
		out = append(out, byte(f>>16), byte(f>>24))
	}
	return out
}

func plannerRandom(length int) []byte {
	out := make([]byte, length)
	state := uint64(0x0badf00ddeadbeef)
	for index := range out {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out[index] = byte(state >> 24)
	}
	return out
}

func openPlannerStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	options := store.DefaultOptions()
	options.GCGraceSecs = 0
	s, err := store.Init(dir, options)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return s, dir
}

func TestFloatTensorCandidateAndCostModel(t *testing.T) {
	s, _ := openPlannerStore(t)
	defer s.Close()
	shape := []uint64{1024, 512} // 1 MiB BF16
	weights := plannerPayload(512*1024, 0x9e3779b97f4a7c15)
	plan, err := s.PlanTensor("bf16", shape, weights, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Chosen != store.TensorStrategyFloatTensor {
		t.Fatalf("weight-like BF16 chose %s, want float-tensor", plan.Chosen)
	}
	var floatBytes, zstdBytes uint64
	for _, candidate := range plan.Candidates {
		switch candidate.Strategy {
		case store.TensorStrategyFloatTensor:
			if candidate.Applicable && candidate.PhysicalBytes != nil {
				floatBytes = *candidate.PhysicalBytes
			}
		case store.TensorStrategyZstd:
			if candidate.Applicable && candidate.PhysicalBytes != nil {
				zstdBytes = *candidate.PhysicalBytes
			}
		}
	}
	if floatBytes == 0 || floatBytes >= zstdBytes {
		t.Fatalf("mode 9 (%d) should beat zstd (%d)", floatBytes, zstdBytes)
	}

	random := plannerRandom(1024 * 1024)
	randomPlan, err := s.PlanTensor("bf16", shape, random, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{})
	if err != nil {
		t.Fatalf("random plan: %v", err)
	}
	if randomPlan.Chosen == store.TensorStrategyFloatTensor {
		t.Fatal("incompressible data must not select mode 9")
	}

	// Shared measured table values (must equal src/cost_model.rs).
	if got, want := store.EstimateDecodeNS(store.CostClassFloatTensor, 1<<20, store.CostModelMeasured), uint64(15_403_165); got != want {
		t.Fatalf("measured float-tensor estimate = %d, want %d", got, want)
	}
	if got, want := store.EstimateDecodeNS(store.CostClassZstd, 1<<20, store.CostModelDeclared), uint64(1_048_576+50_000); got != want {
		t.Fatalf("declared zstd estimate = %d, want %d", got, want)
	}

	// Lambda changes the choice: at 1 byte/ns the decode term dominates and raw
	// wins; the estimated cost is the shared table value.
	hot, err := s.PlanTensor("bf16", shape, weights, store.RowMajorTensorLayout(), nil,
		store.TensorPlanOptions{LambdaNS: 1})
	if err != nil {
		t.Fatalf("hot plan: %v", err)
	}
	if hot.Chosen != store.TensorStrategyRaw {
		t.Fatalf("lambda=1 chose %s, want raw", hot.Chosen)
	}
	if hot.ChosenEstimatedDecodeNS != store.EstimateDecodeNS(store.CostClassRaw, uint64(len(weights)), store.CostModelMeasured) {
		t.Fatal("chosen estimate is not the shared measured table value")
	}
}

func TestRebaseHotDeltaMatchesRustSemantics(t *testing.T) {
	s, dir := openPlannerStore(t)
	shape := []uint64{256, 512} // 256 KiB BF16
	elements := 256 * 512
	base := plannerPayload(elements, 0x51)
	target := append([]byte(nil), base...)
	for index := 0; index < elements; index += 4096 {
		target[index*2] ^= 1
	}
	floatHint := store.TensorStrategyFloatTensor
	baseID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("base"), "bf16", shape,
		base, store.RowMajorTensorLayout(), store.TensorWriteSpec{StrategyHint: &floatHint})
	if err != nil {
		t.Fatalf("write base: %v", err)
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		t.Fatalf("base meta: %v", err)
	}
	deltaHint := store.TensorStrategyWeightDelta
	deltaID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("instruct"), "bf16", shape,
		target, store.RowMajorTensorLayout(), store.TensorWriteSpec{
			StrategyHint: &deltaHint,
			Causal:       []model.Hash32{baseRecord.Version},
		})
	if err != nil {
		t.Fatalf("write delta: %v", err)
	}
	before, err := s.TensorMetadata(deltaID)
	if err != nil {
		t.Fatalf("delta meta: %v", err)
	}
	if before.Strategy != "weight-delta" {
		t.Fatalf("delta strategy = %s", before.Strategy)
	}
	beforeRecord, _ := s.ObjectMeta(deltaID)
	snapshot, err := s.SnapshotCreate("before-rebase")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for index := 0; index < 12; index++ {
		data, err := s.ReadTensor(deltaID)
		if err != nil || !bytes.Equal(data, target) {
			t.Fatalf("read %d: %v", index, err)
		}
	}
	if err := s.FlushAccessCounts(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if reads := s.AccessReads(deltaID); reads < 12 {
		t.Fatalf("reads = %d, want >= 12", reads)
	}
	options := store.DefaultRebaseOptions()
	options.ThresholdNS = 1_000_000
	options.DryRun = true
	dry, err := s.Rebase(model.RootID, options)
	if err != nil {
		t.Fatalf("dry rebase: %v", err)
	}
	var candidate *store.RebaseCandidate
	for index := range dry.Plan.Candidates {
		if dry.Plan.Candidates[index].Object == deltaID {
			candidate = &dry.Plan.Candidates[index]
		}
	}
	if candidate == nil {
		t.Fatalf("hot delta not selected: %+v", dry.Plan.Skipped)
	}
	if candidate.ToStrategy != store.TensorStrategyFloatTensor {
		t.Fatalf("rebase target = %s, want float-tensor", candidate.ToStrategy)
	}
	if len(dry.Applied) != 0 {
		t.Fatal("dry run must not write")
	}

	options.DryRun = false
	report, err := s.Rebase(model.RootID, options)
	if err != nil {
		t.Fatalf("rebase: %v", err)
	}
	if len(report.Applied) != 1 {
		t.Fatalf("applied = %d, want 1", len(report.Applied))
	}
	outcome := report.Applied[0]
	if outcome.NewVersion == beforeRecord.Version {
		t.Fatal("rebase must publish a new version")
	}
	after, err := s.TensorMetadata(deltaID)
	if err != nil {
		t.Fatalf("after meta: %v", err)
	}
	if after.Strategy != "float-tensor" || after.LogicalRoot != before.LogicalRoot {
		t.Fatalf("after = %+v", after)
	}
	if reads := s.AccessReads(deltaID); reads != 0 {
		t.Fatalf("counter not consumed by rebase: %d", reads)
	}

	// Provenance relation: subject -> value(hex id), predicate "provenance".
	record, ok := s.CurrentState().Objects[deltaID]
	if !ok {
		t.Fatal("object missing")
	}
	found := false
	for _, relation := range s.CurrentState().Relations {
		if relation.Subject == deltaID && relation.Predicate == "provenance" {
			found = true
			if relation.Kind != model.RelationValue {
				t.Fatalf("provenance relation kind = %v", relation.Kind)
			}
			if len(relation.Target.Value.Str) != 64 {
				t.Fatalf("provenance id = %q", relation.Target.Value.Str)
			}
		}
	}
	if !found {
		t.Fatal("no provenance relation was recorded")
	}
	if record.Content != outcome.Content {
		t.Fatalf("outcome content %s, record %s", outcome.Content.Hex(), record.Content.Hex())
	}

	// Idempotent: no intervening reads, second run writes nothing.
	second, err := s.Rebase(model.RootID, options)
	if err != nil {
		t.Fatalf("second rebase: %v", err)
	}
	if len(second.Applied) != 0 {
		t.Fatalf("second run applied %d", len(second.Applied))
	}
	for _, candidate := range second.Plan.Candidates {
		if candidate.Object == deltaID {
			t.Fatal("second run selected the rebased object")
		}
	}
	// Bytes and the pinned snapshot are unchanged by the rebase.
	data, err := s.ReadTensor(deltaID)
	if err != nil || !bytes.Equal(data, target) {
		t.Fatalf("post-rebase read: %v", err)
	}
	pinned, err := s.ReadObjectAt(&snapshot, deltaID)
	if err != nil || !bytes.Equal(pinned, target) {
		t.Fatalf("snapshot read: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Counters persist and the consumed count is not resurrected.
	reopened, err := store.Open(dir, store.ReadWrite)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if reads := reopened.AccessReads(deltaID); reads != 2 {
		t.Fatalf("persisted reads = %d, want 2 (the post-rebase reads)", reads)
	}
	// Clean up the store directory explicitly (t.TempDir handles it too).
	if _, err := os.Stat(filepath.Join(dir, "FORMAT")); err != nil {
		t.Fatalf("format marker: %v", err)
	}
}

// TestGoRebaseReadableByRust proves the Go-written rebase (mode 9 + provenance
// receipt) is accepted by the independent Rust implementation: full verify
// decodes the new representation and validates the receipt blob and relation.
func TestGoRebaseReadableByRust(t *testing.T) {
	bin := rustBinary(t)
	s, dir := openPlannerStore(t)
	shape := []uint64{256, 512}
	elements := 256 * 512
	base := plannerPayload(elements, 0x71)
	target := append([]byte(nil), base...)
	for index := 0; index < elements; index += 4096 {
		target[index*2] ^= 1
	}
	floatHint := store.TensorStrategyFloatTensor
	baseID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("base"), "bf16", shape,
		base, store.RowMajorTensorLayout(), store.TensorWriteSpec{StrategyHint: &floatHint})
	if err != nil {
		t.Fatalf("write base: %v", err)
	}
	baseRecord, _ := s.ObjectMeta(baseID)
	deltaHint := store.TensorStrategyWeightDelta
	deltaID, err := s.WriteTensorFileWithSpec(model.RootID, []byte("instruct"), "bf16", shape,
		target, store.RowMajorTensorLayout(), store.TensorWriteSpec{
			StrategyHint: &deltaHint,
			Causal:       []model.Hash32{baseRecord.Version},
		})
	if err != nil {
		t.Fatalf("write delta: %v", err)
	}
	for index := 0; index < 12; index++ {
		if _, err := s.ReadTensor(deltaID); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	options := store.DefaultRebaseOptions()
	options.ThresholdNS = 1_000_000
	options.DryRun = false
	report, err := s.Rebase(model.RootID, options)
	if err != nil {
		t.Fatalf("rebase: %v", err)
	}
	if len(report.Applied) != 1 {
		t.Fatalf("applied = %d", len(report.Applied))
	}
	outcome := report.Applied[0]
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	verify := runRust(t, bin, "--store", dir, "verify", "--full", "--json")
	if !strings.Contains(verify, `"ok": true`) {
		t.Fatalf("rust verify did not report ok: %s", verify)
	}
	show := runRust(t, bin, "--store", dir, "provenance", "show", deltaID.Hex(), "--json")
	if !strings.Contains(show, outcome.ProvenanceID.Hex()) {
		t.Fatalf("rust did not read the Go provenance receipt:\n%s", show)
	}
}
