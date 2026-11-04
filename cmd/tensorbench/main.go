// Command tensorbench measures the Go tensor representation path in a court.
//
// Workload: an 8 MiB bf16 pair (2048x2048) with 1% of elements changed. It
// reports encode (planner) and decode medians, the full tensor write median,
// a 1 MiB region read median, and the delta frame size against the independent
// frame size. It writes one JSON receipt and prints only its path.
//
// The receipt is evidence for one synthetic workload on one host/court. It is
// not a fleet, hardware, or production-data claim.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const (
	rows = 2048
	cols = 2048
)

func main() {
	outDir := flag.String("dir", "bench/receipts", "receipt directory")
	prefix := flag.String("prefix", "go-tensor", "receipt filename prefix")
	reps := flag.Int("iterations", 5, "measured iterations")
	flag.Parse()
	if err := run(*outDir, *prefix, *reps); err != nil {
		fmt.Fprintln(os.Stderr, "tensorbench:", err)
		os.Exit(1)
	}
}

func smoothBf16(elements int) []byte {
	out := make([]byte, 0, elements*2)
	state := uint64(0x5eed)
	for index := 0; index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		low := (uint16(index) * 37) & 0x3ff
		word := uint16(0x3f00|low) ^ (uint16(state) & 0x3f)
		out = append(out, byte(word), byte(word>>8))
	}
	return out
}

func nudge(data []byte, changed int) []byte {
	out := append([]byte(nil), data...)
	elements := len(out) / 2
	stride := elements / changed
	if stride < 1 {
		stride = 1
	}
	done := 0
	for index := 0; index < elements && done < changed; index += stride {
		out[index*2] ^= 0x01
		done++
	}
	return out
}

func median(samples []int64) int64 {
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted)%2 == 1 {
		return sorted[len(sorted)/2]
	}
	return (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
}

func frameBytes(dir string, s *store.Store, path string) (uint64, error) {
	id, err := s.ResolvePath(path)
	if err != nil {
		return 0, fmt.Errorf("resolve %s: %w", path, err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		return 0, fmt.Errorf("meta %s: %w", path, err)
	}
	manifest, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		return 0, fmt.Errorf("manifest %s: %w", path, err)
	}
	if manifest.Representation == nil || manifest.Representation.Frame == nil {
		return 0, fmt.Errorf("%s has no frame", path)
	}
	info, err := os.Stat(store.ManifestPath(dir, *manifest.Representation.Frame))
	if err != nil {
		return 0, fmt.Errorf("frame stat %s: %w", path, err)
	}
	return uint64(info.Size()), nil
}

func env(name string) string { return os.Getenv(name) }

func run(outDir, prefix string, reps int) error {
	if reps < 1 {
		reps = 1
	}
	shape := []uint64{rows, cols}
	elements := rows * cols
	base := smoothBf16(elements)
	changedElements := elements / 100
	derived := nudge(base, changedElements)

	dir, err := os.MkdirTemp("", "weft-tensorbench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	opts := store.DefaultOptions()
	opts.Representation = store.RepresentationModeCodecAuto
	opts.CheckpointInterval = 0
	opts.GCGraceSecs = 0
	s, err := store.Init(dir, opts)
	if err != nil {
		return err
	}

	baseID, err := s.WriteTensorFile(model.RootID, []byte("pair-base.bin"), "bf16", shape,
		base, store.RowMajorTensorLayout(), nil)
	if err != nil {
		return err
	}
	baseRecord, err := s.ObjectMeta(baseID)
	if err != nil {
		return err
	}
	causal := []model.Hash32{baseRecord.Version}

	// Encode (planner) median: prices every applicable candidate, including the
	// weight-delta against the causal base.
	encodeSamples := make([]int64, 0, reps)
	var plan store.TensorPlan
	for index := 0; index < reps; index++ {
		start := time.Now()
		plan, err = s.PlanTensor("bf16", shape, derived, store.RowMajorTensorLayout(), causal,
			store.TensorPlanOptions{})
		encodeSamples = append(encodeSamples, time.Since(start).Nanoseconds())
		if err != nil {
			return err
		}
	}
	if plan.Chosen != store.TensorStrategyWeightDelta {
		return fmt.Errorf("planner chose %s, want weight-delta", plan.Chosen)
	}

	// Full write median (plan + encode + commit + fsync).
	writeSamples := make([]int64, 0, reps)
	var derivedID model.Hash32
	for index := 0; index < reps; index++ {
		name := fmt.Sprintf("pair-derived-%02d.bin", index)
		start := time.Now()
		derivedID, err = s.WriteTensorFileWithSpec(model.RootID, []byte(name), "bf16", shape,
			derived, store.RowMajorTensorLayout(), store.TensorWriteSpec{Causal: causal})
		writeSamples = append(writeSamples, time.Since(start).Nanoseconds())
		if err != nil {
			return err
		}
	}
	if err := s.Close(); err != nil {
		return err
	}
	// Reopen read-only so decode is measured on the persisted path.
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer reader.Close()

	decodeSamples := make([]int64, 0, reps)
	for index := 0; index < reps; index++ {
		start := time.Now()
		bytesValue, err := reader.ReadTensor(derivedID)
		decodeSamples = append(decodeSamples, time.Since(start).Nanoseconds())
		if err != nil {
			return err
		}
		if len(bytesValue) != len(derived) {
			return fmt.Errorf("decoded %d bytes, want %d", len(bytesValue), len(derived))
		}
	}

	// 1 MiB region: 256 rows x 2048 columns x 2 bytes.
	region := tensor.NewRegion([]uint64{1024, 0}, []uint64{1280, 2048})
	regionSamples := make([]int64, 0, reps)
	var regionBytes uint64
	for index := 0; index < reps; index++ {
		start := time.Now()
		read, err := reader.ReadTensorRegion(derivedID, region)
		regionSamples = append(regionSamples, time.Since(start).Nanoseconds())
		if err != nil {
			return err
		}
		regionBytes = uint64(len(read.Bytes))
	}
	if regionBytes != 1024*1024 {
		return fmt.Errorf("region read %d bytes, want 1 MiB", regionBytes)
	}

	verifyReport, err := reader.Verify(true)
	if err != nil {
		return err
	}
	if !verifyReport.OK {
		return fmt.Errorf("verify failed: %+v", verifyReport.Problems)
	}

	independentBytes, err := frameBytes(dir, reader, "/pair-base.bin")
	if err != nil {
		return err
	}
	deltaPath := fmt.Sprintf("/pair-derived-%02d.bin", reps-1)
	deltaBytes, err := frameBytes(dir, reader, deltaPath)
	if err != nil {
		return err
	}
	meta, err := reader.TensorMetadata(derivedID)
	if err != nil {
		return err
	}

	candidates := make([]map[string]any, 0, len(plan.Candidates))
	for _, candidate := range plan.Candidates {
		item := map[string]any{
			"strategy":   candidate.Strategy.String(),
			"applicable": candidate.Applicable,
			"detail":     candidate.Detail,
		}
		if candidate.PhysicalBytes != nil {
			item["physical_bytes"] = *candidate.PhysicalBytes
		}
		if candidate.EstimatedDecodeNS != nil {
			item["estimated_decode_ns"] = *candidate.EstimatedDecodeNS
		}
		if candidate.Cost != nil {
			item["cost_hi"] = candidate.Cost.Hi
			item["cost_lo"] = candidate.Cost.Lo
		}
		if candidate.Dependency != nil {
			item["dependency"] = candidate.Dependency.Hex()
		}
		candidates = append(candidates, item)
	}

	now := time.Now().UTC()
	receipt := map[string]any{
		"receipt":       "go-tensor",
		"generated_utc": now.Format(time.RFC3339),
		"label": "single-host Go court, synthetic bf16 pair, local store; " +
			"not a fleet, hardware, or production-data claim",
		"harness": "WeftFS-Go/cmd/tensorbench",
		"revisions": map[string]string{
			"weftfs":       env("WEFT_REPO_WEFTFS"),
			"weftfs_go":    env("WEFT_REPO_WEFTFS_GO"),
			"weftcodec":    env("WEFT_REPO_WEFTCODEC"),
			"weftcodec_go": env("WEFT_REPO_WEFTCODEC_GO"),
		},
		"court": map[string]string{
			"image":         env("WEFT_COURT_IMAGE"),
			"image_id":      env("WEFT_COURT_IMAGE_ID"),
			"kernel":        env("WEFT_COURT_KERNEL"),
			"memory":        env("WEFT_COURT_MEMORY"),
			"cpus":          env("WEFT_COURT_CPUS"),
			"pids":          env("WEFT_COURT_PIDS"),
			"docker_server": env("WEFT_DOCKER_SERVER"),
			"docker_client": env("WEFT_DOCKER_CLIENT"),
		},
		"workload": map[string]any{
			"dtype":            "bf16",
			"shape":            shape,
			"element_bytes":    2,
			"bytes":            len(derived),
			"elements":         elements,
			"changed_elements": changedElements,
			"changed_fraction": float64(changedElements) / float64(elements),
			"iterations":       reps,
			"independent":      "/pair-base.bin",
			"derived":          deltaPath,
			"derived_strategy": meta.Strategy,
			"logical_root":     meta.LogicalRoot.Hex(),
		},
		"plan": map[string]any{
			"chosen":                plan.Chosen.String(),
			"chosen_physical_bytes": plan.ChosenPhysicalBytes,
			"runner_up":             runnerUp(plan.RunnerUp),
			"candidates":            candidates,
		},
		"timings_ns": map[string]any{
			"encode":      samples(encodeSamples),
			"write":       samples(writeSamples),
			"decode":      samples(decodeSamples),
			"region_read": samples(regionSamples),
		},
		"storage": map[string]any{
			"independent_frame_bytes": independentBytes,
			"delta_frame_bytes":       deltaBytes,
			"delta_over_independent":  float64(deltaBytes) / float64(independentBytes),
			"region_bytes":            regionBytes,
		},
		"verify": map[string]any{
			"ok":                      verifyReport.OK,
			"checked_representations": verifyReport.CheckedRepresentations,
		},
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(outDir, prefix+"-"+now.Format("20060102T150405Z")+".json")
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}

func samples(values []int64) map[string]any {
	return map[string]any{
		"median":  median(values),
		"samples": values,
	}
}

func runnerUp(strategy *store.TensorStrategy) any {
	if strategy == nil {
		return nil
	}
	return strategy.String()
}
