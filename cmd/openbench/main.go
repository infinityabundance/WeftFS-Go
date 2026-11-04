// Command openbench measures the Go store's bounded open against the forced
// full commit-directory replay.
//
// It builds one deterministic store with tiny, identical object payloads
// (content blobs deduplicate; the commit chain is still real) and checkpoint
// interval 256, then times store.Open(ReadOnly) and store.OpenFullScanForBench
// on the same directory. Every timing is followed by a state comparison, so a
// faster open can never be reported if it recovered a different state.
//
// The store is synthetic and lives on the court's /tmp tmpfs inside the Docker
// court. This is not a device, fleet, power-loss, or production claim.
//
// Usage (inside the court):
//
//	go run ./cmd/openbench --generations 100000 --samples 5 \
//	    --work-dir /tmp/weft-go-open-bench --out /work/bench/receipts/go-fast-open-<stamp>.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const checkpointInterval = 256

// payload is deliberately constant: content blobs and manifests deduplicate, so
// the per-generation on-disk cost is one commit file. The replay work is still
// one real commit per generation.
var payload = []byte("weft go open bench object\n")

func options() store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = 1024
	opts.CheckpointInterval = checkpointInterval
	opts.GCGraceSecs = 0
	fixed := int64(1_767_225_600_000_000_000) // 2026-01-01T00:00:00Z
	opts.FixedTimestampNS = &fixed
	return opts
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "openbench: "+format+"\n", args...)
	os.Exit(1)
}

// buildStore creates `generations` committed generations over eight fixed
// files and returns the writer's final generation.
func buildStore(workDir string, generations uint64) uint64 {
	if err := os.RemoveAll(workDir); err != nil {
		fail("clear benchmark store: %v", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		fail("create benchmark dir: %v", err)
	}
	s, err := store.Init(workDir, options())
	if err != nil {
		fail("init benchmark store: %v", err)
	}
	ids := make([]model.Hash32, 0, 8)
	for index := 0; index < 8; index++ {
		id, err := s.CreateFile(model.RootID, []byte("f"+model.FormatU64(uint64(index))),
			[]byte("seed body "+model.FormatU64(uint64(index))), 0o644, 0, 0, nil)
		if err != nil {
			fail("create file: %v", err)
		}
		ids = append(ids, id)
	}
	if _, err := s.RelationAdd(ids[0], "links",
		model.ValueTarget(wcb.TextValue("target")), nil, nil); err != nil {
		fail("relation: %v", err)
	}
	if _, err := s.SnapshotCreate("initial"); err != nil {
		fail("snapshot: %v", err)
	}
	started := time.Now()
	for s.Generation() < generations {
		index := int(s.Generation() % uint64(len(ids)))
		if _, err := s.WriteFile(ids[index], 0, payload); err != nil {
			fail("write generation %d: %v", s.Generation()+1, err)
		}
	}
	if s.Generation() != generations {
		fail("built generation %d, want %d", s.Generation(), generations)
	}
	built := s.Generation()
	if err := s.Close(); err != nil {
		fail("close writer: %v", err)
	}
	fmt.Fprintf(os.Stderr, "openbench: built %d generations in %s\n", built,
		time.Since(started).Round(time.Millisecond))
	return built
}

type sampleResult struct {
	millis float64
	reads  uint64
}

func sample(dir string, fullScan bool) sampleResult {
	store.ResetCommitFileReads()
	started := time.Now()
	var s *store.Store
	var err error
	if fullScan {
		s, err = store.OpenFullScanForBench(dir, store.ReadOnly)
	} else {
		s, err = store.Open(dir, store.ReadOnly)
	}
	if err != nil {
		fail("open: %v", err)
	}
	millis := float64(time.Since(started).Nanoseconds()) / 1e6
	reads := store.CommitFileReads()
	if err := s.Close(); err != nil {
		fail("close: %v", err)
	}
	return sampleResult{millis: millis, reads: reads}
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[middle-1] + sorted[middle]) / 2
	}
	return sorted[middle]
}

// p95 is a nearest-rank 95th percentile.
func p95(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	rank := (len(sorted)*95+99)/100 - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func maxU64(values []uint64) uint64 {
	var best uint64
	for _, value := range values {
		if value > best {
			best = value
		}
	}
	return best
}

func peakRSSKiB() uint64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range splitLines(string(status)) {
		const prefix = "VmHWM:"
		if len(line) >= len(prefix) && line[:len(prefix)] == prefix {
			var value uint64
			if _, err := fmt.Sscanf(line[len(prefix):], "%d", &value); err == nil {
				return value
			}
		}
	}
	return 0
}

func splitLines(text string) []string {
	lines := make([]string, 0, 64)
	start := 0
	for index := 0; index < len(text); index++ {
		if text[index] == '\n' {
			lines = append(lines, text[start:index])
			start = index + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// storeBytes reports apparent and filesystem-allocated bytes under dir.
func storeBytes(dir string) (apparent, allocated uint64) {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		apparent += uint64(info.Size())
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			allocated += uint64(stat.Blocks) * 512
		}
		return nil
	})
	if err != nil {
		fail("walk store: %v", err)
	}
	return apparent, allocated
}

func env(name string) string { return os.Getenv(name) }

func main() {
	generations := uint64(100_000)
	samples := 5
	workDir := "/tmp/weft-go-open-bench"
	outPath := ""
	flag.Uint64Var(&generations, "generations", generations, "commit generations to build")
	flag.IntVar(&samples, "samples", samples, "timed opens per path")
	flag.StringVar(&workDir, "work-dir", workDir, "store directory")
	flag.StringVar(&outPath, "out", outPath, "receipt path (default bench/receipts/go-fast-open-<stamp>.json)")
	flag.Parse()
	if samples <= 0 {
		fail("need at least one sample")
	}
	if outPath == "" {
		outPath = filepath.Join("bench", "receipts",
			"go-fast-open-"+time.Now().UTC().Format("20060102T150405Z")+".json")
	}

	built := buildStore(workDir, generations)
	apparent, allocated := storeBytes(workDir)

	// Warm both paths once, unmeasured, so the page cache is populated the same
	// way for every sample.
	_ = sample(workDir, false)
	_ = sample(workDir, true)

	fastMillis := make([]float64, 0, samples)
	fastReads := make([]uint64, 0, samples)
	for index := 0; index < samples; index++ {
		result := sample(workDir, false)
		fastMillis = append(fastMillis, result.millis)
		fastReads = append(fastReads, result.reads)
	}
	fullMillis := make([]float64, 0, samples)
	fullReads := make([]uint64, 0, samples)
	for index := 0; index < samples; index++ {
		result := sample(workDir, true)
		fullMillis = append(fullMillis, result.millis)
		fullReads = append(fullReads, result.reads)
	}

	// Both paths must recover the same state.
	fastStore, err := store.Open(workDir, store.ReadOnly)
	if err != nil {
		fail("fast state open: %v", err)
	}
	fastState := fastStore.CurrentState().Clone()
	fastHead := fastStore.SnapshotRoot()
	fastGeneration := fastStore.Generation()
	fastNotes := fastStore.RecoveryNotes()
	if err := fastStore.Close(); err != nil {
		fail("close fast state open: %v", err)
	}
	fullStore, err := store.OpenFullScanForBench(workDir, store.ReadOnly)
	if err != nil {
		fail("full state open: %v", err)
	}
	fullState := fullStore.CurrentState().Clone()
	fullHead := fullStore.SnapshotRoot()
	fullGeneration := fullStore.Generation()
	if err := fullStore.Close(); err != nil {
		fail("close full state open: %v", err)
	}

	stateMatch := fastGeneration == fullGeneration &&
		fastHead == fullHead &&
		reflect.DeepEqual(fastState.Objects, fullState.Objects) &&
		reflect.DeepEqual(fastState.Entries, fullState.Entries) &&
		reflect.DeepEqual(fastState.Relations, fullState.Relations) &&
		reflect.DeepEqual(fastState.Snapshots, fullState.Snapshots) &&
		reflect.DeepEqual(fastState.Tips, fullState.Tips)
	if !stateMatch {
		fail("fast and full opens recovered different states")
	}
	if fastGeneration != built {
		fail("recovered generation %d, want %d", fastGeneration, built)
	}

	receipt := map[string]any{
		"schema": "weft-go-open-bench-v1",
		"kind":   "go-bounded-open-bench",
		"label": "Local synthetic store on the Docker court's /tmp tmpfs; single host, " +
			"synthetic fixture, not a device, fleet, power-loss, or production claim.",
		"environment": map[string]any{
			"kernel":                 env("WEFT_COURT_KERNEL"),
			"court_image":            env("WEFT_COURT_IMAGE"),
			"court_image_id":         env("WEFT_COURT_IMAGE_ID"),
			"court_memory":           env("WEFT_COURT_MEMORY"),
			"court_cpus":             env("WEFT_COURT_CPUS"),
			"court_pids":             env("WEFT_COURT_PIDS"),
			"docker_server":          env("WEFT_DOCKER_SERVER"),
			"docker_client":          env("WEFT_DOCKER_CLIENT"),
			"go_version":             runtime.Version(),
			"go_maxprocs":            runtime.GOMAXPROCS(0),
			"revision_weftfs_parent": env("WEFT_REPO_WEFTFS"),
			"revision_weftfs_go":     env("WEFT_REPO_WEFTFS_GO"),
		},
		"work_dir":              workDir,
		"generations":           built,
		"checkpoint_interval":   checkpointInterval,
		"chunk_size":            uint64(1024),
		"objects":               len(fastState.Objects),
		"entries":               len(fastState.Entries),
		"relations":             len(fastState.Relations),
		"snapshots":             len(fastState.Snapshots),
		"tips":                  len(fastState.Tips),
		"recovered_generation":  fastGeneration,
		"store_apparent_bytes":  apparent,
		"store_allocated_bytes": allocated,
		"samples":               samples,
		"state_match":           stateMatch,
		"fast": map[string]any{
			"path":              "store.Open(ReadOnly) - generation-addressed bounded replay",
			"commit_file_reads": fastReads,
			"wall_ms":           fastMillis,
			"median_ms":         median(fastMillis),
			"p95_ms":            p95(fastMillis),
		},
		"full": map[string]any{
			"path":              "store.OpenFullScanForBench(ReadOnly) - full commit-directory replay",
			"commit_file_reads": fullReads,
			"wall_ms":           fullMillis,
			"median_ms":         median(fullMillis),
			"p95_ms":            p95(fullMillis),
		},
		"peak_rss_kib": peakRSSKiB(),
		"notes": []string{
			"The store is built once, sequentially, in this process under /tmp (tmpfs, 1 GiB) and is read from the page cache.",
			"The object payload is identical for every generation, so content blobs and manifests deduplicate; the commit chain and replay work are real (one commit file per generation).",
			"Commit-file reads are counted by store.CommitFileReads(), incremented once per LoadCommitFile call.",
			"The fast path is ReadOnly and directory-free: it starts at the highest published superblock generation and walks parent links down to the nearest verified checkpoint.",
			"The full path is the pre-optimisation behaviour: it enumerates the commit directory and decodes every commit file.",
			"Fast-path recovery notes for this store: " + fmt.Sprint(fastNotes),
			"Store bytes are apparent and filesystem-allocated (stat blocks*512); tmpfs rounds every file up to a page.",
			"No device-level, fsync, power-loss, fleet, or production claim is made.",
		},
	}

	text, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fail("serialize receipt: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fail("create receipt dir: %v", err)
	}
	if err := os.WriteFile(outPath, append(text, '\n'), 0o644); err != nil {
		fail("write receipt: %v", err)
	}
	fmt.Fprintf(os.Stderr, "openbench: wrote %s\n", outPath)
	fmt.Printf("generations %d: fast median %.2f ms (p95 %.2f ms, %d reads), full median %.2f ms (p95 %.2f ms, %d reads)\n",
		built,
		median(fastMillis), p95(fastMillis), maxU64(fastReads),
		median(fullMillis), p95(fullMillis), maxU64(fullReads))
}
