// Command indexbench measures the on-disk selector index at 10k objects.
//
// It builds one synthetic store (10,000 objects, 10,000 relations in exactly
// one group commit), then measures in a single process:
//
//   - cold build of the index from replayed state;
//   - write-to-disk including the build;
//   - the first relation/tag query after a fresh read-only reopen with the
//     persisted segment present (must be DiskLoads=1/Builds=0);
//   - the same fresh reopen with the segment deleted (must be
//     DiskLoads=0/Builds=1).
//
// The store is synthetic and lives on the court's /tmp tmpfs. This is a
// host-local, warm-page-cache measurement, not a device, fleet, or
// production claim.
//
// Usage (inside the court):
//
//	go run ./cmd/indexbench --objects 10000 --trials 5 \
//	    --work-dir /tmp/weft-go-index-bench --out /work/bench/receipts/go-index-persist-<stamp>.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const relationFraction = 2 // half the object count, two edges each

func main() {
	objects := flag.Int("objects", 10_000, "object count")
	trials := flag.Int("trials", 5, "samples per measurement")
	workDir := flag.String("work-dir", "/tmp/weft-go-index-bench", "store directory")
	out := flag.String("out", "", "receipt path (optional)")
	flag.Parse()

	if *objects < 100 {
		fail("--objects must be at least 100")
	}
	if *trials < 1 {
		fail("--trials must be at least 1")
	}
	if err := os.RemoveAll(*workDir); err != nil {
		fail("clean work dir: %v", err)
	}
	if err := os.MkdirAll(*workDir, 0o755); err != nil {
		fail("work dir: %v", err)
	}

	started := time.Now()
	writer, _, linkTarget := buildStore(*workDir, *objects)
	head := writer.Head()
	root := writer.Root()
	principal := auth.New(0, 0, nil)
	lim := limits.Default()

	relationSelector := mustSelector("select relation(links, obj:" + linkTarget.Hex() + ")")
	tagSelector := mustSelector("select tag(\"group-0\")")
	path := store.BlobPath(root, store.BlobIndex, head)

	// (a) Cold build from replayed state.
	coldBuild := make([]float64, 0, *trials)
	for round := 0; round < *trials; round++ {
		elapsed, count := timed(func() int {
			return writer.BuildIndexForBench(writer.CurrentState())
		})
		if count != *objects+1 {
			fail("indexed objects = %d, want %d", count, *objects+1)
		}
		coldBuild = append(coldBuild, elapsed)
	}

	// (b) Write to disk: build + encode + atomic publication.
	writes := make([]float64, 0, *trials)
	var indexBytes uint64
	for round := 0; round < *trials; round++ {
		elapsed, size := timed(func() uint64 {
			written, err := writer.WriteIndexForBench()
			if err != nil {
				fail("write index: %v", err)
			}
			return written
		})
		indexBytes = size
		writes = append(writes, elapsed)
	}
	info, err := os.Stat(path)
	if err != nil {
		fail("segment stat: %v", err)
	}
	if uint64(info.Size()) != indexBytes {
		fail("reported size %d != file size %d", indexBytes, info.Size())
	}
	if err := writer.Close(); err != nil {
		fail("close writer: %v", err)
	}

	// Equivalence against the scan oracle while the persisted index is in use.
	reader, err := store.Open(root, store.ReadOnly)
	if err != nil {
		fail("reopen: %v", err)
	}
	for _, sel := range []*selector.Selector{relationSelector, tagSelector} {
		indexed, err := reader.Resolve(sel, nil, principal, lim)
		if err != nil {
			fail("indexed resolve: %v", err)
		}
		scan, err := store.ResolveState(sel, reader.Head(), reader.CurrentState(), principal, lim)
		if err != nil {
			fail("scan resolve: %v", err)
		}
		if indexed.MatchedCount != scan.MatchedCount || len(indexed.Results) != len(scan.Results) {
			fail("indexed result differs from scan: %d/%d vs %d/%d",
				indexed.MatchedCount, len(indexed.Results), scan.MatchedCount, len(scan.Results))
		}
		for position := range indexed.Results {
			if indexed.Results[position] != scan.Results[position] {
				fail("indexed result %d differs from scan", position)
			}
		}
	}
	reader.Close()

	// (c)/(d) Fresh reopen with the segment present.
	loadRelation := make([]float64, 0, *trials)
	loadTag := make([]float64, 0, *trials)
	for round := 0; round < *trials; round++ {
		elapsed, loads, builds, matched := firstQuery(root, relationSelector, principal, lim)
		if loads != 1 || builds != 0 {
			fail("persisted relation query did not load: loads=%d builds=%d", loads, builds)
		}
		if matched == 0 {
			fail("relation query matched nothing")
		}
		loadRelation = append(loadRelation, elapsed)
	}
	for round := 0; round < *trials; round++ {
		elapsed, loads, builds, matched := firstQuery(root, tagSelector, principal, lim)
		if loads != 1 || builds != 0 {
			fail("persisted tag query did not load: loads=%d builds=%d", loads, builds)
		}
		if matched == 0 {
			fail("tag query matched nothing")
		}
		loadTag = append(loadTag, elapsed)
	}

	// Same reopens with the segment deleted: an in-memory rebuild.
	if err := os.Remove(path); err != nil {
		fail("remove segment: %v", err)
	}
	rebuildRelation := make([]float64, 0, *trials)
	rebuildTag := make([]float64, 0, *trials)
	for round := 0; round < *trials; round++ {
		elapsed, loads, builds, matched := firstQuery(root, relationSelector, principal, lim)
		if loads != 0 || builds != 1 {
			fail("deleted relation query did not rebuild: loads=%d builds=%d", loads, builds)
		}
		if matched == 0 {
			fail("relation query matched nothing after rebuild")
		}
		rebuildRelation = append(rebuildRelation, elapsed)
	}
	for round := 0; round < *trials; round++ {
		elapsed, loads, builds, matched := firstQuery(root, tagSelector, principal, lim)
		if loads != 0 || builds != 1 {
			fail("deleted tag query did not rebuild: loads=%d builds=%d", loads, builds)
		}
		if matched == 0 {
			fail("tag query matched nothing after rebuild")
		}
		rebuildTag = append(rebuildTag, elapsed)
	}

	// Leave the store with its advisory segment present.
	restored, err := store.Open(root, store.ReadWrite)
	if err != nil {
		fail("reopen writable: %v", err)
	}
	if _, err := restored.WriteIndexForBench(); err != nil {
		fail("restore index: %v", err)
	}
	restored.Close()

	peak := peakRSSKiB()
	receipt := map[string]any{
		"schema": "weftfs-go.index-persist-bench.v1",
		"label": "synthetic, host-local, tmpfs, single host; fresh Go Store instance per sample; " +
			"OS page cache warm; not a device, fleet, or production claim",
		"generated_unix_secs": started.Unix(),
		"generated_utc":       started.UTC().Format("20060102T150405Z"),
		"revision":            env("WEFT_REPO_WEFTFS_GO"),
		"go_version":          runtime.Version(),
		"environment": map[string]string{
			"court_image":    env("WEFT_COURT_IMAGE"),
			"court_image_id": env("WEFT_COURT_IMAGE_ID"),
			"kernel":         env("WEFT_COURT_KERNEL"),
			"memory_limit":   env("WEFT_COURT_MEMORY"),
			"cpus":           env("WEFT_COURT_CPUS"),
		},
		"state": map[string]uint64{
			"objects":   uint64(*objects),
			"relations": uint64(*objects / relationFraction * 2),
		},
		"index": map[string]any{
			"format":     "WFX2",
			"version":    1,
			"file_bytes": indexBytes,
			"file":       path,
			"commit":     head.Hex(),
		},
		"measurements_ms": map[string]any{
			"trials": *trials,
			"cold_build_from_state": map[string]any{
				"median": median(coldBuild), "samples": coldBuild,
			},
			"write_to_disk_including_build": map[string]any{
				"median": median(writes), "samples": writes,
			},
			"first_relation_query_persisted": map[string]any{
				"median": median(loadRelation), "samples": loadRelation,
			},
			"first_tag_query_persisted": map[string]any{
				"median": median(loadTag), "samples": loadTag,
			},
			"first_relation_query_index_deleted": map[string]any{
				"median": median(rebuildRelation), "samples": rebuildRelation,
			},
			"first_tag_query_index_deleted": map[string]any{
				"median": median(rebuildTag), "samples": rebuildTag,
			},
		},
		"checks": map[string]any{
			"persisted_first_query_disk_loads": 1,
			"persisted_first_query_builds":     0,
			"deleted_first_query_disk_loads":   0,
			"deleted_first_query_builds":       1,
			"relation_matches_scan":            true,
			"tag_matches_scan":                 true,
		},
		"peak_rss_kib": peak,
	}

	fmt.Printf("indexbench: objects=%d relations=%d segment_bytes=%d peak_rss_kib=%d\n",
		*objects, *objects/relationFraction*2, indexBytes, peak)
	fmt.Printf("%-42s %12s\n", "measurement", "median_ms")
	table := []struct {
		name    string
		samples []float64
	}{
		{"cold_build_from_state", coldBuild},
		{"write_to_disk_including_build", writes},
		{"first_relation_query_persisted", loadRelation},
		{"first_tag_query_persisted", loadTag},
		{"first_relation_query_index_deleted", rebuildRelation},
		{"first_tag_query_index_deleted", rebuildTag},
	}
	for _, row := range table {
		fmt.Printf("%-42s %12.3f\n", row.name, median(row.samples))
	}
	fmt.Printf("%-42s %12.3f\n", "persisted/rebuild relation ratio",
		median(loadRelation)/median(rebuildRelation))
	fmt.Printf("%-42s %12.3f\n", "persisted/rebuild tag ratio",
		median(loadTag)/median(rebuildTag))

	if *out != "" {
		encoded, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			fail("encode receipt: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fail("receipt dir: %v", err)
		}
		if err := os.WriteFile(*out, encoded, 0o644); err != nil {
			fail("write receipt: %v", err)
		}
		fmt.Printf("receipt: %s\n", *out)
	}
}

func buildStore(dir string, objects int) (*store.Store, []model.Hash32, model.Hash32) {
	opts := store.DefaultOptions()
	opts.ChunkSize = 1024
	opts.CheckpointInterval = 256
	opts.GCGraceSecs = 0
	fixed := int64(1_767_225_600_000_000_000) // 2026-01-01T00:00:00Z
	opts.FixedTimestampNS = &fixed
	s, err := store.Init(dir, opts)
	if err != nil {
		fail("init: %v", err)
	}
	root := model.RootID

	// One group commit: 10,000 creates and 10,000 relations become exactly one
	// durable commit, so the benchmark measures index persistence rather than
	// ten thousand commit publications.
	if err := s.BeginGroup(); err != nil {
		fail("begin group: %v", err)
	}
	teams := []string{"red", "green", "blue"}
	ids := make([]model.Hash32, 0, objects)
	linkTarget := model.ZeroHash
	for index := 0; index < objects; index++ {
		mode, uid, gid := uint64(0o644), uint64(1000), uint64(1000)
		if index%7 == 0 {
			mode, uid, gid = 0o600, 2000, 2000
		}
		attrs := map[string]wcb.Value{
			"team":  wcb.TextValue(teams[index%len(teams)]),
			"score": wcb.U64Value(uint64(index % 100)),
			"nested": wcb.MapValue(map[string]wcb.Value{
				"a": wcb.U64Value(uint64(index % 7)),
			}),
		}
		id, err := s.CreateFileSeeded(root,
			[]byte("f"+strconv.Itoa(index)),
			[]byte("payload-"+strconv.Itoa(index)),
			mode, uid, gid, attrs,
			[]byte("index-bench-object-"+strconv.Itoa(index)))
		if err != nil {
			fail("create %d: %v", index, err)
		}
		ids = append(ids, id)
	}
	pairs := objects / relationFraction
	for index := 0; index < pairs; index++ {
		subject := ids[index]
		target := ids[(index*37+11)%objects]
		if index == 1 {
			linkTarget = target
		}
		if _, err := s.RelationAdd(subject, "links", model.ObjectTarget(target), nil, nil); err != nil {
			fail("link relation %d: %v", index, err)
		}
		if _, err := s.RelationAdd(subject, "tagged_as",
			model.ValueTarget(wcb.TextValue("group-"+strconv.Itoa(index%50))), nil, nil); err != nil {
			fail("tag relation %d: %v", index, err)
		}
	}
	if _, err := s.CommitGroup(); err != nil {
		fail("group commit: %v", err)
	}
	return s, ids, linkTarget
}

func firstQuery(root string, sel *selector.Selector, principal auth.Principal, lim limits.Limits) (float64, uint64, uint64, uint64) {
	reader, err := store.Open(root, store.ReadOnly)
	if err != nil {
		fail("reopen read-only: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	elapsed, matched := timed(func() uint64 {
		got, err := reader.Resolve(sel, nil, principal, lim)
		if err != nil {
			fail("resolve: %v", err)
		}
		return got.MatchedCount
	})
	stats := reader.IndexStats()
	return elapsed, stats.DiskLoads, stats.Builds, matched
}

func mustSelector(text string) *selector.Selector {
	parsed, err := selector.Parse(text)
	if err != nil {
		fail("selector %q: %v", text, err)
	}
	return parsed
}

func timed[T any](action func() T) (float64, T) {
	start := time.Now()
	value := action()
	return float64(time.Since(start).Microseconds()) / 1000.0, value
}

func median(values []float64) float64 {
	if len(values) == 0 {
		fail("median of no samples")
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	middle := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[middle-1] + sorted[middle]) / 2
	}
	return sorted[middle]
}

func peakRSSKiB() uint64 {
	text, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(text), "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "VmHWM:"))
		if len(fields) == 0 {
			return 0
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return value
	}
	return 0
}

func env(name string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return "unknown"
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "indexbench: "+format+"\n", args...)
	os.Exit(1)
}
