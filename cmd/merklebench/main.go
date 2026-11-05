// Command merklebench measures whole-file vs Merkle content identity writes.
//
// Workload: one 128 MiB file at 64 KiB chunks, then 500 deterministic random
// 4 KiB overwrites. Each identity runs in its own process so /proc/self/io and
// peak RSS describe one policy. Delegation is to the shipped Go store only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const (
	fileBytes      = 128 * 1024 * 1024
	chunkSize      = 64 * 1024
	overwriteBytes = 4 * 1024
	overwrites     = 500
)

type latencySummary struct {
	Count  int    `json:"count"`
	P50NS  uint64 `json:"p50_ns"`
	P95NS  uint64 `json:"p95_ns"`
	MaxNS  uint64 `json:"max_ns"`
	MeanNS uint64 `json:"mean_ns"`
}

func summarize(values []uint64) latencySummary {
	if len(values) == 0 {
		return latencySummary{}
	}
	sorted := append([]uint64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(p float64) uint64 {
		index := int(float64(len(sorted)-1)*p + 0.5)
		return sorted[index]
	}
	var sum uint64
	for _, value := range sorted {
		sum += value
	}
	return latencySummary{
		Count: len(sorted), P50NS: pick(0.50), P95NS: pick(0.95),
		MaxNS: sorted[len(sorted)-1], MeanNS: sum / uint64(len(sorted)),
	}
}

func nextRandom(state *uint64) uint64 {
	x := *state
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	*state = x
	return x * 0x2545F4914F6CDD1D
}

func largePattern(length, chunk int) []byte {
	out := make([]byte, length)
	value := byte(0)
	for start := 0; start < length; start += chunk {
		end := start + chunk
		if end > length {
			end = length
		}
		for i := start; i < end; i++ {
			out[i] = value
		}
		value++
	}
	return out
}

type procIO struct {
	rchar uint64
	wchar uint64
}

func readProcIO() procIO {
	var out procIO
	data, err := os.ReadFile("/proc/self/io")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		var value uint64
		if _, err := fmt.Sscanf(fields[1], "%d", &value); err != nil {
			continue
		}
		switch fields[0] {
		case "rchar:":
			out.rchar = value
		case "wchar:":
			out.wchar = value
		}
	}
	return out
}

func procStatusKiB(field string) *uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, field+":") {
			continue
		}
		text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, field+":")), "kB"))
		var value uint64
		if _, err := fmt.Sscanf(text, "%d", &value); err != nil {
			return nil
		}
		return &value
	}
	return nil
}

func resetPeakRSS() bool {
	return os.WriteFile("/proc/self/clear_refs", []byte("5\n"), 0o600) == nil
}

func run(identity model.ContentIdentity) (map[string]any, error) {
	dir, err := os.MkdirTemp("", "weft-merkle-bench-go-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	opts := store.DefaultOptions()
	opts.ChunkSize = chunkSize
	opts.GCGraceSecs = 0
	opts.ContentIdentity = identity
	s, err := store.Init(dir, opts)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	root, err := s.ResolvePath("/")
	if err != nil {
		return nil, err
	}
	data := largePattern(fileBytes, chunkSize)
	id, err := s.CreateFileSeeded(root, []byte("large.bin"), data, 0o644, 0, 0, nil, []byte("merkle-bench"))
	if err != nil {
		return nil, err
	}
	data = nil
	runtime.GC()
	record, err := s.ObjectMeta(id)
	if err != nil {
		return nil, err
	}
	first, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		return nil, err
	}
	resetPeakRSS()

	latencies := make([]uint64, 0, overwrites)
	state := uint64(0x9E3779B97F4A7C15)
	payload := make([]byte, overwriteBytes)
	for i := range payload {
		payload[i] = 0xA5
	}
	rngRange := uint64(fileBytes - overwriteBytes + 1)
	ioBefore := readProcIO()
	s.ResetWriteChunkReads()
	wall := time.Now()
	for i := 0; i < overwrites; i++ {
		offset := nextRandom(&state) % rngRange
		started := time.Now()
		if _, err := s.WriteFile(id, offset, payload); err != nil {
			return nil, err
		}
		latencies = append(latencies, uint64(time.Since(started).Nanoseconds()))
	}
	wallNS := uint64(time.Since(wall).Nanoseconds())
	ioAfter := readProcIO()
	chunkReads := s.WriteChunkReads()

	record, err = s.ObjectMeta(id)
	if err != nil {
		return nil, err
	}
	last, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		return nil, err
	}
	report, err := s.Verify(true)
	if err != nil {
		return nil, err
	}
	peak := procStatusKiB("VmHWM")
	return map[string]any{
		"harness":             "go",
		"revision":            envOr("WEFT_REPO_WEFTFS_GO", "unknown"),
		"identity":            store.ContentIdentityString(identity),
		"file_bytes":          fileBytes,
		"chunk_size":          chunkSize,
		"chunks":              len(first.Chunks),
		"overwrites":          overwrites,
		"overwrite_bytes":     overwriteBytes,
		"write_latency":       summarize(latencies),
		"write_loop_wall_ns":  wallNS,
		"bytes_read_rchar":    ioAfter.rchar - ioBefore.rchar,
		"bytes_written_wchar": ioAfter.wchar - ioBefore.wchar,
		"chunk_blobs_read":    chunkReads,
		"peak_rss_kib":        peak,
		"peak_rss_reset":      true,
		"root_hex":            last.ContentHash.Hex(),
		"root_changed":        first.ContentHash != last.ContentHash,
		"identity_preserved":  last.Identity == identity,
		"verify_ok":           report.OK,
		"verify_problems":     len(report.Problems),
	}, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func main() {
	identityFlag := flag.String("identity", "", "whole-file|merkle")
	out := flag.String("out", "", "output JSON path")
	flag.Parse()
	if *identityFlag == "" {
		fmt.Fprintln(os.Stderr, "--identity is required")
		os.Exit(64)
	}
	identity, err := store.ParseContentIdentity(*identityFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(64)
	}
	result, err := run(identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench failed: %v\n", err)
		os.Exit(1)
	}
	text, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "" {
		fmt.Println(string(text))
		return
	}
	if err := os.WriteFile(*out, text, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("go %s receipt: %s\n", *identityFlag, *out)
}
