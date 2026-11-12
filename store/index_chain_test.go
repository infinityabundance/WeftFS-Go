package store_test

// WFX3 incremental index-chain tests: chain load, partial/forged rejection,
// compaction, GC, snapshot pinning, and bounds. See
// docs/INDEX-AMPLIFICATION.md.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	weftindex "github.com/infinityabundance/WeftFS-Go/index"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
)

func chainOptions() store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = 1024
	opts.CheckpointInterval = 256
	opts.GCGraceSecs = 0
	fixed := int64(1_700_000_000_000_000_000)
	opts.FixedTimestampNS = &fixed
	return opts
}

func writeChainFiles(t *testing.T, s *store.Store, count int, prefix string) {
	t.Helper()
	for i := 0; i < count; i++ {
		attrs := map[string]wcb.Value{
			"team":  wcb.TextValue(map[bool]string{true: "red", false: "blue"}[i%2 == 0]),
			"score": wcb.U64Value(uint64(i % 7)),
		}
		id, err := s.CreateFileSeeded(model.RootID, []byte(prefix+string(rune('a'+i))),
			[]byte("body-"+prefix), 0o644, 0, 0, attrs, []byte("seed-"+prefix+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("create %s%d: %v", prefix, i, err)
		}
		if i%3 == 0 {
			if _, err := s.RelationAdd(id, "tagged_as",
				model.RelationTarget{Value: wcb.TextValue("alpha")}, nil, nil); err != nil {
				t.Fatalf("tag %s%d: %v", prefix, i, err)
			}
		}
	}
}

func compareQueryResults(t *testing.T, left, right *store.Store, label string) {
	t.Helper()
	principal := auth.New(0, 0, nil)
	lim := limits.Default()
	for _, text := range []string{
		"select true",
		"select attrs.team == \"red\"",
		"select attrs.score > 3",
		"select tag(\"alpha\")",
	} {
		query, err := selector.Parse(text)
		if err != nil {
			t.Fatalf("parse %q: %v", text, err)
		}
		a, err := left.Resolve(query, nil, principal, lim)
		if err != nil {
			t.Fatalf("%s left %q: %v", label, text, err)
		}
		b, err := right.Resolve(query, nil, principal, lim)
		if err != nil {
			t.Fatalf("%s right %q: %v", label, text, err)
		}
		if a.MatchedCount != b.MatchedCount {
			t.Fatalf("%s %q: matched %d vs %d", label, text, a.MatchedCount, b.MatchedCount)
		}
		leftIDs := make([]string, 0, len(a.Results))
		rightIDs := make([]string, 0, len(b.Results))
		for _, item := range a.Results {
			leftIDs = append(leftIDs, item.ObjectID.Hex())
		}
		for _, item := range b.Results {
			rightIDs = append(rightIDs, item.ObjectID.Hex())
		}
		sort.Strings(leftIDs)
		sort.Strings(rightIDs)
		if len(leftIDs) != len(rightIDs) {
			t.Fatalf("%s %q: result count differs", label, text)
		}
		for i := range leftIDs {
			if leftIDs[i] != rightIDs[i] {
				t.Fatalf("%s %q: object ids differ", label, text)
			}
		}
	}
}

func TestIncrementalIndexChainAnswersLikeFullSegments(t *testing.T) {
	chainDir, fullDir := t.TempDir(), t.TempDir()
	chain, err := store.Init(chainDir, chainOptions())
	if err != nil {
		t.Fatalf("init chain: %v", err)
	}
	fullOpts := chainOptions()
	fullOpts.NoIncrementalIndex = true
	full, err := store.Init(fullDir, fullOpts)
	if err != nil {
		t.Fatalf("init full: %v", err)
	}
	writeChainFiles(t, chain, 16, "f")
	writeChainFiles(t, full, 16, "f")

	kind, depth, err := chain.IndexHeadChain()
	if err != nil || kind != "delta" || depth == 0 {
		t.Fatalf("chain head = %q depth=%d err=%v", kind, depth, err)
	}
	kind, depth, err = full.IndexHeadChain()
	if err != nil || kind != "full" || depth != 0 {
		t.Fatalf("full head = %q depth=%d err=%v", kind, depth, err)
	}
	if err := chain.Close(); err != nil {
		t.Fatalf("close chain: %v", err)
	}
	if err := full.Close(); err != nil {
		t.Fatalf("close full: %v", err)
	}

	chainReader, err := store.Open(chainDir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open chain: %v", err)
	}
	defer chainReader.Close()
	fullReader, err := store.Open(fullDir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open full: %v", err)
	}
	defer fullReader.Close()
	chainReader.ResetIndexStats()
	fullReader.ResetIndexStats()
	compareQueryResults(t, chainReader, fullReader, "chain vs full")
	stats := chainReader.IndexStats()
	if stats.DiskLoads == 0 || stats.Builds != 0 || stats.Rejects != 0 {
		t.Fatalf("chain must load without rebuild: %+v", stats)
	}
}

func indexFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	entries, err := os.ReadDir(filepath.Join(dir, "indexes"))
	if err != nil {
		t.Fatalf("read index dir: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, "indexes", entry.Name()))
		if err != nil {
			t.Fatalf("read index subdir: %v", err)
		}
		for _, file := range files {
			out = append(out, filepath.Join(dir, "indexes", entry.Name(), file.Name()))
		}
	}
	return out
}

func TestPartialIndexChainIsRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, chainOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	writeChainFiles(t, s, 8, "f")
	head := s.Head()
	if _, depth, _ := s.IndexHeadChain(); depth == 0 {
		t.Fatal("expected a delta chain")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	headRel := store.BlobPath(dir, store.BlobIndex, head)
	for _, file := range indexFiles(t, dir) {
		if file != headRel {
			if err := os.Remove(file); err != nil {
				t.Fatalf("remove %s: %v", file, err)
			}
		}
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	query, _ := selector.Parse("select tag(\"alpha\")")
	if _, err := reader.Resolve(query, nil, auth.New(0, 0, nil), limits.Default()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads != 0 || stats.Rejects == 0 || stats.Builds == 0 {
		t.Fatalf("a partial chain must rebuild: %+v", stats)
	}
}

func TestForgedIndexChainRootIsRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, chainOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	writeChainFiles(t, s, 6, "f")
	head := s.Head()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	path := store.BlobPath(dir, store.BlobIndex, head)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data[0:4]) != weftindex.MagicV3 || data[8] != 1 {
		t.Fatalf("expected a WFX3 delta head")
	}
	// Change the base id and recompute the segment digest. The segment is
	// self-consistent; the commit's chain root is the only refutation.
	copy(data[25:57], bytes.Repeat([]byte{0x5a}, 32))
	bodyLen := len(data) - 32
	digest := hash.Domain(weftindex.DomainV3, data[:bodyLen])
	copy(data[bodyLen:], digest[:])
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	query, _ := selector.Parse("select tag(\"alpha\")")
	if _, err := reader.Resolve(query, nil, auth.New(0, 0, nil), limits.Default()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads != 0 || stats.Rejects == 0 {
		t.Fatalf("a forged chain must be rejected: %+v", stats)
	}
}

func TestCompactionAndGcDropTheChain(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, chainOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	writeChainFiles(t, s, 10, "f")
	if _, depth, _ := s.IndexHeadChain(); depth == 0 {
		t.Fatal("expected a chain before compaction")
	}
	oldHead := s.Head()
	newHead, err := s.CompactIndex()
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	if kind, depth, _ := s.IndexHeadChain(); kind != "full" || depth != 0 {
		t.Fatalf("compaction did not write a full segment: %q %d", kind, depth)
	}
	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if report.DeletedIndexBytes == 0 {
		t.Fatalf("GC must drop the old chain: %+v", report)
	}
	if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, oldHead)); !os.IsNotExist(err) {
		t.Fatalf("old head segment still exists: %v", err)
	}
	if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, newHead)); err != nil {
		t.Fatalf("new head segment missing: %v", err)
	}
}

func TestSnapshotPinsItsChain(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, chainOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	writeChainFiles(t, s, 6, "f")
	pinned, err := s.SnapshotCreate("pinned")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	writeChainFiles(t, s, 6, "g")
	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(report.Problems) != 0 {
		t.Fatalf("gc problems: %v", report.Problems)
	}
	if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, pinned)); err != nil {
		t.Fatalf("pinned segment missing: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	query, _ := selector.Parse("select tag(\"alpha\")")
	if _, err := reader.Resolve(query, &pinned, auth.New(0, 0, nil), limits.Default()); err != nil {
		t.Fatalf("resolve pinned: %v", err)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads == 0 || stats.Builds != 0 {
		t.Fatalf("pinned chain must still load: %+v", stats)
	}
}

func TestIndexChainBounds(t *testing.T) {
	dir := t.TempDir()
	opts := chainOptions()
	opts.IndexChainMaxDeltas = 2
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	seenFull := false
	for i := 0; i < 10; i++ {
		writeChainFiles(t, s, 1, fmt.Sprintf("x%d-", i))
		kind, depth, err := s.IndexHeadChain()
		if err != nil {
			t.Fatalf("head chain: %v", err)
		}
		if depth > 2 {
			t.Fatalf("depth %d exceeded the writer bound", depth)
		}
		if kind == "full" {
			seenFull = true
		}
	}
	if !seenFull {
		t.Fatal("the bound must force a full segment")
	}

	budgetDir := t.TempDir()
	budgetOpts := chainOptions()
	one := uint64(1)
	budgetOpts.IndexBytesBudget = &one
	budget, err := store.Init(budgetDir, budgetOpts)
	if err != nil {
		t.Fatalf("init budget: %v", err)
	}
	writeChainFiles(t, budget, 3, "b")
	if kind, depth, _ := budget.IndexHeadChain(); kind != "none" || depth != 0 {
		t.Fatalf("budget must skip the write: %q %d", kind, depth)
	}
	if budget.IndexStats().WriteErrors == 0 {
		t.Fatalf("budget skip must be reported: %+v", budget.IndexStats())
	}
	if total, err := budget.IndexBytesTotal(); err != nil || total > 1 {
		t.Fatalf("index bytes %d err=%v exceed the budget", total, err)
	}
}

// countIndexSegments counts `indexes/**/*.idx` files on disk.
func countIndexSegments(t *testing.T, root string) int {
	t.Helper()
	count := 0
	entries, err := os.ReadDir(filepath.Join(root, "indexes"))
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, "indexes", entry.Name()))
		if err != nil {
			continue
		}
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".idx") {
				count++
			}
		}
	}
	return count
}

// indexChainOf follows the WFX3 chain of head on disk: kind at byte 8, base
// commit at bytes 57..89.
func indexChainOf(t *testing.T, root string, head model.Hash32) []model.Hash32 {
	t.Helper()
	var out []model.Hash32
	current := head
	for {
		data, err := os.ReadFile(store.BlobPath(root, store.BlobIndex, current))
		if err != nil {
			t.Fatalf("read segment %s: %v", current.Hex(), err)
		}
		out = append(out, current)
		if len(data) < 90 || data[8] != 1 {
			return out
		}
		var next model.Hash32
		copy(next[:], data[57:89])
		current = next
		if len(out) > int(weftindex.HardMaxChainDeltas)+2 {
			t.Fatal("chain walk did not terminate")
		}
	}
}

// seedGcFiles creates n files and returns their ids.
func seedGcFiles(t *testing.T, s *store.Store, n int) []model.Hash32 {
	t.Helper()
	ids := make([]model.Hash32, 0, n)
	for i := 0; i < n; i++ {
		attrs := map[string]wcb.Value{"team": wcb.U64Value(uint64(i % 4))}
		id, err := s.CreateFileSeeded(model.RootID, []byte(fmt.Sprintf("f%d", i)),
			[]byte(fmt.Sprintf("body-%d", i)), 0o644, 0, 0, attrs,
			[]byte(fmt.Sprintf("seed-%d", i)))
		if err != nil {
			t.Fatalf("create f%d: %v", i, err)
		}
		ids = append(ids, id)
	}
	return ids
}

// TestGcChainBoundIsPerRetainedRoot is the Go twin of the Rust court: the
// chain-depth bound applies to each retained root, never to the union. Before
// the fix, more than ~8 retaining roots refused index GC entirely.
func TestGcChainBoundIsPerRetainedRoot(t *testing.T) {
	dir := t.TempDir()
	opts := chainOptions()
	opts.CheckpointInterval = 1_000_000
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ids := seedGcFiles(t, s, 8)
	step := 0
	commitOne := func() {
		if err := s.SetXattr(ids[step%len(ids)], "rev", []byte(fmt.Sprintf("%d", step))); err != nil {
			t.Fatalf("set_xattr: %v", err)
		}
		step++
	}
	var pinned []model.Hash32
	var pinnedNames []string
	var checkpoint model.Hash32
	for i := 0; i < 10; i++ {
		guard := 0
		for {
			kind, depth, err := s.IndexHeadChain()
			if err != nil {
				t.Fatalf("head chain: %v", err)
			}
			if kind == "delta" && depth >= uint64(weftindex.DefaultMaxChainDeltas) {
				break
			}
			commitOne()
			guard++
			if guard > 64 {
				t.Fatal("the writer never reached the maximum chain depth")
			}
		}
		name := fmt.Sprintf("s%d", i)
		commit, err := s.SnapshotCreate(name)
		if err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
		pinned = append(pinned, commit)
		pinnedNames = append(pinnedNames, name)
		if i == 3 {
			checkpoint, err = s.Checkpoint()
			if err != nil {
				t.Fatalf("checkpoint: %v", err)
			}
		}
	}
	// Unretained tail commits: those segments are what GC may reclaim.
	for i := 0; i < 60; i++ {
		commitOne()
	}

	roots := append([]model.Hash32{s.Head(), checkpoint}, pinned...)
	union := map[model.Hash32]struct{}{}
	for _, root := range roots {
		walked := indexChainOf(t, dir, root)
		if len(walked) > int(weftindex.HardMaxChainDeltas)+1 {
			t.Fatalf("one root must stay inside the bound: %d segments", len(walked))
		}
		for _, segment := range walked {
			union[segment] = struct{}{}
		}
	}
	if len(union) <= int(weftindex.HardMaxChainDeltas) {
		t.Fatalf("fixture must exceed the union bound: %d segments", len(union))
	}

	before := countIndexSegments(t, dir)
	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(report.Problems) != 0 {
		t.Fatalf("GC must resolve every per-root chain: %v", report.Problems)
	}
	if report.DeletedIndexBytes == 0 {
		t.Fatal("GC must reclaim index segments it no longer needs")
	}
	after := countIndexSegments(t, dir)
	if after >= before {
		t.Fatalf("the index tree must shrink: %d -> %d", before, after)
	}
	for _, root := range roots {
		for _, segment := range indexChainOf(t, dir, root) {
			if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, segment)); err != nil {
				t.Fatalf("a retained chain lost segment %s", segment.Hex())
			}
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	query, err := selector.Parse("select attrs.team == 2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i, snapshot := range pinned {
		reader, err := store.Open(dir, store.ReadOnly)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		reader.ResetIndexStats()
		if _, err := reader.Resolve(query, &snapshot, auth.New(0, 0, nil), limits.Default()); err != nil {
			t.Fatalf("%s: resolve: %v", pinnedNames[i], err)
		}
		stats := reader.IndexStats()
		if stats.DiskLoads == 0 || stats.Builds != 0 || stats.Rejects != 0 {
			t.Fatalf("%s: the retained chain must load without rebuilding: %+v", pinnedNames[i], stats)
		}
		reader.Close()
	}
}

// TestOverLongRetainedChainStillRefusesIndexGc keeps the fail-closed path: a
// chain deeper than the hard bound refuses and deletes nothing. The shipped
// writer never exceeds 32 deltas, so the chain is forged from real bytes.
func TestOverLongRetainedChainStillRefusesIndexGc(t *testing.T) {
	srcDir := t.TempDir()
	srcOpts := chainOptions()
	srcOpts.IndexChainMaxDeltas = 1
	src, err := store.Init(srcDir, srcOpts)
	if err != nil {
		t.Fatalf("init source: %v", err)
	}
	writeChainFiles(t, src, 4, "f")
	writeChainFiles(t, src, 4, "g")
	writeChainFiles(t, src, 4, "h")
	if err := src.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}
	var deltaBytes, fullBytes []byte
	entries, _ := os.ReadDir(filepath.Join(srcDir, "indexes"))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(srcDir, "indexes", entry.Name()))
		for _, file := range files {
			data, err := os.ReadFile(filepath.Join(srcDir, "indexes", entry.Name(), file.Name()))
			if err != nil || len(data) < 90 {
				continue
			}
			switch data[8] {
			case 1:
				if deltaBytes == nil {
					deltaBytes = data
				}
			case 0:
				if fullBytes == nil {
					fullBytes = data
				}
			}
		}
	}
	if deltaBytes == nil || fullBytes == nil {
		t.Fatal("the source store must contain a delta and a full segment")
	}

	dir := t.TempDir()
	s, err := store.Init(dir, chainOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	ids := seedGcFiles(t, s, 4)
	if err := s.SetXattr(ids[0], "rev", []byte("1")); err != nil {
		t.Fatalf("set_xattr: %v", err)
	}
	head := s.Head()

	count := int(weftindex.HardMaxChainDeltas) + 44
	chain := make([]model.Hash32, 0, count)
	for i := 0; i < count; i++ {
		chain = append(chain, hash.Domain("weft/test/gc-chain", []byte(fmt.Sprintf("%d", i))))
	}
	write := func(id model.Hash32, payload []byte) {
		path := store.BlobPath(dir, store.BlobIndex, id)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			t.Fatalf("write segment: %v", err)
		}
	}
	first := []byte(nil)
	for i := 0; i < count; i++ {
		if i+1 == count {
			write(chain[i], fullBytes)
			continue
		}
		payload := append([]byte(nil), deltaBytes...)
		copy(payload[57:89], chain[i+1].Bytes())
		body := len(payload) - 32
		digest := hash.Domain("weft/index/segment/v3", payload[:body])
		copy(payload[body:], digest.Bytes())
		write(chain[i], payload)
		if i == 0 {
			first = payload
		}
	}
	write(head, first)

	before := countIndexSegments(t, dir)
	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(report.DeletedIndexes) != 0 {
		t.Fatalf("nothing may be deleted: %v", report.DeletedIndexes)
	}
	if after := countIndexSegments(t, dir); after != before {
		t.Fatalf("segment count changed: %d -> %d", before, after)
	}
	found := false
	for _, problem := range report.Problems {
		if strings.Contains(problem, "index GC skipped") &&
			strings.Contains(problem, "LimitExceeded: index segment chain exceeds the hard depth bound") {
			found = true
		}
	}
	if !found {
		t.Fatalf("GC must refuse with the typed bound: %v", report.Problems)
	}
	s.Close()
}
