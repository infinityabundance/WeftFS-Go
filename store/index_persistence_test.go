// Persisted per-commit selector-index tests (the Go counterpart of Rust's
// tests/index_persistence.rs).
//
// Every assertion is about observable behaviour: which segment a query used,
// whether the answers equal the index-free scan oracle, what happens to a
// corrupt segment, what GC removes, and that a read-only open never writes.

package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/store"
)

type indexFixture struct {
	store  *store.Store
	dir    string
	head   model.Hash32
	pinned model.Hash32
	files  []model.Hash32
}

func indexOptions(interval uint64) store.Options {
	opts := store.DefaultOptions()
	opts.ChunkSize = 1024
	opts.CheckpointInterval = interval
	opts.GCGraceSecs = 0
	// Trust/corruption tests use full segments so the forged-subset mutation and
	// header offsets are exact. Delta chains are covered by
	// `TestIncrementalIndexChainLoadsAndAnswers` and the handoff test.
	opts.NoIncrementalIndex = true
	fixed := int64(1_700_000_000_000_000_000)
	opts.FixedTimestampNS = &fixed
	return opts
}

// buildIndexFixture mirrors the Rust fixture: 18 files across three parents,
// every seventh owner-only for uid 2000, tags on even files, `links` edges on
// every third, and one readable -> hidden edge so authorization filtering still
// has to happen in the indexed path.
func buildIndexFixture(t *testing.T, dir string, interval uint64) *indexFixture {
	t.Helper()
	s, err := store.Init(dir, indexOptions(interval))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	root := model.RootID
	d0, err := s.MkdirSeeded(root, []byte("d0"), 0o755, 0, 0, []byte("index-dir-0"))
	if err != nil {
		t.Fatalf("mkdir d0: %v", err)
	}
	d1, err := s.MkdirSeeded(root, []byte("d1"), 0o755, 0, 0, []byte("index-dir-1"))
	if err != nil {
		t.Fatalf("mkdir d1: %v", err)
	}
	parents := []model.Hash32{root, d0, d1}
	teams := []string{"red", "green", "blue"}
	tags := []string{"alpha", "beta", "gamma"}
	files := make([]model.Hash32, 0, 18)
	for index := 0; index < 18; index++ {
		mode, uid, gid := uint64(0o644), uint64(1000), uint64(1000)
		if index%7 == 0 {
			mode, uid, gid = 0o600, 2000, 2000
		}
		attrs := map[string]wcb.Value{
			"team":   wcb.TextValue(teams[index%len(teams)]),
			"score":  wcb.U64Value(uint64(index % 9)),
			"signed": wcb.I64Value(int64(index % 5)),
			"nested": wcb.MapValue(map[string]wcb.Value{
				"a": wcb.U64Value(uint64(index % 7)),
			}),
		}
		id, err := s.CreateFileSeeded(parents[index%len(parents)],
			[]byte("f"+model.FormatU64(uint64(index))),
			[]byte("body-"+model.FormatU64(uint64(index))),
			mode, uid, gid, attrs, []byte("index-object-"+model.FormatU64(uint64(index))))
		if err != nil {
			t.Fatalf("create f%d: %v", index, err)
		}
		files = append(files, id)
	}
	for index, object := range files {
		if index%2 == 0 {
			if _, err := s.RelationAdd(object, "tagged_as",
				model.ValueTarget(wcb.TextValue(tags[index%len(tags)])), nil, nil); err != nil {
				t.Fatalf("tag f%d: %v", index, err)
			}
		}
		if index%3 == 0 {
			target := files[(index*7+3)%len(files)]
			if _, err := s.RelationAdd(object, "links", model.ObjectTarget(target), nil, nil); err != nil {
				t.Fatalf("link f%d: %v", index, err)
			}
		}
	}
	hidden := make([]model.Hash32, 0)
	for index, id := range files {
		if index%7 == 0 {
			hidden = append(hidden, id)
		}
	}
	if _, err := s.RelationAdd(files[1], "links", model.ObjectTarget(hidden[0]), nil, nil); err != nil {
		t.Fatalf("readable->hidden link: %v", err)
	}
	pinned, err := s.SnapshotCreate("pinned")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// Move the head past the snapshot so the two views have distinct segments.
	if _, err := s.CreateFileSeeded(root, []byte("after-snapshot"), []byte("later"),
		0o644, 1000, 1000,
		map[string]wcb.Value{"team": wcb.TextValue("red"), "score": wcb.U64Value(3)},
		[]byte("index-after-snapshot")); err != nil {
		t.Fatalf("post-snapshot create: %v", err)
	}
	head := s.Head()
	if head == pinned {
		t.Fatal("head must move past the snapshot")
	}
	return &indexFixture{store: s, dir: dir, head: head, pinned: pinned, files: files}
}

func indexSelectorTexts(files []model.Hash32, hidden []model.Hash32) []string {
	visible := files[1]
	return []string{
		"select true",
		"select kind == \"file\"",
		"select has(attrs.team)",
		"select has(attrs.missing)",
		"select not has(attrs.team)",
		"select attrs.team == \"red\"",
		"select attrs.team != \"red\"",
		"select attrs.score == 3",
		"select attrs.score > 5",
		"select attrs.signed < 2",
		"select attrs.signed == -2",
		"select tag(\"alpha\")",
		"select tag(\"beta\")",
		"select tag(\"nope\")",
		"select tag(\"alpha\") and attrs.team == \"red\"",
		"select not tag(\"alpha\")",
		"select relation(links, obj:" + visible.Hex() + ")",
		"select relation(links, obj:" + hidden[0].Hex() + ")",
		"select not relation(links, obj:" + hidden[0].Hex() + ")",
		"select object_id == \"" + files[1].Hex() + "\"",
		"select true order by size desc limit 5",
		"select kind == \"file\" order by attrs.score desc limit 6",
	}
}

func indexSelectors(t *testing.T, files, hidden []model.Hash32) []*selector.Selector {
	t.Helper()
	out := make([]*selector.Selector, 0)
	for _, text := range indexSelectorTexts(files, hidden) {
		parsed, err := selector.Parse(text)
		if err != nil {
			t.Fatalf("selector %q did not parse: %v", text, err)
		}
		out = append(out, parsed)
	}
	return out
}

func indexSegments(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	root := filepath.Join(dir, "indexes")
	shards, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out
		}
		t.Fatalf("read indexes: %v", err)
	}
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, shard.Name()))
		if err != nil {
			t.Fatalf("read shard %s: %v", shard.Name(), err)
		}
		for _, file := range files {
			path := filepath.Join(root, shard.Name(), file.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				t.Fatalf("rel %s: %v", path, err)
			}
			out[filepath.ToSlash(rel)] = data
		}
	}
	return out
}

func splitIndexBody(t *testing.T, data []byte) ([]byte, []byte) {
	t.Helper()
	if len(data) <= weftindex.DigestBytes {
		t.Fatalf("segment is too short: %d bytes", len(data))
	}
	return data[:len(data)-weftindex.DigestBytes], data[len(data)-weftindex.DigestBytes:]
}

func resealIndex(t *testing.T, body []byte) []byte {
	t.Helper()
	digest := hash.Domain(weftindex.DomainV2, body)
	out := append([]byte(nil), body...)
	return append(out, digest[:]...)
}

// compareResolution asserts full equality against the scan oracle.
func compareResolution(t *testing.T, label string, indexed, scan *resolver.Resolution) {
	t.Helper()
	if !reflect.DeepEqual(indexed, scan) {
		t.Fatalf("%s: indexed resolution differs from scan oracle\nindexed=%+v\nscan=%+v",
			label, indexed, scan)
	}
}

func countIndexMatrix(t *testing.T, s *store.Store, files, hidden []model.Hash32, view *model.Hash32, principal auth.Principal, label string) int {
	t.Helper()
	lim := limits.Default()
	snapshotID := s.Head()
	state := s.CurrentState()
	if view != nil {
		snapshotID = *view
		pinned, err := s.StateAt(*view)
		if err != nil {
			t.Fatalf("%s: state at %s: %v", label, view.Hex(), err)
		}
		state = pinned
	}
	checked := 0
	for _, sel := range indexSelectors(t, files, hidden) {
		indexed, err := s.Resolve(sel, view, principal, lim)
		if err != nil {
			t.Fatalf("%s: indexed resolve: %v", label, err)
		}
		scan, err := resolver.ResolveState(sel, snapshotID, state, principal, lim)
		if err != nil {
			t.Fatalf("%s: scan resolve: %v", label, err)
		}
		compareResolution(t, label, indexed, scan)
		checked++
	}
	return checked
}

func hiddenIDs(files []model.Hash32) []model.Hash32 {
	out := make([]model.Hash32, 0)
	for index, id := range files {
		if index%7 == 0 {
			out = append(out, id)
		}
	}
	return out
}

func TestPersistedIndexLoadsOnReopenWithoutRebuild(t *testing.T) {
	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	principal := auth.New(0, 0, nil)
	lim := limits.Default()
	segments := indexSegments(t, dir)
	headRel := "indexes/" + fixture.head.Hex()[:2] + "/" + fixture.head.Hex() + ".idx"
	if _, ok := segments[headRel]; !ok {
		t.Fatalf("a commit must write its advisory segment; have %v", sortedKeys(segments))
	}
	body, trailer := splitIndexBody(t, segments[headRel])
	if string(body[0:4]) != weftindex.MagicV3 {
		t.Fatalf("segment magic = %q", body[0:4])
	}
	if len(trailer) != weftindex.DigestBytes {
		t.Fatalf("segment trailer = %d bytes", len(trailer))
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	query, err := selector.Parse("select tag(\"alpha\")")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, mode := range []store.OpenMode{store.ReadOnly, store.ReadWrite} {
		reader, err := store.Open(dir, mode)
		if err != nil {
			t.Fatalf("reopen mode %v: %v", mode, err)
		}
		reader.ResetIndexStats()
		got, err := reader.Resolve(query, nil, principal, lim)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		scan, err := resolver.ResolveState(query, reader.Head(), reader.CurrentState(), principal, lim)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		compareResolution(t, "reopen", got, scan)
		stats := reader.IndexStats()
		if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
			t.Fatalf("mode %v: first query must load the persisted index: %+v", mode, stats)
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("close reader: %v", err)
		}
	}
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func TestPersistedIndexMatchesScanMatrixAcrossViewsAndPrincipals(t *testing.T) {
	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	hidden := hiddenIDs(fixture.files)
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	checked := 0
	for _, principal := range []auth.Principal{auth.New(0, 0, nil), auth.Root()} {
		checked += countIndexMatrix(t, reader, fixture.files, hidden, nil, principal, "head")
		checked += countIndexMatrix(t, reader, fixture.files, hidden, &fixture.pinned, principal, "pinned")
	}
	want := len(indexSelectorTexts(fixture.files, hidden)) * 4
	if checked != want {
		t.Fatalf("checked %d comparisons, want %d", checked, want)
	}
	stats := reader.IndexStats()
	if stats.Rejects != 0 || stats.DiskLoads != 2 || stats.Builds != 0 {
		t.Fatalf("both views must load their persisted index: %+v", stats)
	}
}

func TestCorruptIndexRebuildsAndAnswersStayExact(t *testing.T) {
	type corruption struct {
		name   string
		mutate func(t *testing.T, data []byte) []byte
	}
	cases := []corruption{
		{"bad magic", func(t *testing.T, data []byte) []byte {
			body, _ := splitIndexBody(t, data)
			copy(body[0:4], "BAD!")
			return resealIndex(t, body)
		}},
		{"wrong version", func(t *testing.T, data []byte) []byte {
			body, _ := splitIndexBody(t, data)
			copy(body[4:8], []byte{99, 0, 0, 0})
			return resealIndex(t, body)
		}},
		{"wrong commit", func(t *testing.T, data []byte) []byte {
			body, _ := splitIndexBody(t, data)
			for i := 8; i < 40; i++ {
				body[i] = 0xAB
			}
			return resealIndex(t, body)
		}},
		{"wrong generation", func(t *testing.T, data []byte) []byte {
			body, _ := splitIndexBody(t, data)
			for i := 40; i < 48; i++ {
				body[i] = 0
			}
			return resealIndex(t, body)
		}},
		{"wrong object count", func(t *testing.T, data []byte) []byte {
			body, _ := splitIndexBody(t, data)
			body[48]++
			return resealIndex(t, body)
		}},
		{"bad digest", func(t *testing.T, data []byte) []byte {
			out := append([]byte(nil), data...)
			out[len(out)-1] ^= 0x01
			return out
		}},
		{"truncated", func(t *testing.T, data []byte) []byte {
			return append([]byte(nil), data[:len(data)/2]...)
		}},
		{"trailing bytes", func(t *testing.T, data []byte) []byte {
			body, _ := splitIndexBody(t, data)
			withTail := append(append([]byte(nil), body...), 0)
			return resealIndex(t, withTail)
		}},
		{"superseded WFX1 magic", func(t *testing.T, data []byte) []byte {
			out := append([]byte(nil), data...)
			copy(out[0:4], "WFX1")
			return out
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			fixture := buildIndexFixture(t, dir, 256)
			if err := fixture.store.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}
			hiddenIDs := hiddenIDsFor(fixture.files)
			path := store.BlobPath(dir, store.BlobIndex, fixture.head)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read segment: %v", err)
			}
			mutated := test.mutate(t, data)
			if err := os.WriteFile(path, mutated, 0o644); err != nil {
				t.Fatalf("write mutated segment: %v", err)
			}
			reader, err := store.Open(dir, store.ReadOnly)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer reader.Close()
			reader.ResetIndexStats()
			checked := countIndexMatrix(t, reader, fixture.files, hiddenIDs, nil, auth.New(0, 0, nil), test.name)
			if checked == 0 {
				t.Fatal("no comparisons ran")
			}
			stats := reader.IndexStats()
			if stats.DiskLoads != 0 {
				t.Fatalf("%s: a corrupt segment must never be used: %+v", test.name, stats)
			}
			if stats.Builds == 0 || stats.Rejects == 0 {
				t.Fatalf("%s: a reject note and a rebuild are required: %+v", test.name, stats)
			}
			mentioned := false
			for _, note := range stats.Notes {
				if bytes.Contains([]byte(note), []byte("index")) {
					mentioned = true
				}
			}
			if !mentioned {
				t.Fatalf("%s: reject note must name the index: %+v", test.name, stats)
			}
			if report, verifyErr := reader.Verify(false); verifyErr != nil || !report.OK {
				t.Fatalf("%s: verify after rebuild: ok=%v err=%v problems=%v",
					test.name, report, verifyErr, report.Problems)
			}
		})
	}
}

func hiddenIDsFor(files []model.Hash32) []model.Hash32 { return hiddenIDs(files) }

func TestNewHeadKeysNewSegmentAndOldIsNotReused(t *testing.T) {
	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	oldHead := fixture.head
	query, err := selector.Parse("select attrs.team == \"zeta\"")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	principal := auth.New(0, 0, nil)
	lim := limits.Default()
	if got, err := fixture.store.Resolve(query, nil, principal, lim); err != nil || got.MatchedCount != 0 {
		t.Fatalf("pre-write query: %+v %v", got, err)
	}
	if _, err := fixture.store.CreateFileSeeded(model.RootID, []byte("zeta"), []byte("new-state"),
		0o644, 1000, 1000, map[string]wcb.Value{"team": wcb.TextValue("zeta")},
		[]byte("index-zeta")); err != nil {
		t.Fatalf("create zeta: %v", err)
	}
	newHead := fixture.store.Head()
	if newHead == oldHead {
		t.Fatal("head did not move")
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	for _, head := range []model.Hash32{oldHead, newHead} {
		if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, head)); err != nil {
			t.Fatalf("segment for %s: %v", head.Hex(), err)
		}
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	got, err := reader.Resolve(query, nil, principal, lim)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	scan, err := resolver.ResolveState(query, reader.Head(), reader.CurrentState(), principal, lim)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	compareResolution(t, "new head", got, scan)
	if got.MatchedCount != 1 {
		t.Fatalf("new state must be visible: %d", got.MatchedCount)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
		t.Fatalf("new head must load its own segment: %+v", stats)
	}
	// The old head's segment still exists but must not have been consulted.
	if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, oldHead)); err != nil {
		t.Fatalf("old segment must remain: %v", err)
	}
}

func TestGCKeepsHeadSnapshotAndCheckpointSegments(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, indexOptions(3))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	// The snapshot itself is one commit, so the shape is:
	// gen1 init, gen2 create, gen3 snapshot+create, gen4..7 creates, gen8 head.
	for index := 0; index < 6; index++ {
		if _, err := s.CreateFile(model.RootID, []byte("g"+model.FormatU64(uint64(index))),
			[]byte("gen body"), 0o644, 1000, 1000,
			map[string]wcb.Value{"team": wcb.TextValue("red")}); err != nil {
			t.Fatalf("create %d: %v", index, err)
		}
		if index == 0 {
			if _, err := s.SnapshotCreate("pinned"); err != nil {
				t.Fatalf("snapshot: %v", err)
			}
		}
	}
	generations := s.Generation()
	if generations < 6 {
		t.Fatalf("generation = %d, want >= 6", generations)
	}

	// Derive the retained set exactly as the collector must: head, every
	// snapshot commit, and every commit carrying a checkpoint manifest.
	commits, err := store.AllCommits(dir, ^uint64(0))
	if err != nil {
		t.Fatalf("all commits: %v", err)
	}
	retained := make(map[model.Hash32]bool)
	retained[s.Head()] = true
	for _, commit := range s.CurrentState().Snapshots {
		retained[commit] = true
	}
	for _, commit := range commits {
		if commit.Commit.Checkpoint != nil {
			retained[commit.Hash] = true
		}
	}
	if len(commits) < 6 {
		t.Fatalf("expected at least 6 commits, got %d", len(commits))
	}
	// Every commit's segment must exist before GC.
	for _, commit := range commits {
		if _, err := os.Stat(store.BlobPath(dir, store.BlobIndex, commit.Hash)); err != nil {
			t.Fatalf("pre-GC segment for generation %d: %v", commit.Generation, err)
		}
	}
	if len(retained) >= len(commits) {
		t.Fatalf("the fixture must leave at least one unreferenced segment: %d retained of %d",
			len(retained), len(commits))
	}

	report, err := s.GC(true)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if len(report.DeletedIndexes) == 0 {
		t.Fatalf("gc must report deleted index segments: %+v", report)
	}
	for _, commit := range commits {
		_, statErr := os.Stat(store.BlobPath(dir, store.BlobIndex, commit.Hash))
		exists := statErr == nil
		if retained[commit.Hash] && !exists {
			t.Fatalf("generation %d (%s) segment must be retained", commit.Generation, commit.Hash.Hex())
		}
		if !retained[commit.Hash] && exists {
			t.Fatalf("generation %d (%s) segment must be deleted", commit.Generation, commit.Hash.Hex())
		}
	}
	if q, verifyErr := s.Verify(false); verifyErr != nil || !q.OK {
		t.Fatalf("verify after index gc: ok=%v err=%v problems=%v", q, verifyErr, q.Problems)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// The matrix still answers exactly from the retained segment or a rebuild.
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	files := make([]model.Hash32, 0)
	for _, record := range reader.CurrentState().Objects {
		if record.Kind == model.KindFile {
			files = append(files, record.ID)
		}
	}
	if len(files) != 6 {
		t.Fatalf("expected 6 files, got %d", len(files))
	}
	countIndexMatrix(t, reader, files, files, nil, auth.New(0, 0, nil), "post-gc")
}

func TestReadOnlyOpenNeverWritesSegments(t *testing.T) {
	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	before := indexSegments(t, dir)
	if len(before) == 0 {
		t.Fatal("fixture commits write indexes")
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	reader.ResetIndexStats()
	countIndexMatrix(t, reader, fixture.files, hiddenIDsFor(fixture.files), nil, auth.New(0, 0, nil), "read-only")
	stats := reader.IndexStats()
	if stats.DiskLoads == 0 {
		t.Fatalf("the persisted segment should have been loaded: %+v", stats)
	}
	if stats.Writes != 0 {
		t.Fatalf("read-only open must not write: %+v", stats)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	after := indexSegments(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read-only open changed index files: before %v after %v",
			sortedKeys(before), sortedKeys(after))
	}

	// Even with no `indexes/` directory at all, a read-only open rebuilds in
	// memory and must not recreate the layout.
	if err := os.RemoveAll(filepath.Join(dir, "indexes")); err != nil {
		t.Fatalf("remove indexes: %v", err)
	}
	bare, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen without indexes: %v", err)
	}
	defer bare.Close()
	bare.ResetIndexStats()
	countIndexMatrix(t, bare, fixture.files, hiddenIDsFor(fixture.files), nil, auth.New(0, 0, nil), "no-index-dir")
	stats = bare.IndexStats()
	if stats.Builds == 0 || stats.Writes != 0 {
		t.Fatalf("a missing segment must rebuild and write nothing: %+v", stats)
	}
	if _, err := os.Stat(filepath.Join(dir, "indexes")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only open must not create the index layout: %v", err)
	}
}

// TestIndexWriteFailureNeverFailsTheCommit makes `indexes` a regular file so
// every segment write fails, then proves the commit still publishes and the
// failure is only a diagnostic note.
func TestIndexWriteFailureNeverFailsTheCommit(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, indexOptions(256))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()
	if err := os.RemoveAll(filepath.Join(dir, "indexes")); err != nil {
		t.Fatalf("remove indexes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "indexes"), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("block indexes: %v", err)
	}
	before := s.Head()
	beforeStats := s.IndexStats()
	if _, err := s.CreateFile(model.RootID, []byte("survives"), []byte("body"),
		0o644, 1000, 1000, nil); err != nil {
		t.Fatalf("create must succeed even when the index write fails: %v", err)
	}
	if s.Head() == before {
		t.Fatal("the commit did not publish")
	}
	after := s.IndexStats()
	if after.WriteErrors < beforeStats.WriteErrors+1 {
		t.Fatalf("the default write failure must be recorded: before %+v after %+v", beforeStats, after)
	}
	if len(after.Notes) == 0 {
		t.Fatal("a write failure must leave a diagnostic note")
	}
	if report, verifyErr := s.Verify(false); verifyErr != nil || !report.OK {
		t.Fatalf("verify after a failed index write: ok=%v err=%v problems=%v", report, verifyErr, report.Problems)
	}
}

// TestForgedSubsetIndexIsRejectedByCommitAttestation is the adversarial proof:
// take a valid Go-written segment, remove one candidate, re-encode it (which
// recomputes the WFX2 digest and keeps every header count unchanged), and
// require the loader to reject it and rebuild. Only the commit's
// `candidates_root` can catch this, because every self-consistency check still
// passes.
func TestForgedSubsetIndexIsRejectedByCommitAttestation(t *testing.T) {
	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	head := fixture.head
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	path := store.BlobPath(dir, store.BlobIndex, head)
	query, err := selector.Parse("select tag(\"alpha\")")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	principal := auth.New(0, 0, nil)
	lim := limits.Default()

	// The honest segment loads.
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	reader.ResetIndexStats()
	if _, err := reader.Resolve(query, nil, principal, lim); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
		t.Fatalf("the attested segment must load: %+v", stats)
	}
	reader.Close()

	// Forge: remove one id from one tag set and re-encode a valid full segment.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	segment, err := weftindex.DecodeSegment(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded, err := weftindex.ResolveSegment(data, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	forged := false
	for _, ids := range decoded.Tags {
		if len(ids) > 1 {
			var victim model.Hash32
			for id := range ids {
				victim = id
				break
			}
			delete(ids, victim)
			forged = true
			break
		}
	}
	if !forged {
		t.Fatal("fixture has no tag set with at least two members")
	}
	if segment.Header.Kind != weftindex.SegmentFull {
		t.Fatalf("forged test needs a full segment, got %s", segment.Header.Kind)
	}
	mutated, err := weftindex.EncodeFull(decoded)
	if err != nil {
		t.Fatalf("re-encode forged segment: %v", err)
	}
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatalf("write forged segment: %v", err)
	}

	reader, err = store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	reader.ResetIndexStats()
	got, err := reader.Resolve(query, nil, principal, lim)
	if err != nil {
		t.Fatalf("resolve forged: %v", err)
	}
	scan, err := resolver.ResolveState(query, reader.Head(), reader.CurrentState(), principal, lim)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	compareResolution(t, "forged subset", got, scan)
	stats = reader.IndexStats()
	if stats.DiskLoads != 0 {
		t.Fatalf("a forged subset must never load: %+v", stats)
	}
	if stats.Rejects < 1 || stats.Builds < 1 {
		t.Fatalf("the forged subset must be rejected and rebuilt: %+v", stats)
	}
	if !strings.Contains(strings.Join(stats.Notes, "\n"), "attestation") {
		t.Fatalf("the reject note must name the attestation: %+v", stats)
	}
}
