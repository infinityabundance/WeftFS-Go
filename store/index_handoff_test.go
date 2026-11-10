// Cross-language index-segment tests.
//
// Rust's WFX2 segment is internal advisory data, so the only honest question is
// whether the two implementations can consume each other's bytes. These tests
// answer it with real processes:
//
//   * Go writes the segments, Rust must load the Go bytes (its `query --json`
//     reports `index.loads>0, builds==0, rejects==0`).
//   * A **forged** segment that is self-consistent (one section emptied,
//     counts and the WFX2 digest fixed up) must be rejected: the commit's
//     attestation is the only thing that can prove completeness, so Rust and
//     Go both rebuild and still return the true answers.
//   * Rust writes the segments, Go must load them with DiskLoads=1/Builds=0
//     and reproduce the scan oracle exactly.

package store_test

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftFS-Go/auth"
	weftindex "github.com/infinityabundance/WeftFS-Go/index"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/resolver"
	"github.com/infinityabundance/WeftFS-Go/store"
)

type rustQueryResult struct {
	MatchedCount uint64 `json:"matched_count"`
	Results      []struct {
		ObjectID string `json:"object_id"`
	} `json:"results"`
	Index struct {
		Loads   uint64   `json:"loads"`
		Builds  uint64   `json:"builds"`
		Rejects uint64   `json:"rejects"`
		Notes   []string `json:"notes"`
	} `json:"index"`
}

func runRustQuery(t *testing.T, bin, dir, text string) rustQueryResult {
	t.Helper()
	output := runRust(t, bin, "--store", dir, "--json", "query", text, "--uid", "0", "--gid", "0")
	var parsed rustQueryResult
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("rust query %q output is not JSON: %v\n%s", text, err, output)
	}
	return parsed
}

func rustObjectIDs(result rustQueryResult) []string {
	out := make([]string, 0, len(result.Results))
	for _, item := range result.Results {
		out = append(out, item.ObjectID)
	}
	sort.Strings(out)
	return out
}

// TestRustLoadsGoWrittenIndexSegment proves both directions of the section
// layout: Rust answers correctly from a Go segment, and it really read it.
func TestRustLoadsGoWrittenIndexSegment(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)

	dir := t.TempDir()
	fixture := buildIndexFixture(t, dir, 256)
	if err := fixture.store.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	tagQuery := "select tag(\"alpha\")"
	attrQuery := "select attrs.team == \"red\""

	// 1. Sanity: Rust and Go agree on the same store bytes.
	rustTag := runRustQuery(t, bin, dir, tagQuery)
	if rustTag.MatchedCount == 0 {
		t.Fatal("rust found no tagged objects")
	}
	parsed, err := selector.Parse(tagQuery)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	defer reader.Close()
	goResult, err := reader.Resolve(parsed, nil, auth.New(0, 0, nil), limits.Default())
	if err != nil {
		t.Fatalf("go resolve: %v", err)
	}
	if goResult.MatchedCount != rustTag.MatchedCount {
		t.Fatalf("tag matched_count: go=%d rust=%d", goResult.MatchedCount, rustTag.MatchedCount)
	}
	goIDs := make([]string, 0, len(goResult.Results))
	for _, result := range goResult.Results {
		goIDs = append(goIDs, result.ObjectID.Hex())
	}
	sort.Strings(goIDs)
	if strings.Join(goIDs, ",") != strings.Join(rustObjectIDs(rustTag), ",") {
		t.Fatalf("tag results differ:\ngo=%v\nrust=%v", goIDs, rustObjectIDs(rustTag))
	}

	// The genuine Go segment must be *loaded*, not rebuilt: the CLI reports the
	// advisory index diagnostics, so a load is provable from outside.
	if rustTag.Index.Loads == 0 || rustTag.Index.Builds != 0 || rustTag.Index.Rejects != 0 {
		t.Fatalf("rust did not load the genuine Go segment: %+v", rustTag.Index)
	}

	// 2. Control: clear the tag section of the *Go-written head segment* and
	// recompute the WFX2 digest, so every self-consistency check still passes.
	// The commit attests the full candidate set, so Rust must reject this
	// forged subset, rebuild, and still return the true answers.
	headPath := store.BlobPath(dir, store.BlobIndex, reader.Head())
	original, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatalf("read go segment: %v", err)
	}
	decoded, err := weftindex.ResolveSegment(original, nil)
	if err != nil {
		t.Fatalf("go segment did not resolve: %v", err)
	}
	decoded.Tags = map[string]weftindex.IDSet{}
	mutated, err := weftindex.EncodeFull(decoded)
	if err != nil {
		t.Fatalf("re-encode control segment: %v", err)
	}
	if strings.HasPrefix(string(mutated), weftindex.MagicV1) {
		t.Fatal("control segment lost its magic")
	}
	if err := os.WriteFile(headPath, mutated, 0o644); err != nil {
		t.Fatalf("write control segment: %v", err)
	}
	controlTag := runRustQuery(t, bin, dir, tagQuery)
	if controlTag.Index.Loads != 0 || controlTag.Index.Rejects == 0 || controlTag.Index.Builds == 0 {
		t.Fatalf("rust trusted a forged subset (attestation not enforced): %+v", controlTag.Index)
	}
	if controlTag.MatchedCount != rustTag.MatchedCount ||
		strings.Join(rustObjectIDs(controlTag), ",") != strings.Join(rustObjectIDs(rustTag), ",") {
		t.Fatalf("forged-subset query answers changed: matched=%d", controlTag.MatchedCount)
	}

	// 3. Restore, then repeat the control for the attr_eq section.
	if err := os.WriteFile(headPath, original, 0o644); err != nil {
		t.Fatalf("restore go segment: %v", err)
	}
	beforeAttr := runRustQuery(t, bin, dir, attrQuery)
	if beforeAttr.MatchedCount == 0 || beforeAttr.Index.Loads == 0 {
		t.Fatalf("rust did not load the restored Go segment: %+v", beforeAttr.Index)
	}
	decoded, err = weftindex.ResolveSegment(original, nil)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	decoded.ObjectsByAttrEq = map[weftindex.AttrEqKey]weftindex.IDSet{}
	mutated, err = weftindex.EncodeFull(decoded)
	if err != nil {
		t.Fatalf("reenecode attr control: %v", err)
	}
	if err := os.WriteFile(headPath, mutated, 0o644); err != nil {
		t.Fatalf("write attr control: %v", err)
	}
	controlAttr := runRustQuery(t, bin, dir, attrQuery)
	if controlAttr.Index.Loads != 0 || controlAttr.Index.Rejects == 0 {
		t.Fatalf("rust trusted a forged attr_eq subset: %+v", controlAttr.Index)
	}
	if controlAttr.MatchedCount != beforeAttr.MatchedCount {
		t.Fatalf("forged attr_eq subset changed the answer: %d vs %d",
			controlAttr.MatchedCount, beforeAttr.MatchedCount)
	}
	if err := os.WriteFile(headPath, original, 0o644); err != nil {
		t.Fatalf("final restore: %v", err)
	}
	// And with the real segment restored, Rust answers again.
	if after := runRustQuery(t, bin, dir, attrQuery); after.MatchedCount == 0 {
		t.Fatal("rust did not see the restored Go segment")
	}
}

// TestGoLoadsRustWrittenIndexSegment proves Go decodes Rust's bytes: no state
// rebuild, no reject, exact answers, and a byte-level re-encode identity.
func TestGoLoadsRustWrittenIndexSegment(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)
	dir := t.TempDir()

	runRust(t, bin, "--store", dir, "init")
	runRust(t, bin, "--store", dir, "create", "/f0", "--text", "body-0",
		"--attr", "team=red", "--attr-int", "score=3")
	runRust(t, bin, "--store", dir, "create", "/f1", "--text", "body-1",
		"--attr", "team=green", "--attr-int", "score=7")
	runRust(t, bin, "--store", dir, "create", "/f2", "--text", "body-2",
		"--attr", "team=red", "--attr-int", "score=9")
	runRust(t, bin, "--store", dir, "relation", "add", "--subject", "/f0",
		"--predicate", "tagged_as", "--value", "alpha")
	runRust(t, bin, "--store", dir, "relation", "add", "--subject", "/f2",
		"--predicate", "tagged_as", "--value", "alpha")
	runRust(t, bin, "--store", dir, "relation", "add", "--subject", "/f1",
		"--predicate", "links", "--object", "/f2")
	runRust(t, bin, "--store", dir, "snapshot", "create", "pinned")

	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("go open: %v", err)
	}
	defer reader.Close()

	// The Rust writer wrote a segment for every commit, including the head.
	headPath := store.BlobPath(dir, store.BlobIndex, reader.Head())
	rustBytes, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatalf("rust-written head segment: %v", err)
	}
	if string(rustBytes[0:4]) != weftindex.MagicV3 {
		t.Fatalf("rust segment magic = %q", rustBytes[0:4])
	}
	segment, err := weftindex.DecodeSegment(rustBytes)
	if err != nil {
		t.Fatalf("Go rejected the Rust-written segment: %v", err)
	}
	if segment.Header.Generation != reader.Generation() {
		t.Fatalf("segment generation %d, head is %d",
			segment.Header.Generation, reader.Generation())
	}
	loadBase := func(baseCommit, _ model.Hash32) ([]byte, error) {
		return os.ReadFile(store.BlobPath(dir, store.BlobIndex, baseCommit))
	}
	resolved, err := weftindex.ResolveChainSegment(segment, loadBase)
	if err != nil {
		t.Fatalf("Go cannot resolve the Rust chain: %v", err)
	}
	if resolved.Index.Generation() != reader.Generation() {
		t.Fatalf("resolved generation %d, head is %d",
			resolved.Index.Generation(), reader.Generation())
	}
	// Re-encode the head segment and require byte identity. A delta needs its
	// resolved base index, which is loaded through the same chain walk.
	var reencoded []byte
	switch resolved.Chain.Kind {
	case weftindex.SegmentFull:
		reencoded, err = weftindex.EncodeFull(resolved.Index)
	case weftindex.SegmentDelta:
		baseBytes, readErr := loadBase(segment.Header.BaseCommit, segment.Header.BaseID)
		if readErr != nil {
			t.Fatalf("read base segment: %v", readErr)
		}
		base, chainErr := weftindex.ResolveChain(baseBytes, loadBase)
		if chainErr != nil {
			t.Fatalf("resolve base chain: %v", chainErr)
		}
		reencoded, err = weftindex.EncodeDelta(base.Index, resolved.Index,
			resolved.Chain.Chain[1], segment.Header.BaseCommit)
	}
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(reencoded) != string(rustBytes) {
		t.Fatalf("Go re-encode is not byte-identical to the Rust segment: go %d bytes, rust %d bytes",
			len(reencoded), len(rustBytes))
	}

	principals := []auth.Principal{auth.New(0, 0, nil), auth.Root()}
	queries := []string{
		"select tag(\"alpha\")",
		"select attrs.team == \"red\"",
		"select attrs.score == 3",
		"select attrs.score > 5",
		"select relation(links, obj:" + mustObjectID(t, reader, "/f2").Hex() + ")",
		"select true",
	}
	for position, principal := range principals {
		reader.ResetIndexStats()
		for _, text := range queries {
			parsed, err := selector.Parse(text)
			if err != nil {
				t.Fatalf("parse %q: %v", text, err)
			}
			got, err := reader.Resolve(parsed, nil, principal, limits.Default())
			if err != nil {
				t.Fatalf("go resolve %q: %v", text, err)
			}
			scan, err := resolver.ResolveState(parsed, reader.Head(), reader.CurrentState(),
				principal, limits.Default())
			if err != nil {
				t.Fatalf("scan %q: %v", text, err)
			}
			compareResolution(t, "rust segment: "+text, got, scan)
		}
		stats := reader.IndexStats()
		if position == 0 {
			if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
				t.Fatalf("Go must load the Rust segment: %+v", stats)
			}
		} else if stats.DiskLoads != 0 || stats.Builds != 0 || stats.Rejects != 0 {
			t.Fatalf("second principal must reuse the cached index: %+v", stats)
		}
	}
	// The pinned view also has its own Rust-written segment.
	pinned := reader.CurrentState().Snapshots["pinned"]
	reader.ResetIndexStats()
	query, err := selector.Parse("select tag(\"alpha\")")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := reader.Resolve(query, &pinned, auth.New(0, 0, nil), limits.Default()); err != nil {
		t.Fatalf("resolve pinned: %v", err)
	}
	stats := reader.IndexStats()
	if stats.DiskLoads != 1 || stats.Builds != 0 || stats.Rejects != 0 {
		t.Fatalf("Go must load the pinned view's Rust segment: %+v", stats)
	}
}

func TestRustLoadsGoDeltaChain(t *testing.T) {
	bin := rustBinary(t)
	rustUsable(t, bin)
	dir := t.TempDir()
	s, err := store.Init(dir, chainOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	writeChainFiles(t, s, 10, "d")
	if kind, depth, err := s.IndexHeadChain(); err != nil || kind != "delta" || depth == 0 {
		t.Fatalf("Go chain head = %q depth=%d err=%v", kind, depth, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	result := runRustQuery(t, bin, dir, "select tag(\"alpha\")")
	if result.MatchedCount == 0 {
		t.Fatal("rust found no tagged objects in the Go chain")
	}
	if result.Index.Loads == 0 || result.Index.Builds != 0 || result.Index.Rejects != 0 {
		t.Fatalf("rust did not load the genuine Go delta chain: %+v", result.Index)
	}
}

func mustObjectID(t *testing.T, s *store.Store, path string) model.Hash32 {
	t.Helper()
	id, err := s.ResolvePath(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return id
}
